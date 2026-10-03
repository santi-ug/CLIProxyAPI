package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestManagedUpdateSerializesPoolModeCheckWithMutation(t *testing.T) {
	m := NewManager(nil, nil, nil)
	if _, err := m.Register(context.Background(), &Auth{ID: "managed", Provider: "codex", Metadata: map[string]any{"pool_mode": "auto"}}); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	first := make(chan error, 1)
	go func() {
		_, err := m.UpdateManagedAuth(context.Background(), "managed", func(auth *Auth) error {
			close(entered)
			<-release
			auth.Metadata["pool_mode"] = "off"
			auth.Disabled = true
			return nil
		})
		first <- err
	}()
	<-entered
	started := make(chan struct{})
	second := make(chan error, 1)
	stale := errors.New("pool mode changed")
	go func() {
		close(started)
		_, err := m.UpdateManagedAuth(context.Background(), "managed", func(auth *Auth) error {
			if auth.Metadata["pool_mode"] != "auto" {
				return stale
			}
			auth.Disabled = false
			return nil
		})
		second <- err
	}()
	<-started
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; !errors.Is(err, stale) {
		t.Fatalf("guard=%v", err)
	}
	current, _ := m.GetByID("managed")
	if !current.Disabled || current.Metadata["pool_mode"] != "off" {
		t.Fatal("stale router overrode mode")
	}
}

func TestRejectedManagedNestedPatchDoesNotChangePublishedAuth(t *testing.T) {
	m := NewManager(nil, nil, nil)
	if _, err := m.Register(context.Background(), &Auth{ID: "managed", Provider: "codex", Metadata: map[string]any{"nested": map[string]any{"value": "before"}}}); err != nil {
		t.Fatal(err)
	}
	_, err := m.UpdateManagedAuth(context.Background(), "managed", func(auth *Auth) error {
		auth.Metadata["nested"].(map[string]any)["value"] = "after"
		return errors.New("invalid patch")
	})
	if err == nil {
		t.Fatal("expected rejected patch")
	}
	current, _ := m.GetByID("managed")
	if current.Metadata["nested"].(map[string]any)["value"] != "before" {
		t.Fatal("rejected patch leaked to runtime")
	}
}

func TestManagedUpdateConcurrentWithRefreshAndResults(t *testing.T) {
	m := NewManager(nil, nil, nil)
	ctx := WithSkipPersist(context.Background())
	if _, err := m.Register(ctx, &Auth{ID: "managed-race", Provider: "codex", Metadata: map[string]any{"access_token": "fixture", "pool_mode": "auto"}}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 3; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				switch worker {
				case 0:
					_, err := m.UpdateManagedAuth(ctx, "managed-race", func(auth *Auth) error { auth.Metadata["pool_mode"] = "off"; auth.Disabled = true; return nil })
					if err != nil {
						t.Error(err)
						return
					}
				case 1:
					base, _ := m.GetByID("managed-race")
					if _, err := m.UpdateRefreshedAuth(ctx, base, base.Clone()); err != nil {
						t.Error(err)
						return
					}
				case 2:
					m.MarkResult(ctx, Result{AuthID: "managed-race", Provider: "codex", Model: "fixture", Success: true})
				}
			}
		}(worker)
	}
	wg.Wait()
	current, _ := m.GetByID("managed-race")
	if !current.Disabled || current.Metadata["pool_mode"] != "off" {
		t.Fatal("refresh erased current manual mode")
	}
}
