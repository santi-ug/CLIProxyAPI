package auth

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestActiveRequestCounterReleaseIsIdempotent(t *testing.T) {
	var counter activeRequestCounter
	first := counter.begin("a")
	second := counter.begin("a")

	first()
	first()
	if got := counter.get("a"); got != 1 {
		t.Fatalf("after double release of one request: count = %d, want 1", got)
	}
	second()
	if got := counter.get("a"); got != 0 {
		t.Fatalf("after releasing both: count = %d, want 0", got)
	}
	if _, ok := counter.counts["a"]; ok {
		t.Fatal("idle credentials must not keep a map entry")
	}
}

func TestActiveRequestCounterConcurrentUse(t *testing.T) {
	var counter activeRequestCounter
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				release := counter.begin("a")
				_ = counter.get("a")
				release()
				release()
			}
		}()
	}
	wg.Wait()
	if got := counter.get("a"); got != 0 {
		t.Fatalf("count = %d, want 0", got)
	}
}

// activeRequestExecutor fails for IDs in fail and otherwise blocks until release is closed.
// onCall observes the active counts while a request is executing.
type activeRequestExecutor struct {
	fail    map[string]bool
	release chan struct{}
	onCall  func(authID string)
	stream  chan cliproxyexecutor.StreamChunk
}

func (e *activeRequestExecutor) Identifier() string { return "codex" }

func (e *activeRequestExecutor) Execute(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.onCall(auth.ID)
	if e.fail[auth.ID] {
		return cliproxyexecutor.Response{}, &Error{HTTPStatus: http.StatusInternalServerError, Message: "upstream failed"}
	}
	<-e.release
	return cliproxyexecutor.Response{Payload: []byte("ok")}, nil
}

func (e *activeRequestExecutor) ExecuteStream(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.onCall(auth.ID)
	if e.fail[auth.ID] {
		return nil, &Error{HTTPStatus: http.StatusInternalServerError, Message: "upstream failed"}
	}
	return &cliproxyexecutor.StreamResult{Chunks: e.stream}, nil
}

func (e *activeRequestExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	return auth, nil
}

func (e *activeRequestExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *activeRequestExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

// newActiveRequestFixture registers a failing primary and a working backup on the same model.
func newActiveRequestFixture(t *testing.T) (*Manager, *activeRequestExecutor, string) {
	t.Helper()
	const model = "gpt-5.5"
	executor := &activeRequestExecutor{
		fail:    map[string]bool{"aa-primary": true},
		release: make(chan struct{}),
		stream:  make(chan cliproxyexecutor.StreamChunk),
	}
	m := NewManager(nil, nil, nil)
	m.RegisterExecutor(executor)
	reg := registry.GetGlobalRegistry()
	for _, id := range []string{"aa-primary", "bb-backup"} {
		reg.RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { reg.UnregisterClient(id) })
		if _, errRegister := m.Register(context.Background(), &Auth{ID: id, Provider: "codex", Metadata: map[string]any{"access_token": id}}); errRegister != nil {
			t.Fatalf("register %s: %v", id, errRegister)
		}
	}
	return m, executor, model
}

func TestManagerCountsActiveUnaryRequestsAcrossFailover(t *testing.T) {
	m, executor, model := newActiveRequestFixture(t)
	// Each call reports [primary backup] active counts as seen from inside the upstream call.
	seen := make(chan [2]int, 2)
	executor.onCall = func(string) {
		seen <- [2]int{m.ActiveRequests("aa-primary"), m.ActiveRequests("bb-backup")}
	}

	done := make(chan error, 1)
	go func() {
		_, errExecute := m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
		done <- errExecute
	}()

	if got := <-seen; got != [2]int{1, 0} {
		t.Fatalf("while primary runs: [primary backup] = %v, want [1 0]", got)
	}
	if got := <-seen; got != [2]int{0, 1} {
		t.Fatalf("after failover, while backup runs: [primary backup] = %v, want [0 1]", got)
	}
	close(executor.release)
	if errExecute := <-done; errExecute != nil {
		t.Fatalf("Execute: %v", errExecute)
	}
	for _, id := range []string{"aa-primary", "bb-backup"} {
		if got := m.ActiveRequests(id); got != 0 {
			t.Fatalf("after Execute: %s = %d, want 0", id, got)
		}
	}
}

func TestManagerCountsActiveStreamUntilItEnds(t *testing.T) {
	m, executor, model := newActiveRequestFixture(t)
	var calls []string
	executor.onCall = func(authID string) { calls = append(calls, authID) }

	go func() { executor.stream <- cliproxyexecutor.StreamChunk{Payload: []byte("first")} }()
	result, errStream := m.ExecuteStream(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
	if errStream != nil {
		t.Fatalf("ExecuteStream: %v", errStream)
	}
	if len(calls) != 2 || calls[0] != "aa-primary" {
		t.Fatalf("stream calls = %v, want the failing primary first", calls)
	}
	if got := m.ActiveRequests("aa-primary"); got != 0 {
		t.Fatalf("failed primary stream attempt: count = %d, want 0", got)
	}
	if chunk := <-result.Chunks; string(chunk.Payload) != "first" {
		t.Fatalf("first chunk = %q", chunk.Payload)
	}
	if got := m.ActiveRequests("bb-backup"); got != 1 {
		t.Fatalf("open stream: count = %d, want 1", got)
	}

	close(executor.stream)
	for range result.Chunks {
	}
	if got := m.ActiveRequests("bb-backup"); got != 0 {
		t.Fatalf("finished stream: count = %d, want 0", got)
	}
}

type activeHTTPExecutor struct{ activeRequestExecutor }

func (e *activeHTTPExecutor) HttpRequest(_ context.Context, auth *Auth, _ *http.Request) (*http.Response, error) {
	e.onCall(auth.ID)
	return &http.Response{Body: io.NopCloser(strings.NewReader("response"))}, nil
}
func TestActiveHttpRequestBodyLifetime(t *testing.T) {
	m := NewManager(nil, nil, nil)
	e := &activeHTTPExecutor{}
	e.onCall = func(id string) {
		if m.ActiveRequests(id) != 1 {
			t.Fatal("HTTP call not counted")
		}
	}
	m.RegisterExecutor(e)
	req, _ := http.NewRequest("GET", "http://localhost", nil)
	response, err := m.HttpRequest(context.Background(), &Auth{ID: "raw", Provider: "codex"}, req)
	if err != nil {
		t.Fatal(err)
	}
	if m.ActiveRequests("raw") != 1 {
		t.Fatal("released before body finished")
	}
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	if m.ActiveRequests("raw") != 0 {
		t.Fatal("not released at EOF")
	}
	_ = response.Body.Close()
	if m.ActiveRequests("raw") != 0 {
		t.Fatal("double release")
	}
}
