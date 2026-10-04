package management

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type delayedPoolRequestBody struct {
	io.Reader
	entered, release chan struct{}
	once             sync.Once
}

func (r *delayedPoolRequestBody) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.entered); <-r.release })
	return r.Reader.Read(p)
}

func patchPoolFields(h *Handler, body io.Reader) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPatch, "/v8/management/auth-files/fields", body)
	h.PatchAuthFileFields(c)
	return rec
}

func TestPoolFieldsDelayedRouterCannotOverwriteManualChoice(t *testing.T) {
	manager, dir := newPoolTestManager(t, nil, map[string]map[string]any{"atomic.json": {"pool_mode": "auto", "pool_role": "reserve", "priority": 200}})
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: dir}, manager)
	body := &delayedPoolRequestBody{Reader: strings.NewReader(`{"name":"atomic.json","expected_pool_mode":"auto","disabled":false,"priority":200,"pool_state":"burn"}`), entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- patchPoolFields(h, body) }()
	<-body.entered
	manual := patchPoolFields(h, strings.NewReader(`{"name":"atomic.json","pool_mode":"off"}`))
	if manual.Code != http.StatusOK {
		t.Fatalf("manual=%d %s", manual.Code, manual.Body.String())
	}
	close(body.release)
	stale := <-done
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale=%d %s", stale.Code, stale.Body.String())
	}
	current, _ := manager.GetByID("atomic.json")
	if !current.Disabled || current.Metadata["pool_mode"] != "off" || current.Attributes["priority"] != "-1" {
		t.Fatalf("manual choice overwritten: %+v", current)
	}
	if _, exists := current.Metadata["pool_state"]; exists {
		t.Fatal("stale routing fields were partially applied")
	}
	if _, exists := current.Metadata["expected_pool_mode"]; exists {
		t.Fatal("compare-and-set argument persisted as metadata")
	}
}

func TestPoolManualModeAppliesStatusAndPriorityInOneWrite(t *testing.T) {
	manager, dir := newPoolTestManager(t, nil, map[string]map[string]any{
		"primary.json": {"pool_mode": "auto", "pool_role": "primary", "priority": 20},
		"reserve.json": {"pool_mode": "auto", "pool_role": "reserve", "priority": 200},
	})
	primary, _ := manager.GetByID("primary.json")
	primary.Attributes["priority"] = "20"
	if _, err := manager.Update(context.Background(), primary); err != nil {
		t.Fatal(err)
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: dir}, manager)
	for _, tc := range []struct {
		mode, priority string
		disabled       bool
	}{{"off", "-1", true}, {"on", "19", false}} {
		rec := patchPoolFields(h, strings.NewReader(`{"name":"reserve.json","pool_mode":"`+tc.mode+`","priority":200,"disabled":false}`))
		if rec.Code != http.StatusOK {
			t.Fatalf("patch=%d %s", rec.Code, rec.Body.String())
		}
		current, _ := manager.GetByID("reserve.json")
		if current.Disabled != tc.disabled || current.Attributes["priority"] != tc.priority || current.Metadata["pool_mode"] != tc.mode {
			t.Fatalf("mode=%s auth=%+v", tc.mode, current)
		}
	}
	before, _ := manager.GetByID("reserve.json")
	rec := patchPoolFields(h, strings.NewReader(`{"name":"reserve.json","pool_mode":"auto"}`))
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	after, _ := manager.GetByID("reserve.json")
	if after.Disabled != before.Disabled || after.Attributes["priority"] != before.Attributes["priority"] {
		t.Fatal("Auto changed routing before router recomputed policy")
	}
}

func TestPoolFieldsGuardUsesCurrentManagerState(t *testing.T) {
	manager, dir := newPoolTestManager(t, nil, map[string]map[string]any{"atomic.json": {"pool_mode": "auto"}})
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: dir}, manager)
	_, err := manager.UpdateManagedAuth(context.Background(), "atomic.json", func(auth *coreauth.Auth) error { auth.Metadata["pool_mode"] = "on"; return nil })
	if err != nil {
		t.Fatal(err)
	}
	rec := patchPoolFields(h, strings.NewReader(`{"name":"atomic.json","expected_pool_mode":"auto","disabled":true,"priority":-1}`))
	if rec.Code != http.StatusConflict {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	current, _ := manager.GetByID("atomic.json")
	if current.Disabled || current.Metadata["pool_mode"] != "on" {
		t.Fatal("stale router changed current mode")
	}
}

func TestPoolPrimaryOnKeepsPrimaryTier(t *testing.T) {
	manager, dir := newPoolTestManager(t, nil, map[string]map[string]any{"primary.json": {"pool_mode": "off", "pool_role": "primary", "priority": -1}})
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: dir}, manager)
	rec := patchPoolFields(h, strings.NewReader(`{"name":"primary.json","pool_mode":"on"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d %s", rec.Code, rec.Body.String())
	}
	current, _ := manager.GetByID("primary.json")
	if current.Disabled || current.Attributes["priority"] != "100" {
		t.Fatalf("On primary lost primary tier: %+v", current)
	}
}

func TestPoolManualOnIgnoresDisabledPrimaryPriority(t *testing.T) {
	manager, dir := newPoolTestManager(t, nil, map[string]map[string]any{
		"primary.json": {"pool_mode": "off", "pool_role": "primary", "priority": -1},
		"reserve.json": {"pool_mode": "auto", "pool_role": "reserve", "priority": 200},
	})
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: dir}, manager)
	rec := patchPoolFields(h, strings.NewReader(`{"name":"reserve.json","pool_mode":"on"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d %s", rec.Code, rec.Body.String())
	}
	current, _ := manager.GetByID("reserve.json")
	if current.Disabled || current.Attributes["priority"] != "50" {
		t.Fatalf("disabled primary reduced On reserve priority: %+v", current)
	}
}
