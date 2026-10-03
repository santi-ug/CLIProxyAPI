package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const poolTestModel = "gpt-5.5"

// newPoolTestManager registers file-backed codex auths that can serve poolTestModel.
func newPoolTestManager(t *testing.T, selector coreauth.Selector, metadata map[string]map[string]any) (*coreauth.Manager, string) {
	t.Helper()
	t.Setenv("MANAGEMENT_PASSWORD", "")
	authDir := t.TempDir()
	store := fileauth.NewFileTokenStore()
	store.SetBaseDir(authDir)
	manager := coreauth.NewManager(store, selector, nil)
	reg := registry.GetGlobalRegistry()
	for name, extra := range metadata {
		meta := map[string]any{"type": "codex", "access_token": name}
		for key, value := range extra {
			meta[key] = value
		}
		reg.RegisterClient(name, "codex", []*registry.ModelInfo{{ID: poolTestModel}})
		t.Cleanup(func() { reg.UnregisterClient(name) })
		record := &coreauth.Auth{
			ID:         name,
			FileName:   name,
			Provider:   "codex",
			Attributes: map[string]string{"path": filepath.Join(authDir, name)},
			Metadata:   meta,
		}
		if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
			t.Fatalf("register %s: %v", name, errRegister)
		}
	}
	return manager, authDir
}

func listAuthFileEntries(t *testing.T, h *Handler) map[string]map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files", nil)
	h.ListAuthFiles(ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d: %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Files []map[string]any `json:"files"`
	}
	if errDecode := json.Unmarshal(rec.Body.Bytes(), &payload); errDecode != nil {
		t.Fatal(errDecode)
	}
	byName := make(map[string]map[string]any, len(payload.Files))
	for _, file := range payload.Files {
		name, _ := file["name"].(string)
		byName[name] = file
	}
	return byName
}

// blockingExecutor holds every Execute call until release is closed.
type blockingExecutor struct {
	started chan struct{}
	release chan struct{}
}

func (e *blockingExecutor) Identifier() string { return "codex" }

func (e *blockingExecutor) Execute(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	close(e.started)
	<-e.release
	return cliproxyexecutor.Response{}, nil
}

func (e *blockingExecutor) ExecuteStream(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, &coreauth.Error{HTTPStatus: http.StatusNotImplemented, Message: "not implemented"}
}

func (e *blockingExecutor) Refresh(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	return auth, nil
}

func (e *blockingExecutor) CountTokens(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *blockingExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func TestListAuthFilesIncludesPoolFieldsAndActiveRequests(t *testing.T) {
	manager, authDir := newPoolTestManager(t, nil, map[string]map[string]any{
		"pool.json": {
			"pool_mode":       "auto",
			"pool_label":      "Work Max",
			"pool_updated_at": float64(1759500000),
			"pool_pinned":     true,
			"pool_limits":     map[string]any{"5h": 0.8},
			"pool_tags":       []any{"a"},
			"pool_cleared":    nil,
			"notpool_mode":    "x",
		},
	})
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	entry := listAuthFileEntries(t, h)["pool.json"]
	if entry == nil {
		t.Fatal("pool.json missing from list")
	}
	want := map[string]any{"pool_mode": "auto", "pool_label": "Work Max", "pool_updated_at": float64(1759500000), "pool_pinned": true}
	for key, value := range want {
		if entry[key] != value {
			t.Errorf("%s = %#v, want %#v", key, entry[key], value)
		}
	}
	for _, key := range []string{"pool_limits", "pool_tags", "pool_cleared", "notpool_mode"} {
		if _, ok := entry[key]; ok {
			t.Errorf("%s should not be listed", key)
		}
	}
	if entry["active_requests"] != float64(0) {
		t.Fatalf("idle active_requests = %#v, want 0", entry["active_requests"])
	}

	executor := &blockingExecutor{started: make(chan struct{}), release: make(chan struct{})}
	manager.RegisterExecutor(executor)
	done := make(chan error, 1)
	go func() {
		_, errExecute := manager.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: poolTestModel}, cliproxyexecutor.Options{})
		done <- errExecute
	}()
	<-executor.started
	if got := listAuthFileEntries(t, h)["pool.json"]["active_requests"]; got != float64(1) {
		t.Errorf("in-flight active_requests = %#v, want 1", got)
	}
	close(executor.release)
	if errExecute := <-done; errExecute != nil {
		t.Fatalf("execute: %v", errExecute)
	}
	if got := listAuthFileEntries(t, h)["pool.json"]["active_requests"]; got != float64(0) {
		t.Errorf("finished active_requests = %#v, want 0", got)
	}
}

func TestPatchAuthFileFieldsPoolAndPriorityKeepRuntimeState(t *testing.T) {
	ctx := context.Background()
	selector := coreauth.NewSessionAffinitySelector(&coreauth.RoundRobinSelector{})
	t.Cleanup(selector.Stop)
	manager, authDir := newPoolTestManager(t, selector, map[string]map[string]any{"a.json": nil, "b.json": nil})
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	pick := func(session string) string {
		t.Helper()
		opts := cliproxyexecutor.Options{Headers: http.Header{"X-Session-Id": {session}}}
		picked, errPick := selector.Pick(ctx, "codex", poolTestModel, opts, manager.List())
		if errPick != nil || picked == nil {
			t.Fatalf("pick %s: %v", session, errPick)
		}
		return picked.ID
	}
	if got := pick("bound-session"); got != "a.json" {
		t.Fatalf("initial binding = %s, want a.json", got)
	}
	// Cool a different model so a.json stays usable for the bound session.
	manager.MarkResult(ctx, coreauth.Result{AuthID: "a.json", Provider: "codex", Model: "gpt-5.4", Error: &coreauth.Error{HTTPStatus: http.StatusTooManyRequests, Message: "rate limited"}})
	before, _ := manager.GetByID("a.json")

	// priority -1 drops a.json below b.json, so only the binding can keep the session on it.
	body := `{"name":"a.json","pool_mode":"auto","pool_label":"Work","pool_updated_at":1759500000,"priority":-1}`
	rec := httptest.NewRecorder()
	patchCtx, _ := gin.CreateTestContext(rec)
	patchCtx.Request = httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/fields", strings.NewReader(body))
	h.PatchAuthFileFields(patchCtx)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch status = %d: %s", rec.Code, rec.Body.String())
	}

	raw, errRead := os.ReadFile(filepath.Join(authDir, "a.json"))
	if errRead != nil {
		t.Fatal(errRead)
	}
	var onDisk map[string]any
	if errUnmarshal := json.Unmarshal(raw, &onDisk); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	if onDisk["pool_mode"] != "auto" || onDisk["priority"] != float64(-1) {
		t.Fatalf("file not updated: pool_mode=%#v priority=%#v", onDisk["pool_mode"], onDisk["priority"])
	}
	entry := listAuthFileEntries(t, h)["a.json"]
	if entry["pool_mode"] != "auto" || entry["pool_label"] != "Work" || entry["pool_updated_at"] != float64(1759500000) || entry["priority"] != float64(-1) {
		t.Fatalf("list after patch: %v", entry)
	}

	after, _ := manager.GetByID("a.json")
	if after.Unavailable != before.Unavailable || after.Status != before.Status || !after.NextRetryAfter.Equal(before.NextRetryAfter) || after.Quota.Exceeded != before.Quota.Exceeded {
		t.Fatalf("patch reset auth state: unavailable %t -> %t, status %s -> %s", before.Unavailable, after.Unavailable, before.Status, after.Status)
	}
	if state := after.ModelStates["gpt-5.4"]; state == nil || !state.NextRetryAfter.Equal(before.ModelStates["gpt-5.4"].NextRetryAfter) {
		t.Fatalf("patch reset model cooldown: %+v", state)
	}

	if got := pick("new-session"); got != "b.json" {
		t.Fatalf("new session = %s, want b.json (higher priority)", got)
	}
	if got := pick("bound-session"); got != "a.json" {
		t.Fatalf("bound session moved to %s after patch, want a.json", got)
	}
}

func TestPoolStatusRejectsStaleRouterAndKeepsCooldown(t *testing.T) {
	manager, dir := newPoolTestManager(t, nil, map[string]map[string]any{"guard.json": {"pool_mode": "auto"}})
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: dir}, manager)
	patch := func(body string, fields bool) int {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest("PATCH", "/v8/management/auth-files/status", strings.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		if fields {
			h.PatchAuthFileFields(c)
		} else {
			h.PatchAuthFileStatus(c)
		}
		return rec.Code
	}
	manager.MarkResult(context.Background(), coreauth.Result{AuthID: "guard.json", Provider: "codex", Model: poolTestModel, Error: &coreauth.Error{HTTPStatus: 429, Message: "quota"}})
	before, _ := manager.GetByID("guard.json")
	if got := patch(`{"name":"guard.json","pool_mode":"off"}`, true); got != 200 {
		t.Fatalf("off metadata=%d", got)
	}
	if got := patch(`{"name":"guard.json","disabled":true,"expected_pool_mode":"off"}`, false); got != 200 {
		t.Fatalf("disable=%d", got)
	}
	if got := patch(`{"name":"guard.json","disabled":false,"expected_pool_mode":"auto"}`, false); got != 409 {
		t.Fatalf("stale router=%d", got)
	}
	after, _ := manager.GetByID("guard.json")
	if !after.Disabled || after.Metadata["pool_mode"] != "off" {
		t.Fatal("stale router overrode user Off")
	}
	if !after.Quota.Exceeded || !after.NextRetryAfter.Equal(before.NextRetryAfter) {
		t.Fatal("pause erased quota cooldown")
	}
	if got := patch(`{"name":"guard.json","disabled":false,"expected_pool_mode":"off"}`, false); got != 200 {
		t.Fatalf("enable=%d", got)
	}
	after, _ = manager.GetByID("guard.json")
	if !after.Quota.Exceeded || !after.NextRetryAfter.Equal(before.NextRetryAfter) {
		t.Fatal("resume erased quota cooldown")
	}
}

func TestNewPoolAccountDefaultAutoKeepsCooldown(t *testing.T) {
	manager, dir := newPoolTestManager(t, nil, map[string]map[string]any{"new-pool.json": {"pool_label": "new-account"}})
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: dir}, manager)
	manager.MarkResult(context.Background(), coreauth.Result{AuthID: "new-pool.json", Provider: "codex", Model: poolTestModel, Error: &coreauth.Error{HTTPStatus: 429, Message: "quota"}})
	before, _ := manager.GetByID("new-pool.json")
	for _, disabled := range []bool{true, false} {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		payload, _ := json.Marshal(map[string]any{"name": "new-pool.json", "disabled": disabled, "expected_pool_mode": "auto"})
		c.Request = httptest.NewRequest("PATCH", "/v8/management/auth-files/status", strings.NewReader(string(payload)))
		c.Request.Header.Set("Content-Type", "application/json")
		h.PatchAuthFileStatus(c)
		if rec.Code != 200 {
			t.Fatalf("status=%d %s", rec.Code, rec.Body.String())
		}
		current, _ := manager.GetByID("new-pool.json")
		if !current.Quota.Exceeded || !current.NextRetryAfter.Equal(before.NextRetryAfter) {
			t.Fatal("default Auto pause erased quota")
		}
		if _, exists := current.Metadata["pool_mode"]; exists {
			t.Fatal("status PATCH rewrote user mode")
		}
	}
}
