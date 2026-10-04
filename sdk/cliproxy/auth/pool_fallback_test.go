package auth

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type poolFallbackExecutor struct {
	failures map[string]error
	prepare  bool
	calls    []string
}

func (*poolFallbackExecutor) Identifier() string { return "claude" }
func (e *poolFallbackExecutor) call(auth *Auth) error {
	e.calls = append(e.calls, auth.ID)
	return e.failures[auth.ID]
}
func (e *poolFallbackExecutor) Execute(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{Payload: []byte("ok")}, e.call(auth)
}
func (e *poolFallbackExecutor) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return e.Execute(ctx, auth, req, opts)
}
func (e *poolFallbackExecutor) ExecuteStream(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if err := e.call(auth); err != nil {
		return nil, err
	}
	chunks := make(chan cliproxyexecutor.StreamChunk, 1)
	chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("ok")}
	close(chunks)
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}
func (*poolFallbackExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) { return auth, nil }
func (*poolFallbackExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}
func (e *poolFallbackExecutor) ShouldPrepareRequestAuth(auth *Auth) bool {
	return e.prepare && auth.ID == "pool-primary"
}
func (e *poolFallbackExecutor) PrepareRequestAuth(_ context.Context, auth *Auth) (*Auth, error) {
	e.calls = append(e.calls, auth.ID+":prepare")
	return auth, e.failures[auth.ID]
}

func newPoolFallbackFixture(t *testing.T, mode string, priority int, primary bool) (*Manager, *poolFallbackExecutor, context.Context, string) {
	t.Helper()
	m := NewManager(nil, nil, nil)
	exec := &poolFallbackExecutor{failures: make(map[string]error)}
	m.RegisterExecutor(exec)
	model := "claude-pool-fallback-test"
	ids := []string{"pool-reserve"}
	if primary {
		ids = append(ids, "pool-primary")
	}
	for _, id := range ids {
		role, p, accountMode := "reserve", priority, mode
		if id == "pool-primary" {
			role, p, accountMode = "primary", 100, "auto"
		}
		auth := &Auth{ID: id, Provider: "claude", Attributes: map[string]string{"priority": strconv.Itoa(p)}, Metadata: map[string]any{"access_token": "fixture", "pool_role": role, "pool_mode": accountMode}}
		registry.GetGlobalRegistry().RegisterClient(id, "claude", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
		if _, err := m.Register(context.Background(), auth); err != nil {
			t.Fatal(err)
		}
	}
	return m, exec, context.Background(), model
}

func runPoolRequest(ctx context.Context, m *Manager, model, path string) error {
	req, opts := cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{}
	switch path {
	case "execute":
		_, err := m.Execute(ctx, []string{"claude"}, req, opts)
		return err
	case "count":
		_, err := m.ExecuteCount(ctx, []string{"claude"}, req, opts)
		return err
	case "stream":
		stream, err := m.ExecuteStream(ctx, []string{"claude"}, req, opts)
		if err != nil {
			return err
		}
		for chunk := range stream.Chunks {
			if chunk.Err != nil {
				return chunk.Err
			}
		}
		return nil
	default:
		panic("unknown test path")
	}
}

func TestPoolReserveRequiresQuotaAcrossExecutionPaths(t *testing.T) {
	for _, path := range []string{"execute", "count", "stream"} {
		for _, status := range []int{401, 403, 500, 429} {
			t.Run(path+"/"+strconv.Itoa(status), func(t *testing.T) {
				m, exec, ctx, model := newPoolFallbackFixture(t, "auto", 10, true)
				exec.failures["pool-primary"] = &Error{HTTPStatus: status, Message: "upstream failure"}
				err := runPoolRequest(ctx, m, model, path)
				want := []string{"pool-primary"}
				if status == 429 {
					want = append(want, "pool-reserve")
				}
				if (err == nil) != (status == 429) {
					t.Fatalf("error=%v status=%d", err, status)
				}
				if !reflect.DeepEqual(exec.calls, want) {
					t.Fatalf("calls=%v want=%v", exec.calls, want)
				}
			})
		}
		t.Run(path+"/invalid-grant-prepare", func(t *testing.T) {
			m, exec, ctx, model := newPoolFallbackFixture(t, "auto", 50, true)
			exec.prepare = true
			exec.failures["pool-primary"] = errors.New("token refresh failed: invalid_grant")
			if err := runPoolRequest(ctx, m, model, path); err == nil {
				t.Fatal("expected login failure")
			}
			if !reflect.DeepEqual(exec.calls, []string{"pool-primary:prepare"}) {
				t.Fatalf("calls=%v", exec.calls)
			}
		})
	}
}

func TestPoolReservePersistedQuotaAndManualModes(t *testing.T) {
	for _, tc := range []struct {
		name, mode             string
		priority               int
		primary, quota, paused bool
		want                   string
	}{
		{"persisted quota", "auto", 10, true, true, false, "pool-reserve"},
		{"router paused depleted primary", "auto", 10, true, true, true, "pool-reserve"},
		{"missing primary", "auto", 10, false, false, false, ""},
		{"explicit on", "on", 50, true, false, false, "pool-primary"},
		{"auto burn", "auto", 200, true, false, false, "pool-reserve"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _, ctx, model := newPoolFallbackFixture(t, tc.mode, tc.priority, tc.primary)
			if tc.quota {
				retry := time.Hour
				m.MarkResult(context.Background(), Result{AuthID: "pool-primary", Provider: "claude", Model: model, Error: &Error{HTTPStatus: 429, Message: "quota"}, CredentialScope: true, RetryAfter: &retry})
				if tc.paused {
					_, err := m.UpdateManagedAuth(context.Background(), "pool-primary", func(auth *Auth) error { auth.Disabled = true; auth.Status = StatusDisabled; return nil })
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			picked, err := m.SelectAuth(ctx, "claude", model, cliproxyexecutor.Options{})
			if tc.want == "" {
				if err == nil {
					t.Fatalf("unexpected selected auth: %v", picked)
				}
				return
			}
			if err != nil || picked.ID != tc.want {
				t.Fatalf("picked=%v err=%v want=%s", picked, err, tc.want)
			}
		})
	}
}

func TestPoolReserveRejectsBrokenPrimaryWithStaleQuota(t *testing.T) {
	for _, status := range []int{401, 403, 500, 400} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			m, _, ctx, model := newPoolFallbackFixture(t, "auto", 10, true)
			_, err := m.UpdateManagedAuth(context.Background(), "pool-primary", func(auth *Auth) error {
				auth.Quota = QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: time.Now().Add(time.Hour)}
				auth.Unavailable = true
				auth.LastError = &Error{HTTPStatus: status, Message: "invalid_grant or non-quota failure"}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.SelectAuth(ctx, "claude", model, cliproxyexecutor.Options{}); err == nil {
				t.Fatal("stale quota allowed broken primary reserve fallback")
			}
		})
	}
}

func TestPoolReserveRequiresEveryPrimaryToBeQuotaExhausted(t *testing.T) {
	for _, secondStatus := range []int{500, 429} {
		t.Run(strconv.Itoa(secondStatus), func(t *testing.T) {
			m, exec, ctx, model := newPoolFallbackFixture(t, "auto", 10, true)
			const id = "pool-primary-two"
			registry.GetGlobalRegistry().RegisterClient(id, "claude", []*registry.ModelInfo{{ID: model}})
			t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
			_, err := m.Register(context.Background(), &Auth{ID: id, Provider: "claude", Attributes: map[string]string{"priority": "100"}, Metadata: map[string]any{"access_token": "fixture", "pool_role": "primary", "pool_mode": "auto"}})
			if err != nil {
				t.Fatal(err)
			}
			exec.failures["pool-primary"] = &Error{HTTPStatus: 429, Message: "quota"}
			exec.failures[id] = &Error{HTTPStatus: secondStatus, Message: "failure"}
			err = runPoolRequest(ctx, m, model, "execute")
			if (err == nil) != (secondStatus == 429) {
				t.Fatalf("error=%v", err)
			}
			for _, called := range exec.calls {
				if called == "pool-reserve" && secondStatus != 429 {
					t.Fatal("reserve served after other primary failed for non-quota reason")
				}
			}
		})
	}
}

func TestPoolReserveRejectsLatestRoutedModelFailureWithSiblingQuota(t *testing.T) {
	for _, path := range []string{"execute", "count", "stream"} {
		for _, route := range []string{"plain", "thinking", "alias", "alias-thinking", "prefix-alias-thinking"} {
			t.Run(path+"/"+route, func(t *testing.T) {
				m, exec, ctx, modelA := newPoolFallbackFixture(t, "auto", 10, true)
				const modelB, alias = "claude-pool-model-b", "claude-pool-route-a"
				m.SetOAuthModelAlias(map[string][]internalconfig.OAuthModelAlias{"claude": {{Name: modelA, Alias: alias, Fork: true}}})
				routeModel := modelA
				switch route {
				case "thinking":
					routeModel += "(1024)"
				case "alias":
					routeModel = alias
				case "alias-thinking":
					routeModel = alias + "(1024)"
				case "prefix-alias-thinking":
					routeModel = "work/" + alias + "(1024)"
				}
				for _, id := range []string{"pool-primary", "pool-reserve"} {
					registry.GetGlobalRegistry().RegisterClient(id, "claude", []*registry.ModelInfo{{ID: modelA}, {ID: modelB}, {ID: alias}, {ID: "work/" + alias}})
					if route == "prefix-alias-thinking" {
						if _, err := m.UpdateManagedAuth(context.Background(), id, func(auth *Auth) error { auth.Prefix = "work"; return nil }); err != nil {
							t.Fatal(err)
						}
					}
				}
				mark := func(model string, status int) {
					retry := time.Hour
					m.MarkResult(context.Background(), Result{AuthID: "pool-primary", Provider: "claude", Model: model, Error: &Error{HTTPStatus: status, Message: "fixture failure"}, RetryAfter: &retry})
				}
				mark(modelA, 429)
				mark(modelA, 500)
				mark(modelB, 429)
				primary, _ := m.GetByID("pool-primary")
				if key := m.selectionModelKeyForAuth(primary, routeModel); key != modelA {
					t.Fatalf("route resolved to %q, want %q", key, modelA)
				}
				state := existingModelState(primary, modelA)
				if primary.LastError == nil || primary.LastError.HTTPStatus != 429 || state == nil || !state.Quota.Exceeded || state.LastError == nil || state.LastError.HTTPStatus != 500 {
					t.Fatalf("missing stale-quota precondition: primary=%+v state=%+v", primary.LastError, state)
				}
				if err := runPoolRequest(ctx, m, routeModel, path); err == nil {
					t.Fatal("sibling quota hid the routed model's newer non-quota failure")
				}
				if len(exec.calls) != 0 {
					t.Fatalf("blocked routed model consumed reserve: %v", exec.calls)
				}
				// A real newer 429 for this exact routed model restores quota fallback.
				mark(modelA, 429)
				if err := runPoolRequest(ctx, m, routeModel, path); err != nil {
					t.Fatalf("actual routed model quota failed to allow reserve: %v", err)
				}
				if !reflect.DeepEqual(exec.calls, []string{"pool-reserve"}) {
					t.Fatalf("quota calls=%v", exec.calls)
				}
			})
		}
	}
}
