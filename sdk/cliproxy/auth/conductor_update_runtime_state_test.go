package auth

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// diskSnapshot mimics what the file watcher hands to Update after a management PATCH
// rewrites the auth file: the same credential, new metadata, and no runtime state.
func diskSnapshot(id, accessToken string, extra map[string]any) *Auth {
	metadata := map[string]any{"access_token": accessToken}
	for key, value := range extra {
		metadata[key] = value
	}
	return &Auth{ID: id, Provider: "codex", Status: StatusActive, Metadata: metadata}
}

func TestUpdateWithDiskSnapshotKeepsCooldown(t *testing.T) {
	ctx := context.Background()
	const model = "gpt-5.5"
	m := NewManager(nil, nil, nil)
	if _, errRegister := m.Register(ctx, diskSnapshot("pool-auth", "token", nil)); errRegister != nil {
		t.Fatalf("register: %v", errRegister)
	}
	m.MarkResult(ctx, Result{AuthID: "pool-auth", Provider: "codex", Model: model, Error: &Error{HTTPStatus: http.StatusTooManyRequests, Message: "rate limited"}})
	before, _ := m.GetByID("pool-auth")
	if !before.Unavailable || !before.Quota.Exceeded || before.NextRetryAfter.IsZero() {
		t.Fatalf("precondition: auth should be cooling, got unavailable=%t quota=%+v", before.Unavailable, before.Quota)
	}

	if _, errUpdate := m.Update(ctx, diskSnapshot("pool-auth", "token", map[string]any{"pool_mode": "off", "priority": 3})); errUpdate != nil {
		t.Fatalf("update: %v", errUpdate)
	}

	after, _ := m.GetByID("pool-auth")
	if after.Metadata["pool_mode"] != "off" {
		t.Fatalf("metadata not applied: %v", after.Metadata)
	}
	if after.Status != before.Status || after.Unavailable != before.Unavailable || !after.NextRetryAfter.Equal(before.NextRetryAfter) {
		t.Fatalf("auth state reset: status %s -> %s, unavailable %t -> %t, next retry %v -> %v",
			before.Status, after.Status, before.Unavailable, after.Unavailable, before.NextRetryAfter, after.NextRetryAfter)
	}
	if after.Quota.Exceeded != before.Quota.Exceeded || !after.Quota.NextRecoverAt.Equal(before.Quota.NextRecoverAt) || after.LastError == nil {
		t.Fatalf("quota or error reset: quota %+v -> %+v, last error %v", before.Quota, after.Quota, after.LastError)
	}
	if state := after.ModelStates[model]; state == nil || !state.NextRetryAfter.Equal(before.ModelStates[model].NextRetryAfter) {
		t.Fatalf("model cooldown reset: %+v", state)
	}
}

func TestUpdateWithNewCredentialsStillClearsUnauthorized(t *testing.T) {
	ctx := context.Background()
	m := NewManager(nil, nil, nil)
	unauthorized := diskSnapshot("relogin-auth", "old-token", nil)
	unauthorized.Status = StatusError
	unauthorized.Unavailable = true
	unauthorized.LastError = &Error{HTTPStatus: http.StatusUnauthorized, Message: "token revoked"}
	if _, errRegister := m.Register(ctx, unauthorized); errRegister != nil {
		t.Fatalf("register: %v", errRegister)
	}

	if _, errUpdate := m.Update(ctx, diskSnapshot("relogin-auth", "old-token", map[string]any{"pool_note": "x"})); errUpdate != nil {
		t.Fatalf("metadata update: %v", errUpdate)
	}
	if current, _ := m.GetByID("relogin-auth"); !HasUnauthorizedAuthFailure(current) {
		t.Fatal("a metadata-only update must keep the terminal unauthorized state")
	}

	if _, errUpdate := m.Update(ctx, diskSnapshot("relogin-auth", "new-token", nil)); errUpdate != nil {
		t.Fatalf("relogin update: %v", errUpdate)
	}
	current, _ := m.GetByID("relogin-auth")
	if HasUnauthorizedAuthFailure(current) || current.Unavailable || current.Status != StatusActive {
		t.Fatalf("new credentials should clear the unauthorized state, got status=%s unavailable=%t", current.Status, current.Unavailable)
	}
}

func TestReloginClearsNonQuotaFailures(t *testing.T) {
	for _, code := range []int{400, 401, 402, 403, 404} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			m := NewManager(nil, nil, nil)
			ctx := context.Background()
			old := diskSnapshot("relogin", "old", nil)
			old.Status = StatusError
			old.Unavailable = true
			old.NextRetryAfter = time.Now().Add(time.Hour)
			old.LastError = &Error{HTTPStatus: code, Message: "old credential failed"}
			old.ModelStates = map[string]*ModelState{"model": {Status: StatusError, Unavailable: true, NextRetryAfter: old.NextRetryAfter, LastError: old.LastError}}
			if _, err := m.Register(ctx, old); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Update(ctx, diskSnapshot("relogin", "new", nil)); err != nil {
				t.Fatal(err)
			}
			got, _ := m.GetByID("relogin")
			if got.Unavailable || got.LastError != nil || !got.NextRetryAfter.IsZero() || got.Status != StatusActive {
				t.Fatalf("credential retained failure: %+v", got)
			}
			state := got.ModelStates["model"]
			if state != nil && (state.Unavailable || state.LastError != nil || !state.NextRetryAfter.IsZero()) {
				t.Fatalf("model retained failure: %+v", state)
			}
		})
	}
}
