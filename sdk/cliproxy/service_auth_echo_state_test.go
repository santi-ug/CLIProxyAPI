package cliproxy

import (
	"context"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

// After a management PATCH writes pool_* metadata, the file watcher hands the re-read file
// back through applyCoreAuthAddOrUpdate. That echo must not make a cooling credential look healthy.
func TestServiceAuthFileEchoKeepsCooldown(t *testing.T) {
	ctx := context.Background()
	service := &Service{cfg: &config.Config{}, coreManager: coreauth.NewManager(nil, nil, nil)}
	const authID = "echo-state-auth"
	t.Cleanup(func() { GlobalModelRegistry().UnregisterClient(authID) })
	fromDisk := func(extra map[string]any) *coreauth.Auth {
		metadata := map[string]any{"type": "claude", "email": "pool@example.com"}
		for key, value := range extra {
			metadata[key] = value
		}
		return &coreauth.Auth{ID: authID, Provider: "claude", Status: coreauth.StatusActive, Attributes: map[string]string{"path": "/tmp/" + authID + ".json"}, Metadata: metadata}
	}

	service.applyCoreAuthAddOrUpdate(ctx, fromDisk(nil))
	models := registry.GetGlobalRegistry().GetModelsForClient(authID)
	if len(models) < 2 {
		t.Fatalf("registered models = %d, want at least 2", len(models))
	}
	for _, model := range models[:2] {
		service.coreManager.MarkResult(ctx, coreauth.Result{AuthID: authID, Provider: "claude", Model: model.ID, Error: &coreauth.Error{HTTPStatus: http.StatusTooManyRequests, Message: "rate limited"}})
	}
	before, _ := service.coreManager.GetByID(authID)
	if !before.Unavailable {
		t.Fatal("precondition: credential should be unavailable with every tracked model cooling")
	}

	service.applyCoreAuthAddOrUpdate(ctx, fromDisk(map[string]any{"pool_mode": "off"}))

	after, _ := service.coreManager.GetByID(authID)
	if after.Metadata["pool_mode"] != "off" {
		t.Fatalf("metadata not applied: %v", after.Metadata)
	}
	if after.Status != before.Status || after.Unavailable != before.Unavailable || !after.NextRetryAfter.Equal(before.NextRetryAfter) || after.Quota.Exceeded != before.Quota.Exceeded {
		t.Fatalf("echo reset state: status %s -> %s, unavailable %t -> %t, next retry %v -> %v, quota %t -> %t",
			before.Status, after.Status, before.Unavailable, after.Unavailable, before.NextRetryAfter, after.NextRetryAfter, before.Quota.Exceeded, after.Quota.Exceeded)
	}
	if len(after.ModelStates) != len(before.ModelStates) {
		t.Fatalf("model states = %d, want %d", len(after.ModelStates), len(before.ModelStates))
	}
}
