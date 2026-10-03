package auth

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"net/http"
	"testing"
)

func TestClaudeCodeOnlySelectionAndRefusal(t *testing.T) {
	SetClaudeCodeOnly(true)
	t.Cleanup(func() { SetClaudeCodeOnly(false) })
	login := &Auth{ID: "claude-only-login", Provider: "claude", Metadata: map[string]any{"access_token": "test-token"}}
	apiKey := &Auth{ID: "claude-only-key", Provider: "claude", Attributes: map[string]string{AttributeAPIKey: "test-key"}}
	m := NewManager(nil, nil, nil)
	if _, err := m.Register(context.Background(), login); err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(login.ID, "claude", []*registry.ModelInfo{{ID: "claude-only-model"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(login.ID) })
	for _, ctx := range []context.Context{nil, context.Background(), context.WithValue(context.Background(), "gin", &gin.Context{})} {
		eligibility := authSelectionEligibilityForRequest(ctx, coreexecutor.Options{})
		if eligibility.allows(login) || !eligibility.allows(apiKey) {
			t.Fatal("non-native request may use subscription or API key was blocked")
		}
		if err := m.claudeCodeOnlyRefusal(ctx, []string{"claude"}, coreexecutor.Options{}, "claude-only-model"); err != ErrClaudeCodeOnly {
			t.Fatalf("refusal=%v", err)
		}
	}
	c := &gin.Context{}
	MarkNativeClaudeCode(c)
	ctx := context.WithValue(context.Background(), "gin", c)
	if !authSelectionEligibilityForRequest(ctx, coreexecutor.Options{}).allows(login) {
		t.Fatal("native messages blocked")
	}
	if err := m.claudeCodeOnlyRefusal(ctx, []string{"claude"}, coreexecutor.Options{}, "claude-only-model"); err != nil {
		t.Fatal(err)
	}
	if err := RefuseUnverifiedClaudeSubscription(login, false); err == nil {
		t.Fatal("executor bypass")
	}
	if err := RefuseUnverifiedClaudeSubscription(login, true); err != nil {
		t.Fatal(err)
	}
	if err := RefuseUnverifiedClaudeSubscription(apiKey, false); err != nil {
		t.Fatal(err)
	}
	if ErrClaudeCodeOnly.(interface{ StatusCode() int }).StatusCode() != http.StatusForbidden {
		t.Fatal("wrong HTTP refusal")
	}
}
