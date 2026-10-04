package handlers

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClaudeCodeOnlyModelLists(t *testing.T) {
	coreauth.SetClaudeCodeOnly(true)
	t.Cleanup(func() { coreauth.SetClaudeCodeOnly(false) })
	m := coreauth.NewManager(nil, nil, nil)
	login := &coreauth.Auth{ID: "model-list-login", Provider: "claude", Metadata: map[string]any{"access_token": "test"}}
	if _, err := m.Register(context.Background(), login); err != nil {
		t.Fatal(err)
	}
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(login.ID, "claude", []*registry.ModelInfo{{ID: "claude-hidden"}})
	t.Cleanup(func() { reg.UnregisterClient(login.ID) })
	h := &BaseAPIHandler{AuthManager: m}
	for _, tc := range []struct {
		format, body string
		native, want bool
	}{
		{"openai", `{"data":[{"id":"claude-hidden"},{"id":"visible"}]}`, false, false},
		{"openai", `{"models":[{"slug":"claude-hidden"},{"slug":"visible"}]}`, true, false},
		{"gemini", `{"models":[{"name":"models/claude-hidden"},{"name":"models/visible"}]}`, false, false},
		{"claude", `{"data":[{"id":"claude-hidden"},{"id":"visible"}]}`, false, false},
		{"claude", `{"data":[{"id":"claude-hidden"},{"id":"visible"}]}`, true, true},
	} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		if tc.native {
			coreauth.MarkNativeClaudeCode(c)
		}
		got := h.filterClaudeSubscriptionModels(c, tc.format, []byte(tc.body))
		if strings.Contains(string(got), "claude-hidden") != tc.want {
			t.Fatalf("%s native=%t: %s", tc.format, tc.native, got)
		}
		if !strings.Contains(string(got), "visible") {
			t.Fatal("unrelated model removed")
		}
	}
}
