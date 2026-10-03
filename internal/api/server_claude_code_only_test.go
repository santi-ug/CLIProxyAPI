package api

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClaudeCodeOnlyNativeMessagesMarker(t *testing.T) {
	s := newTestServerWithConfig(t, &config.Config{ClaudeCodeOnly: true})
	t.Cleanup(func() { coreauth.SetClaudeCodeOnly(false) })
	userID, _ := json.Marshal(`{"device_id":"0000000000000000000000000000000000000000000000000000000000000000","account_uuid":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","session_id":"11111111-2222-4333-8444-555555555555"}`)
	payload := `{"model":"claude-opus-4-6","metadata":{"user_id":` + string(userID) + `},"messages":[{"role":"user","content":"test"}]}`
	for _, native := range []bool{false, true} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("POST", "/v1/messages", strings.NewReader(payload))
		c.Request.Header.Set("User-Agent", "claude-cli/2.1.280 (external, cli)")
		if native {
			c.Request.Header.Set("X-App", "cli")
			c.Request.Header.Set("Anthropic-Beta", "claude-code-20250219")
		}
		s.markNativeClaudeCode(false)(c)
		if got := coreauth.IsNativeClaudeCode(c); got != native {
			t.Fatalf("native=%t marker=%t", native, got)
		}
	}
}
