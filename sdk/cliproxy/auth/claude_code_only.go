package auth

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// ClaudeCodeOnlyMessage is the refusal returned when claude-code-only keeps a request
// away from Claude subscription logins.
const ClaudeCodeOnlyMessage = "Claude subscription logins only serve Claude Code"

// claudeCodeOnlyError refuses a request that claude-code-only keeps away from Claude logins.
// It is request-scoped, so it never cools a credential or triggers failover.
type claudeCodeOnlyError struct{}

func (claudeCodeOnlyError) Error() string         { return ClaudeCodeOnlyMessage }
func (claudeCodeOnlyError) StatusCode() int       { return http.StatusForbidden }
func (claudeCodeOnlyError) IsRequestScoped() bool { return true }

// ErrClaudeCodeOnly is the HTTP 403 refusal for requests claude-code-only blocks.
var ErrClaudeCodeOnly error = claudeCodeOnlyError{}

// nativeClaudeCodeGinKey marks a gin request the server verified as native Claude Code.
// Gin keys are server-side only, so clients cannot set it.
const nativeClaudeCodeGinKey = "cliproxy.native_claude_code"

// claudeCodeOnly mirrors the claude-code-only config flag. The server sets it on start and reload.
var claudeCodeOnly atomic.Bool

// SetClaudeCodeOnly toggles the claude-code-only policy globally.
func SetClaudeCodeOnly(enabled bool) {
	claudeCodeOnly.Store(enabled)
}

// ClaudeCodeOnlyEnabled reports whether claude-code-only is on.
func ClaudeCodeOnlyEnabled() bool {
	return claudeCodeOnly.Load()
}

// IsClaudeSubscriptionAuth reports whether auth is a Claude login (OAuth or file credential)
// rather than a Claude API key. An API-key entry that holds an OAuth token counts as a login.
func IsClaudeSubscriptionAuth(auth *Auth) bool {
	if auth == nil || !strings.EqualFold(strings.TrimSpace(auth.Provider), "claude") {
		return false
	}
	if auth.AuthKind() != AuthKindAPIKey {
		return true
	}
	return strings.Contains(authAttribute(auth, AttributeAPIKey), "sk-ant-oat")
}

// MarkNativeClaudeCode records on a gin context that the request is verified native Claude Code.
func MarkNativeClaudeCode(c interface{ Set(string, any) }) {
	if c != nil {
		c.Set(nativeClaudeCodeGinKey, true)
	}
}

// IsNativeClaudeCode reports whether MarkNativeClaudeCode was called on this gin context.
func IsNativeClaudeCode(c interface{ Get(string) (any, bool) }) bool {
	if c == nil {
		return false
	}
	value, _ := c.Get(nativeClaudeCodeGinKey)
	native, _ := value.(bool)
	return native
}

// claudeSubscriptionsBlocked reports whether this request must stay away from Claude
// subscription logins: claude-code-only is on and the request is not marked native.
// Requests without a gin context (internal callers) are blocked too.
func claudeSubscriptionsBlocked(ctx context.Context) bool {
	if !claudeCodeOnly.Load() {
		return false
	}
	if ctx == nil {
		return true
	}
	ginCtx, _ := ctx.Value("gin").(interface{ Get(string) (any, bool) })
	return !IsNativeClaudeCode(ginCtx)
}

// claudeCodeOnlyRefusal fails a blocked request before any upstream call when Claude
// subscription logins are the only credentials that could serve it. When another
// credential (such as a Claude API key) could serve, selection proceeds and simply skips
// the logins.
func (m *Manager) claudeCodeOnlyRefusal(ctx context.Context, providers []string, opts cliproxyexecutor.Options, model string) error {
	if m == nil || !claudeSubscriptionsBlocked(ctx) {
		return nil
	}
	model = authSelectionModelFromOptions(opts, model)
	providerSet := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		providerSet[canonicalSchedulingProvider(provider)] = struct{}{}
	}
	registryRef := registry.GetGlobalRegistry()
	m.mu.RLock()
	defer m.mu.RUnlock()
	blocked := false
	for _, candidate := range m.auths {
		if candidate == nil || candidate.Disabled {
			continue
		}
		if _, ok := providerSet[canonicalSchedulingProvider(executorKeyFromAuth(candidate))]; !ok {
			continue
		}
		if strings.TrimSpace(model) != "" && !m.authSupportsRouteModel(registryRef, candidate, model) {
			continue
		}
		if !IsClaudeSubscriptionAuth(candidate) {
			return nil
		}
		blocked = true
	}
	if blocked {
		return ErrClaudeCodeOnly
	}
	return nil
}

// RefuseUnverifiedClaudeSubscription is the executor-side backstop for claude-code-only.
// Selection already keeps unmarked requests away from Claude logins, so this only fires if
// the executor's own Claude Code detection disagrees; it then refuses instead of cloaking.
func RefuseUnverifiedClaudeSubscription(auth *Auth, confirmedClaudeCode bool) error {
	if confirmedClaudeCode || !claudeCodeOnly.Load() || !IsClaudeSubscriptionAuth(auth) {
		return nil
	}
	return ErrClaudeCodeOnly
}

// ClaudeSubscriptionOnlyModels returns the IDs of models that only Claude subscription logins
// provide. Model listings hide them from clients that are not native Claude Code.
func (m *Manager) ClaudeSubscriptionOnlyModels() map[string]struct{} {
	if m == nil {
		return nil
	}
	subscriptions := make(map[string]struct{})
	m.mu.RLock()
	for _, candidate := range m.auths {
		if IsClaudeSubscriptionAuth(candidate) {
			subscriptions[candidate.ID] = struct{}{}
		}
	}
	m.mu.RUnlock()
	if len(subscriptions) == 0 {
		return nil
	}
	return registry.GetGlobalRegistry().ModelsProvidedOnlyBy(subscriptions)
}
