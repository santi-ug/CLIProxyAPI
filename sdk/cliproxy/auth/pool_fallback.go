package auth

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

type poolAttemptContextKey struct{}

type poolAttemptState struct {
	mu       sync.Mutex
	failures map[string]bool
}

func withPoolAttemptState(ctx context.Context) context.Context {
	return context.WithValue(ctx, poolAttemptContextKey{}, &poolAttemptState{failures: make(map[string]bool)})
}

func recordPoolAttemptResult(ctx context.Context, result Result) {
	state, _ := ctx.Value(poolAttemptContextKey{}).(*poolAttemptState)
	if state == nil || result.Success {
		return
	}
	state.mu.Lock()
	state.failures[result.AuthID] = result.Error != nil && result.Error.HTTPStatus == http.StatusTooManyRequests
	state.mu.Unlock()
}

func poolAttemptQuotaFailure(ctx context.Context, id string) (bool, bool) {
	if ctx == nil {
		return false, false
	}
	state, _ := ctx.Value(poolAttemptContextKey{}).(*poolAttemptState)
	if state == nil {
		return false, false
	}
	state.mu.Lock()
	quota, observed := state.failures[id]
	state.mu.Unlock()
	return quota, observed
}

func poolMetadataString(auth *Auth, key string) string {
	value, _ := auth.Metadata[key].(string)
	return strings.ToLower(strings.TrimSpace(value))
}

// Auto reserves below the burn tier are quota fallback only. Manual On and the
// router's explicit priority-200 burn decision are ordinary eligible credentials.
func protectedPoolReserve(auth *Auth) bool {
	if auth == nil || poolMetadataString(auth, "pool_role") != "reserve" || authPriority(auth) >= 200 {
		return false
	}
	mode := poolMetadataString(auth, "pool_mode")
	return mode == "" || mode == "auto"
}

// Caller holds m.mu. All primaries for this provider and route must have actual
// quota evidence; excluding a primary after a login or transport failure is not evidence.
func (m *Manager) reserveFallbackAllowedLocked(ctx context.Context, reserve *Auth, model string, eligibility authSelectionEligibility, now time.Time) bool {
	if !protectedPoolReserve(reserve) {
		return true
	}
	foundPrimary := false
	for _, primary := range m.auths {
		if primary == nil || executorKeyFromAuth(primary) != executorKeyFromAuth(reserve) || poolMetadataString(primary, "pool_role") != "primary" || !eligibility.allows(primary) {
			continue
		}
		if !m.authSupportsRouteModel(registry.GetGlobalRegistry(), primary, model) {
			continue
		}
		foundPrimary = true
		if poolMetadataString(primary, "pool_mode") == "off" {
			return false
		}
		selectionModel := m.selectionModelKeyForAuth(primary, model)
		// Credential LastError may belong to a different model. A retained
		// quota flag must not hide this routed model's newer non-quota failure.
		if state := existingModelState(primary, selectionModel); state != nil && state.LastError != nil && state.LastError.HTTPStatus != http.StatusTooManyRequests {
			return false
		}
		if quota, observed := poolAttemptQuotaFailure(ctx, primary.ID); observed {
			if !quota {
				return false
			}
			continue
		}
		if hasUnauthorizedAuthFailure(primary) || (primary.LastError != nil && primary.LastError.HTTPStatus != http.StatusTooManyRequests) {
			return false
		}
		// An Auto router pause may disable a depleted primary without revoking it.
		// Test its underlying cooldown, while retaining token/login checks.
		candidate := primary.Clone()
		candidate.Disabled = false
		if candidate.Status == StatusDisabled {
			candidate.Status = StatusActive
		}
		blocked, reason, _ := isAuthBlockedForModel(candidate, selectionModel, now)
		if !blocked || reason != blockReasonCooldown {
			return false
		}
	}
	return foundPrimary
}
