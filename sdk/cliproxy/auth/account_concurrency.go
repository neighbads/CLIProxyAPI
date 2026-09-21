package auth

import (
	"context"
	"sync"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/ratelimit"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const (
	acquiredAccountIDKey   = "cliproxy.acquired_account_id"
	acquiredAccountSlotKey = "cliproxy.acquired_account_release"
)

func storePreAcquiredSlot(metadata map[string]any, authID string, release func()) {
	if release == nil {
		return
	}
	if metadata == nil {
		release()
		return
	}
	metadata[acquiredAccountIDKey] = authID
	metadata[acquiredAccountSlotKey] = release
}

func extractAcquiredSlot(metadata map[string]any, authID string) func() {
	if metadata == nil {
		return nil
	}
	storedID, _ := metadata[acquiredAccountIDKey].(string)
	release, _ := metadata[acquiredAccountSlotKey].(func())
	if release != nil && (storedID == "" || storedID == authID) {
		delete(metadata, acquiredAccountIDKey)
		delete(metadata, acquiredAccountSlotKey)
		return release
	}
	return nil
}

func cleanupAcquiredSlot(metadata map[string]any) {
	if metadata == nil {
		return
	}
	if rel, ok := metadata[acquiredAccountSlotKey].(func()); ok && rel != nil {
		delete(metadata, acquiredAccountIDKey)
		delete(metadata, acquiredAccountSlotKey)
		rel()
	}
}

func wrapStreamWithRelease(ctx context.Context, result *cliproxyexecutor.StreamResult, release func()) *cliproxyexecutor.StreamResult {
	if release == nil {
		return result
	}
	if result == nil || result.Chunks == nil {
		release()
		return result
	}
	var once sync.Once
	safeRelease := func() {
		once.Do(release)
	}
	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		defer safeRelease()
		for chunk := range result.Chunks {
			select {
			case out <- chunk:
			default:
				if ctx == nil {
					out <- chunk
					continue
				}
				select {
				case out <- chunk:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: result.Headers, Chunks: out}
}

type accountPoliciesAwareSelector interface {
	SetAccountPolicies(policies []internalconfig.AccountPolicy)
}

// AccountPolicyFor resolves the account rate limit policy for the given auth using the manager's current config snapshot.
func (m *Manager) AccountPolicyFor(auth *Auth) *internalconfig.AccountPolicy {
	if m == nil || auth == nil {
		return &internalconfig.AccountPolicy{}
	}
	cfg := m.runtimeConfigSnapshot()
	if cfg == nil {
		return &internalconfig.AccountPolicy{}
	}
	return cfg.AccountPolicyFor(auth.Provider, auth.ID, authAccountEmail(auth))
}

func (m *Manager) tracker() *ratelimit.Tracker {
	return ratelimit.AccountTracker()
}

func (m *Manager) acquireAccountSlot(ctx context.Context, auth *Auth, metadata map[string]any) (func(), error) {
	if m == nil || auth == nil {
		return func() {}, nil
	}

	// Check if slot was already pre-acquired in selector (e.g. SessionAffinitySelector)
	if rel := extractAcquiredSlot(metadata, auth.ID); rel != nil {
		return rel, nil
	}

	policy := m.AccountPolicyFor(auth)
	if policy == nil || policy.RateLimits.MaxInFlight <= 0 {
		return func() {}, nil
	}

	tracker := m.tracker()
	return tracker.Acquire(ctx, auth.ID, policy.RateLimits.MaxInFlight, policy.RateLimits.QueueRetries)
}

type accountPoliciesContextKey struct{}
type accountTrackerContextKey struct{}

func withAccountPolicies(ctx context.Context, policies []internalconfig.AccountPolicy) context.Context {
	if len(policies) == 0 {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, accountPoliciesContextKey{}, policies)
}

func accountPoliciesFromContext(ctx context.Context) []internalconfig.AccountPolicy {
	if ctx == nil {
		return nil
	}
	policies, _ := ctx.Value(accountPoliciesContextKey{}).([]internalconfig.AccountPolicy)
	return policies
}

func withAccountTracker(ctx context.Context, tracker *ratelimit.Tracker) context.Context {
	if tracker == nil {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, accountTrackerContextKey{}, tracker)
}

func accountTrackerFromContext(ctx context.Context) *ratelimit.Tracker {
	if ctx == nil {
		return nil
	}
	tracker, _ := ctx.Value(accountTrackerContextKey{}).(*ratelimit.Tracker)
	return tracker
}
