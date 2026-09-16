package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executionregistry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// recordingSelector is a non-built-in selector: it disables the fast scheduler so the
// legacy selection path is exercised, and returns the first candidate handed to it.
type recordingSelector struct{}

func (s *recordingSelector) Pick(_ context.Context, _ string, _ string, _ cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	if len(auths) == 0 {
		return nil, &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	return auths[0], nil
}

// countingExecutor records how many upstream requests were attempted.
type countingExecutor struct {
	provider string
	calls    int
}

func (e *countingExecutor) Identifier() string { return e.provider }

func (e *countingExecutor) callCount() int { return e.calls }

func (e *countingExecutor) Execute(_ context.Context, _ *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.calls++
	return cliproxyexecutor.Response{Payload: []byte("ok")}, nil
}

func (e *countingExecutor) ExecuteStream(_ context.Context, _ *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.calls++
	return nil, nil
}

func (e *countingExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) { return auth, nil }

func (e *countingExecutor) CountTokens(_ context.Context, _ *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.calls++
	return cliproxyexecutor.Response{Payload: []byte("ok")}, nil
}

func (e *countingExecutor) HttpRequest(_ context.Context, _ *Auth, _ *http.Request) (*http.Response, error) {
	return nil, nil
}

// policyKey returns the provider configuration instance api-key attribute that identifies a
// concrete provider configuration entry.
func policyAuth(id, provider, providerKey string) *Auth {
	auth := &Auth{ID: id, Provider: provider, Status: StatusActive}
	if providerKey != "" {
		auth.Attributes = map[string]string{"api_key": providerKey}
	}
	return auth
}

func withAPIKeyPolicy(opts cliproxyexecutor.Options, set *internalconfig.APIKeyPolicySet) cliproxyexecutor.Options {
	opts.EnsureMetadata()
	opts.Metadata[cliproxyexecutor.APIKeyPolicyMetadataKey] = set
	return opts
}

// providerExclusionPolicy compiles the same policy the config layer publishes for one client
// key, so the test drives the real compilation instead of a hand-built set.
func providerExclusionPolicy(t *testing.T, apiKey string, providers ...string) *internalconfig.APIKeyPolicySet {
	t.Helper()

	set := (&internalconfig.Config{SDKConfig: internalconfig.SDKConfig{
		APIKeyPolicies: internalconfig.NormalizeAPIKeyPolicies([]internalconfig.APIKeyPolicy{
			{APIKey: apiKey, ExcludedAIProviders: providers},
		}),
	}}).APIKeyPolicySetFor(apiKey)
	if set == nil {
		t.Fatal("compiled policy is nil")
	}
	return set
}

// accountExclusionPolicy compiles an account-scoped policy for one client key.
func accountExclusionPolicy(t *testing.T, apiKey string, accounts ...string) *internalconfig.APIKeyPolicySet {
	t.Helper()

	set := (&internalconfig.Config{SDKConfig: internalconfig.SDKConfig{
		APIKeyPolicies: internalconfig.NormalizeAPIKeyPolicies([]internalconfig.APIKeyPolicy{
			{APIKey: apiKey, ExcludedAIAccounts: accounts},
		}),
	}}).APIKeyPolicySetFor(apiKey)
	if set == nil {
		t.Fatal("compiled policy is nil")
	}
	return set
}

func registerPolicyAuth(t *testing.T, manager *Manager, auth *Auth, models ...string) {
	t.Helper()
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register %s: %v", auth.ID, errRegister)
	}
	modelInfos := make([]*registry.ModelInfo, 0, len(models))
	for _, model := range models {
		modelInfos = append(modelInfos, &registry.ModelInfo{ID: model})
	}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, modelInfos)
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
	manager.refreshAuth(context.Background(), auth.ID)
}

// The provider-instance and account restrictions must filter the fast scheduler before a
// credential is chosen, so the forbidden instance is never returned.
func TestAPIKeyPolicyFiltersFastScheduler(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(schedulerProviderTestExecutor{provider: "codex"})
	registerPolicyAuth(t, manager, policyAuth("blocked-auth", "codex", "provider-key-1"), "gpt-5")
	registerPolicyAuth(t, manager, policyAuth("allowed-auth", "codex", "provider-key-2"), "gpt-5")

	policy := providerExclusionPolicy(t, "sk-a", "provider-key-1")
	opts := withAPIKeyPolicy(cliproxyexecutor.Options{}, policy)
	for i := 0; i < 4; i++ {
		auth, _, errPick := manager.pickNext(context.Background(), "codex", "gpt-5", opts, nil)
		if errPick != nil {
			t.Fatalf("pickNext error = %v", errPick)
		}
		if auth.ID != "allowed-auth" {
			t.Fatalf("picked %q, want allowed-auth", auth.ID)
		}
	}
}

// Same guarantee for the legacy selector path (custom selector, no fast scheduler).
func TestAPIKeyPolicyFiltersLegacySelector(t *testing.T) {
	manager := NewManager(nil, &recordingSelector{}, nil)
	manager.RegisterExecutor(schedulerProviderTestExecutor{provider: "codex"})
	registerPolicyAuth(t, manager, policyAuth("blocked-auth", "codex", "provider-key-1"), "gpt-5")
	registerPolicyAuth(t, manager, policyAuth("allowed-auth", "codex", "provider-key-2"), "gpt-5")

	policy := providerExclusionPolicy(t, "sk-a", "provider-key-1")
	opts := withAPIKeyPolicy(cliproxyexecutor.Options{}, policy)
	auth, _, errPick := manager.pickNextLegacy(context.Background(), "codex", "gpt-5", opts, nil)
	if errPick != nil {
		t.Fatalf("pickNextLegacy error = %v", errPick)
	}
	if auth.ID != "allowed-auth" {
		t.Fatalf("picked %q, want allowed-auth", auth.ID)
	}
}

// A pinned credential must not bypass the policy: the pinned-but-forbidden auth is rejected
// and no upstream request is made.
func TestAPIKeyPolicyCannotBeBypassedByPinnedAuth(t *testing.T) {
	executor := &countingExecutor{provider: "codex"}
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(executor)
	registerPolicyAuth(t, manager, policyAuth("blocked-auth", "codex", "provider-key-1"), "gpt-5")

	policy := providerExclusionPolicy(t, "sk-a", "provider-key-1")
	opts := withAPIKeyPolicy(cliproxyexecutor.Options{}, policy)
	opts.EnsureMetadata()
	opts.Metadata[cliproxyexecutor.PinnedAuthMetadataKey] = "blocked-auth"

	_, errExecute := manager.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "gpt-5"}, opts)
	if errExecute == nil {
		t.Fatal("expected Execute to fail when the pinned auth is policy-excluded")
	}
	if calls := executor.callCount(); calls != 0 {
		t.Fatalf("executor was called %d times, want 0", calls)
	}
}

// When every candidate is excluded, selection must fail rather than fall back to a
// forbidden credential, and no upstream request may be sent.
func TestAPIKeyPolicyAllCandidatesExcluded(t *testing.T) {
	for _, tc := range []struct {
		name     string
		selector Selector
	}{
		{name: "fast_scheduler", selector: &RoundRobinSelector{}},
		{name: "legacy_selector", selector: &recordingSelector{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			executor := &countingExecutor{provider: "codex"}
			manager := NewManager(nil, tc.selector, nil)
			manager.RegisterExecutor(executor)
			registerPolicyAuth(t, manager, policyAuth("blocked-a", "codex", "provider-key-1"), "gpt-5")
			registerPolicyAuth(t, manager, policyAuth("blocked-b", "codex", "provider-key-2"), "gpt-5")

			policy := providerExclusionPolicy(t, "sk-a", "provider-key-1", "provider-key-2")
			opts := withAPIKeyPolicy(cliproxyexecutor.Options{}, policy)
			_, errExecute := manager.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "gpt-5"}, opts)
			if errExecute == nil {
				t.Fatal("expected Execute to fail when every candidate is excluded")
			}
			var authErr *Error
			if !errors.As(errExecute, &authErr) {
				t.Fatalf("error = %T, want *Error", errExecute)
			}
			if calls := executor.callCount(); calls != 0 {
				t.Fatalf("executor was called %d times, want 0", calls)
			}
		})
	}
}

// Account exclusions match either the auth id or the account email, and only that account.
func TestAPIKeyPolicyAccountExclusion(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(schedulerProviderTestExecutor{provider: "codex"})
	blocked := policyAuth("blocked-auth", "codex", "")
	blocked.Metadata = map[string]any{"email": "blocked@example.com"}
	registerPolicyAuth(t, manager, blocked, "gpt-5")
	registerPolicyAuth(t, manager, policyAuth("allowed-auth", "codex", ""), "gpt-5")

	policy := accountExclusionPolicy(t, "sk-a", "blocked@example.com")
	opts := withAPIKeyPolicy(cliproxyexecutor.Options{}, policy)
	for i := 0; i < 4; i++ {
		auth, _, errPick := manager.pickNext(context.Background(), "codex", "gpt-5", opts, nil)
		if errPick != nil {
			t.Fatalf("pickNext error = %v", errPick)
		}
		if auth.ID != "allowed-auth" {
			t.Fatalf("picked %q, want allowed-auth", auth.ID)
		}
	}
}

// A key without a policy keeps the existing behaviour: every credential stays selectable.
func TestAPIKeyPolicyAbsentKeepsAllAuthsSelectable(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(schedulerProviderTestExecutor{provider: "codex"})
	registerPolicyAuth(t, manager, policyAuth("auth-1", "codex", "provider-key-1"), "gpt-5")
	registerPolicyAuth(t, manager, policyAuth("auth-2", "codex", "provider-key-2"), "gpt-5")

	seen := make(map[string]bool)
	for i := 0; i < 4; i++ {
		auth, _, errPick := manager.pickNext(context.Background(), "codex", "gpt-5", cliproxyexecutor.Options{}, nil)
		if errPick != nil {
			t.Fatalf("pickNext error = %v", errPick)
		}
		seen[auth.ID] = true
	}
	if !seen["auth-1"] || !seen["auth-2"] {
		t.Fatalf("unrestricted key should reach both auths, saw %v", seen)
	}
	unrestricted := (&internalconfig.Config{SDKConfig: internalconfig.SDKConfig{
		APIKeyPolicies: internalconfig.NormalizeAPIKeyPolicies([]internalconfig.APIKeyPolicy{
			{APIKey: "sk-a", ExcludedAIProviders: []string{"provider-key-1"}},
		}),
	}}).APIKeyPolicySetFor("sk-other")
	if unrestricted != nil {
		t.Fatalf("key without a policy resolved to %#v, want nil", unrestricted)
	}
}

// Retry rounds must not resurrect an excluded credential.
func TestAPIKeyPolicyRetryCannotSelectExcludedAuth(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	registerPolicyAuth(t, manager, policyAuth("blocked-auth", "codex", "provider-key-1"), "gpt-5")

	policy := providerExclusionPolicy(t, "sk-a", "provider-key-1")
	opts := withAPIKeyPolicy(cliproxyexecutor.Options{}, policy)
	eligibility := authSelectionEligibilityForRequest(context.Background(), opts)

	if manager.retryAllowed(1, []string{"codex"}, "gpt-5", eligibility, "", 3) {
		t.Fatal("retryAllowed must not allow a retry when the only auth is policy-excluded")
	}
	if _, found := manager.closestCooldownWait([]string{"codex"}, "gpt-5", 1, eligibility, "", 3); found {
		t.Fatal("closestCooldownWait must not report a wait for a policy-excluded auth")
	}
}

// Session affinity must not hand back a bound credential that the policy forbids.
func TestAPIKeyPolicySessionAffinitySkipsExcludedAuth(t *testing.T) {
	manager := NewManager(nil, NewSessionAffinitySelector(&RoundRobinSelector{}), nil)
	manager.RegisterExecutor(schedulerProviderTestExecutor{provider: "codex"})
	registerPolicyAuth(t, manager, policyAuth("blocked-auth", "codex", "provider-key-1"), "gpt-5")
	registerPolicyAuth(t, manager, policyAuth("allowed-auth", "codex", "provider-key-2"), "gpt-5")

	policy := providerExclusionPolicy(t, "sk-a", "provider-key-1")
	opts := withAPIKeyPolicy(cliproxyexecutor.Options{}, policy)
	opts.EnsureMetadata()
	opts.Metadata[cliproxyexecutor.SessionAffinityProviderMetadataKey] = "codex"
	opts.Metadata[cliproxyexecutor.SessionAffinityModelMetadataKey] = "gpt-5"
	opts.Headers = http.Header{"X-Session-Id": []string{"session-1"}}

	for i := 0; i < 4; i++ {
		auth, _, errPick := manager.pickNext(context.Background(), "codex", "gpt-5", opts, nil)
		if errPick != nil {
			t.Fatalf("pickNext error = %v", errPick)
		}
		if auth.ID != "allowed-auth" {
			t.Fatalf("picked %q, want allowed-auth", auth.ID)
		}
	}
}

// Home dispatch seeds its excluded ids with locally-forbidden credentials and re-verifies
// the returned credential, so a Home that ignores the exclusions cannot leak a forbidden one.
func TestAPIKeyPolicyHomeDispatchRejectsExcludedAuth(t *testing.T) {
	dispatcher := &retryContractHomeDispatcher{authIDs: []string{"blocked-auth", "allowed-auth"}}
	manager := NewManager(nil, nil, nil)
	manager.SetConfig(&internalconfig.Config{Home: internalconfig.HomeConfig{Enabled: true}})
	manager.PublishHomeDispatch(dispatcher, executionregistry.New(), 1)
	manager.RegisterExecutor(&retryContractHomeExecutor{})

	blocked := policyAuth("blocked-auth", "home-retry-contract", "provider-key-1")
	blocked.Metadata = map[string]any{"email": "blocked@example.com"}
	if _, errRegister := manager.Register(context.Background(), blocked); errRegister != nil {
		t.Fatalf("register blocked auth: %v", errRegister)
	}
	allowed := policyAuth("allowed-auth", "home-retry-contract", "provider-key-2")
	if _, errRegister := manager.Register(context.Background(), allowed); errRegister != nil {
		t.Fatalf("register allowed auth: %v", errRegister)
	}

	policy := providerExclusionPolicy(t, "sk-a", "provider-key-1")
	opts := withAPIKeyPolicy(cliproxyexecutor.Options{}, policy)
	response, errExecute := manager.Execute(context.Background(), []string{"home-retry-contract"}, cliproxyexecutor.Request{Model: "gpt"}, opts)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if string(response.Payload) != "allowed-auth" {
		t.Fatalf("response payload = %q, want allowed-auth", string(response.Payload))
	}
	// The first dispatch must already carry the locally-forbidden id as an exclusion.
	excluded := dispatcher.Excluded()
	if len(excluded) == 0 || len(excluded[0]) != 1 || excluded[0][0] != "blocked-auth" {
		t.Fatalf("home excluded auth IDs = %v, want [[blocked-auth] ...]", excluded)
	}
}
