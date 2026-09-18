package api

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
)

// Usage accounting must follow the compiled policies: a key restricted only by model, or a
// key with no policy at all, keeps no counter.
func TestUsageLimitedFingerprintsTracksOnlyLimitedKeys(t *testing.T) {
	t.Parallel()

	cfg := &config.SDKConfig{
		APIKeys: []string{"sk-limited", "sk-models", "sk-plain"},
		APIKeyPolicies: config.NormalizeAPIKeyPolicies([]config.APIKeyPolicy{
			{APIKey: "sk-limited", UsageLimits: config.APIKeyUsageLimits{DailyTokensMB: 200}},
			{APIKey: "sk-models", ExcludedModels: []string{"gpt-5"}},
		}),
	}

	tracked := usageLimitedFingerprints(buildAPIKeyPolicyIndex(cfg))
	if len(tracked) != 1 {
		t.Fatalf("tracked = %d keys, want 1: %#v", len(tracked), tracked)
	}
	if _, ok := tracked[misc.APIKeyFingerprint("sk-limited")]; !ok {
		t.Fatal("key with a usage limit is not tracked")
	}

	// A configuration without any usage limit tracks nothing.
	if tracked = usageLimitedFingerprints(buildAPIKeyPolicyIndex(&config.SDKConfig{})); len(tracked) != 0 {
		t.Fatalf("empty config tracked %d keys", len(tracked))
	}
}
