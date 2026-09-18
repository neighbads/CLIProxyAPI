package config

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	"gopkg.in/yaml.v3"
)

// The keys used here are the ones documented in config.example.yaml.
func TestAPIKeyPolicyUnmarshalsUsageLimitsFromYAML(t *testing.T) {
	t.Parallel()

	var policies []APIKeyPolicy
	source := `
- api-key: "your-api-key-1"
  excluded-models:
    - "gpt-5*"
  usage-limits:
    daily-tokens-mb: 200
    monthly-tokens-mb: 4000
`
	if err := yaml.Unmarshal([]byte(source), &policies); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("len = %d, want 1", len(policies))
	}
	if got := policies[0].UsageLimits; got.DailyTokensMB != 200 || got.MonthlyTokensMB != 4000 {
		t.Fatalf("usage-limits = %#v, want 200/4000", got)
	}
}

func TestNormalizeAPIKeyPoliciesKeepsUsageLimitOnlyEntries(t *testing.T) {
	t.Parallel()

	got := NormalizeAPIKeyPolicies([]APIKeyPolicy{
		{APIKey: "sk-a", UsageLimits: APIKeyUsageLimits{DailyTokensMB: 200}},
		{APIKey: "sk-negative", UsageLimits: APIKeyUsageLimits{DailyTokensMB: -5, MonthlyTokensMB: -1}},
	})
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1: %#v", len(got), got)
	}
	if got[0].APIKey != "sk-a" || got[0].UsageLimits.DailyTokensMB != 200 {
		t.Fatalf("policy = %#v, want sk-a with 200", got[0])
	}
}

func TestAPIKeyPolicySetCompilesUsageLimits(t *testing.T) {
	t.Parallel()

	cfg := &Config{SDKConfig: SDKConfig{
		APIKeyPolicies: NormalizeAPIKeyPolicies([]APIKeyPolicy{
			{APIKey: "sk-a", UsageLimits: APIKeyUsageLimits{DailyTokensMB: 200, MonthlyTokensMB: 4000}},
			{APIKey: "sk-models", ExcludedModels: []string{"gpt-5"}},
		}),
	}}

	set := cfg.APIKeyPolicySetFor("sk-a")
	if set == nil {
		t.Fatal("usage-limit-only policy compiled to nil")
	}
	if set.Empty() {
		t.Fatal("usage-limit-only policy reports Empty")
	}
	if !set.LimitsUsage() {
		t.Fatal("LimitsUsage = false, want true")
	}
	if got, want := set.DailyTokenLimit(), int64(200_000_000); got != want {
		t.Fatalf("daily limit = %d, want %d", got, want)
	}
	if got, want := set.MonthlyTokenLimit(), int64(4_000_000_000); got != want {
		t.Fatalf("monthly limit = %d, want %d", got, want)
	}
	// Accounting is keyed by fingerprint so the raw client key never leaves the config.
	if got, want := set.Fingerprint(), misc.APIKeyFingerprint("sk-a"); got != want {
		t.Fatalf("fingerprint = %q, want %q", got, want)
	}

	// A policy without usage limits carries none, and keeps restricting what it did before.
	modelsOnly := cfg.APIKeyPolicySetFor("sk-models")
	if modelsOnly == nil {
		t.Fatal("model policy compiled to nil")
	}
	if modelsOnly.LimitsUsage() || modelsOnly.DailyTokenLimit() != 0 || modelsOnly.Fingerprint() != "" {
		t.Fatalf("model-only policy carries usage limits: %#v", modelsOnly)
	}
	if !modelsOnly.DeniesModel("gpt-5") {
		t.Fatal("model restriction lost")
	}
}
