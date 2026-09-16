package config

import "testing"

func TestNormalizeAPIKeyPolicies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []APIKeyPolicy
		wantKeys []string
	}{
		{
			name:     "empty input",
			input:    nil,
			wantKeys: nil,
		},
		{
			name: "trims values and drops entries without restrictions",
			input: []APIKeyPolicy{
				{APIKey: " sk-a ", ExcludedModels: []string{" gpt-5 ", "gpt-5"}},
				{APIKey: "sk-empty"},
				{APIKey: "   "},
			},
			wantKeys: []string{"sk-a"},
		},
		{
			name: "keeps first definition of a duplicated api-key",
			input: []APIKeyPolicy{
				{APIKey: "sk-a", ExcludedModels: []string{"first"}},
				{APIKey: "sk-a", ExcludedModels: []string{"second"}},
			},
			wantKeys: []string{"sk-a"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := NormalizeAPIKeyPolicies(tc.input)
			if len(got) != len(tc.wantKeys) {
				t.Fatalf("len = %d, want %d: %#v", len(got), len(tc.wantKeys), got)
			}
			for i, key := range tc.wantKeys {
				if got[i].APIKey != key {
					t.Fatalf("policy[%d].api-key = %q, want %q", i, got[i].APIKey, key)
				}
			}
		})
	}

	deduped := NormalizeAPIKeyPolicies([]APIKeyPolicy{
		{APIKey: "sk-a", ExcludedModels: []string{"first"}},
		{APIKey: "sk-a", ExcludedModels: []string{"second"}},
	})
	if deduped[0].ExcludedModels[0] != "first" {
		t.Fatalf("duplicate api-key kept %q, want first definition", deduped[0].ExcludedModels[0])
	}
}

func TestParseConfigBytesNormalizesAPIKeyPolicies(t *testing.T) {
	t.Parallel()

	const yamlConfig = `
api-keys:
  - "sk-client-a"
  - "sk-client-b"
api-key-policies:
  - api-key: " sk-client-b "
    excluded-models:
      - " gemini-2.5-* "
      - "gemini-2.5-*"
    excluded-ai-providers:
      - "provider-instance-1"
    excluded-ai-accounts:
      - "user@example.com"
  - api-key: "sk-client-b"
    excluded-models:
      - "duplicate-should-be-dropped"
  - api-key: "sk-unused"
    excluded-models:
      - "*"
`

	cfg, err := ParseConfigBytes([]byte(yamlConfig))
	if err != nil {
		t.Fatalf("ParseConfigBytes failed: %v", err)
	}
	if len(cfg.APIKeys) != 2 {
		t.Fatalf("api-keys len = %d, want 2", len(cfg.APIKeys))
	}
	if len(cfg.APIKeyPolicies) != 2 {
		t.Fatalf("api-key-policies len = %d, want 2: %#v", len(cfg.APIKeyPolicies), cfg.APIKeyPolicies)
	}
	policy := cfg.APIKeyPolicies[0]
	if policy.APIKey != "sk-client-b" {
		t.Fatalf("policy api-key = %q, want sk-client-b", policy.APIKey)
	}
	if len(policy.ExcludedModels) != 1 || policy.ExcludedModels[0] != "gemini-2.5-*" {
		t.Fatalf("excluded-models = %#v, want [gemini-2.5-*]", policy.ExcludedModels)
	}
	if len(policy.ExcludedAIProviders) != 1 || policy.ExcludedAIProviders[0] != "provider-instance-1" {
		t.Fatalf("excluded-ai-providers = %#v", policy.ExcludedAIProviders)
	}
	if len(policy.ExcludedAIAccounts) != 1 || policy.ExcludedAIAccounts[0] != "user@example.com" {
		t.Fatalf("excluded-ai-accounts = %#v", policy.ExcludedAIAccounts)
	}
	// A policy that references a key absent from api-keys survives parsing so it stays
	// visible and fixable through the management API. It is never applied, because the
	// runtime index only publishes policies for keys listed in api-keys (see
	// internal/api.buildAPIKeyPolicyIndex), and it never registers the key for
	// authentication (see internal/access/config_access).
	if len(cfg.APIKeyPolicies) != 2 || cfg.APIKeyPolicies[1].APIKey != "sk-unused" {
		t.Fatalf("unexpected policies = %#v", cfg.APIKeyPolicies)
	}
}

func TestAPIKeyPolicySetFor(t *testing.T) {
	t.Parallel()

	cfg := &Config{SDKConfig: SDKConfig{
		APIKeys: []string{"sk-a", "sk-b"},
		APIKeyPolicies: NormalizeAPIKeyPolicies([]APIKeyPolicy{
			{APIKey: "sk-a", ExcludedModels: []string{"gemini-2.5-*"}},
			{APIKey: "sk-b", ExcludedModels: []string{"*"}},
		}),
	}}

	// PolicySetFor compiles by api-key value alone; whether the key is a configured client
	// key is enforced by the runtime index, not here.
	if set := cfg.APIKeyPolicySetFor("sk-unknown"); set != nil {
		t.Fatalf("key without a policy resolved to %#v, want nil", set)
	}
	if set := cfg.APIKeyPolicySetFor(""); set != nil {
		t.Fatalf("empty key resolved to %#v, want nil", set)
	}

	setA := cfg.APIKeyPolicySetFor("sk-a")
	if setA == nil {
		t.Fatal("sk-a policy is nil")
	}
	if !setA.DeniesModel("gemini-2.5-pro") {
		t.Fatal("sk-a should deny gemini-2.5-pro")
	}
	if setA.DeniesModel("gpt-5") {
		t.Fatal("sk-a should allow gpt-5")
	}

	setB := cfg.APIKeyPolicySetFor("sk-b")
	if setB == nil || !setB.DeniesModel("anything") {
		t.Fatal("bare * should deny every model")
	}
}

func TestAPIKeyPolicySetDeniesModelWildcards(t *testing.T) {
	t.Parallel()

	set := &APIKeyPolicySet{excludedModels: []string{"gemini-2.5-*", "pro_0_2/gpt-5.5", "*-deprecated"}}
	tests := []struct {
		model string
		want  bool
	}{
		{"gemini-2.5-pro", true},
		{"Gemini-2.5-FLASH", true},
		{"gemini-2.0-pro", false},
		{"pro_0_2/gpt-5.5", true},
		{"gpt-5.5", false},
		{"old-deprecated", true},
		{"gpt-5(high)", false},
	}
	for _, tc := range tests {
		t.Run(tc.model, func(t *testing.T) {
			t.Parallel()
			if got := set.DeniesModel(tc.model); got != tc.want {
				t.Fatalf("DeniesModel(%q) = %v, want %v", tc.model, got, tc.want)
			}
		})
	}
}

// Policies are configured with outward-facing model names, which may carry a provider
// prefix. Matching the unprefixed form as well keeps request enforcement consistent with
// the /v1/models filter, which reports the prefixed identifier.
func TestAPIKeyPolicySetDeniesPrefixedModel(t *testing.T) {
	t.Parallel()

	set := &APIKeyPolicySet{excludedModels: []string{"gpt-5.5"}}
	if !set.DeniesModel("pro_0_2/gpt-5.5") {
		t.Fatal("prefixed outward model should match the unprefixed pattern")
	}
	if set.DeniesModel("pro_0_2/gpt-4") {
		t.Fatal("unrelated prefixed model should not be denied")
	}
}

func TestAPIKeyPolicySetEmptyAndRestrictsAuth(t *testing.T) {
	t.Parallel()

	var nilSet *APIKeyPolicySet
	if !nilSet.Empty() {
		t.Fatal("nil set must be empty")
	}
	if nilSet.RestrictsAuth() {
		t.Fatal("nil set must not report auth restrictions")
	}
	if nilSet.DeniesModel("gpt-5") || nilSet.DeniesAuth("a", "b", "c") {
		t.Fatal("nil set must not deny anything")
	}

	modelOnly := &APIKeyPolicySet{excludedModels: []string{"gpt-5"}}
	if modelOnly.Empty() {
		t.Fatal("model-only set must not be empty")
	}
	if modelOnly.RestrictsAuth() {
		t.Fatal("model-only set must not report auth restrictions")
	}
}

func TestAPIKeyPolicySetDeniesAuth(t *testing.T) {
	t.Parallel()

	set := &APIKeyPolicySet{
		excludedProviders: map[string]struct{}{"provider-key-1": {}},
		excludedAccounts:  map[string]struct{}{"user@example.com": {}, "codex/account-2.json": {}},
	}

	tests := []struct {
		name     string
		authID   string
		provider string
		email    string
		want     bool
	}{
		{"provider instance", "auth-1", "provider-key-1", "other@example.com", true},
		{"sibling provider instance", "auth-2", "provider-key-2", "other@example.com", false},
		{"account email", "auth-3", "provider-key-2", "USER@example.com", true},
		{"account id", "codex/account-2.json", "provider-key-2", "", true},
		{"unrelated", "auth-4", "provider-key-2", "other@example.com", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := set.DeniesAuth(tc.authID, tc.provider, tc.email); got != tc.want {
				t.Fatalf("DeniesAuth(%q, %q, %q) = %v, want %v", tc.authID, tc.provider, tc.email, got, tc.want)
			}
		})
	}
}
