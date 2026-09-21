package config

import (
	"testing"
)

func TestAccountPolicy_Normalize(t *testing.T) {
	tests := []struct {
		name     string
		input    []AccountPolicy
		expected []AccountPolicy
	}{
		{
			name:     "empty slice",
			input:    nil,
			expected: nil,
		},
		{
			name: "trims whitespace and normalizes case",
			input: []AccountPolicy{
				{
					Provider: "  OpenAI  ",
					AuthID:   "  User@Example.COM  ",
					RateLimits: AccountRateLimits{
						MaxInFlight:  5,
						QueueRetries: 3,
					},
				},
				{
					Default: true,
					RateLimits: AccountRateLimits{
						MaxInFlight:  10,
						QueueRetries: -1, // should clamp to 0
					},
				},
			},
			expected: []AccountPolicy{
				{
					Provider: "openai",
					AuthID:   "user@example.com",
					RateLimits: AccountRateLimits{
						MaxInFlight:  5,
						QueueRetries: 3,
					},
				},
				{
					Default: true,
					RateLimits: AccountRateLimits{
						MaxInFlight:  10,
						QueueRetries: 0,
					},
				},
			},
		},
		{
			name: "drops entries with empty rate limits and negative max in flight",
			input: []AccountPolicy{
				{
					Provider: "anthropic",
					RateLimits: AccountRateLimits{
						MaxInFlight: -5,
					},
				},
			},
			expected: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := NormalizeAccountPolicies(tc.input)
			if len(actual) != len(tc.expected) {
				t.Fatalf("len(actual) = %d, want %d", len(actual), len(tc.expected))
			}
			for i := range actual {
				if actual[i].Provider != tc.expected[i].Provider ||
					actual[i].AuthID != tc.expected[i].AuthID ||
					actual[i].Default != tc.expected[i].Default ||
					actual[i].RateLimits.MaxInFlight != tc.expected[i].RateLimits.MaxInFlight ||
					actual[i].RateLimits.QueueRetries != tc.expected[i].RateLimits.QueueRetries {
					t.Errorf("[%d] actual = %+v, want %+v", i, actual[i], tc.expected[i])
				}
			}
		})
	}
}

func TestConfig_AccountPolicyFor(t *testing.T) {
	cfg := &Config{
		SDKConfig: SDKConfig{
			AccountPolicies: NormalizeAccountPolicies([]AccountPolicy{
				// 1. Exact match on auth-id
				{
					AuthID: "exact-user@domain.com",
					RateLimits: AccountRateLimits{
						MaxInFlight:  2,
						QueueRetries: 1,
					},
				},
				// 2. Wildcard match on auth-id
				{
					AuthID: "*@company.org",
					RateLimits: AccountRateLimits{
						MaxInFlight:  4,
						QueueRetries: 2,
					},
				},
				// 3. Provider match
				{
					Provider: "claude",
					RateLimits: AccountRateLimits{
						MaxInFlight:  8,
						QueueRetries: 3,
					},
				},
				// 4. Default policy
				{
					Default: true,
					RateLimits: AccountRateLimits{
						MaxInFlight:  16,
						QueueRetries: 4,
					},
				},
			}),
		},
	}

	// Case 1: Exact match beats wildcard, provider, and default
	pol := cfg.AccountPolicyFor("claude", "exact-user@domain.com")
	if pol == nil || pol.RateLimits.MaxInFlight != 2 || pol.RateLimits.QueueRetries != 1 {
		t.Fatalf("exact match failed, got %+v", pol)
	}

	// Case 2: Wildcard match beats provider and default
	pol = cfg.AccountPolicyFor("claude", "developer@company.org")
	if pol == nil || pol.RateLimits.MaxInFlight != 4 || pol.RateLimits.QueueRetries != 2 {
		t.Fatalf("wildcard match failed, got %+v", pol)
	}

	// Case 3: Email alias match
	pol = cfg.AccountPolicyFor("claude", "some-id", "engineer@company.org")
	if pol == nil || pol.RateLimits.MaxInFlight != 4 || pol.RateLimits.QueueRetries != 2 {
		t.Fatalf("email alias wildcard match failed, got %+v", pol)
	}

	// Case 4: Provider match beats default
	pol = cfg.AccountPolicyFor("claude", "other-user@other.com")
	if pol == nil || pol.RateLimits.MaxInFlight != 8 || pol.RateLimits.QueueRetries != 3 {
		t.Fatalf("provider match failed, got %+v", pol)
	}

	// Case 5: Default policy used when provider and auth-id do not match
	pol = cfg.AccountPolicyFor("gemini", "random-user@random.com")
	if pol == nil || pol.RateLimits.MaxInFlight != 16 || pol.RateLimits.QueueRetries != 4 {
		t.Fatalf("default policy fallback failed, got %+v", pol)
	}

	// Case 6: Nil or empty config returns empty policy (MaxInFlight = 0, unlimited)
	var nilCfg *Config
	pol = nilCfg.AccountPolicyFor("claude", "any")
	if pol == nil || pol.RateLimits.MaxInFlight != 0 {
		t.Fatalf("nil config should return empty policy with MaxInFlight=0, got %+v", pol)
	}

	emptyCfg := &Config{}
	pol = emptyCfg.AccountPolicyFor("claude", "any")
	if pol == nil || pol.RateLimits.MaxInFlight != 0 {
		t.Fatalf("empty config should return empty policy with MaxInFlight=0, got %+v", pol)
	}
}
