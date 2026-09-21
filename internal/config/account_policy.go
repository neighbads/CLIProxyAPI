package config

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
)

// AccountRateLimits caps the in-flight concurrency and queueing behaviour for an upstream account.
type AccountRateLimits struct {
	// MaxInFlight caps the number of active, in-flight requests the account may run concurrently.
	// A non-positive value means unlimited.
	MaxInFlight int `yaml:"max-in-flight,omitempty" json:"max-in-flight,omitempty"`

	// QueueRetries is the number of exponential backoff retries (1s, 2s, 4s, 8s...) to wait
	// for an in-flight slot before returning or spilling over.
	QueueRetries int `yaml:"queue-retries,omitempty" json:"queue-retries,omitempty"`
}

// Empty reports whether in-flight rate limits are unrestricted.
func (l AccountRateLimits) Empty() bool {
	return l.MaxInFlight <= 0
}

// Normalized clamps negative values to zero. If MaxInFlight is non-positive,
// QueueRetries is also zeroed as queueing has no effect without an in-flight cap.
func (l AccountRateLimits) Normalized() AccountRateLimits {
	out := l
	if out.MaxInFlight <= 0 {
		out.MaxInFlight = 0
		out.QueueRetries = 0
		return out
	}
	if out.QueueRetries < 0 {
		out.QueueRetries = 0
	}
	return out
}

// AccountPolicy defines rate-limiting and concurrency policy for upstream accounts.
type AccountPolicy struct {
	Provider   string            `yaml:"provider,omitempty" json:"provider,omitempty"`
	AuthID     string            `yaml:"auth-id,omitempty" json:"auth-id,omitempty"`
	Default    bool              `yaml:"default,omitempty" json:"default,omitempty"`
	RateLimits AccountRateLimits `yaml:"rate-limits,omitempty" json:"rate-limits,omitempty"`
}

// Empty reports whether the policy is empty / unconfigured.
func (p AccountPolicy) Empty() bool {
	return strings.TrimSpace(p.Provider) == "" &&
		strings.TrimSpace(p.AuthID) == "" &&
		!p.Default &&
		p.RateLimits.Empty()
}

// MaxInFlight returns the concurrent in-flight request limit, or 0 when unlimited.
func (p *AccountPolicy) MaxInFlight() int {
	if p == nil {
		return 0
	}
	return p.RateLimits.MaxInFlight
}

// QueueRetries returns the number of queue retries to wait for an in-flight slot.
func (p *AccountPolicy) QueueRetries() int {
	if p == nil {
		return 0
	}
	return p.RateLimits.QueueRetries
}

// NormalizeAccountPolicies trims entries, normalizes rate limits, and removes empty policies.
func NormalizeAccountPolicies(entries []AccountPolicy) []AccountPolicy {
	if len(entries) == 0 {
		return nil
	}
	out := make([]AccountPolicy, 0, len(entries))
	for _, entry := range entries {
		entry.Provider = strings.ToLower(strings.TrimSpace(entry.Provider))
		entry.AuthID = strings.ToLower(strings.TrimSpace(entry.AuthID))
		entry.RateLimits = entry.RateLimits.Normalized()
		if entry.RateLimits.Empty() {
			continue
		}
		out = append(out, entry)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// AccountPolicyFor resolves the account policy for a given provider, authID, and optional emails.
// Priority: exact or wildcard auth-id match > provider match > default: true.
// Returns *AccountPolicy or empty if unconfigured (defaulting to unlimited MaxInFlight = 0).
func (cfg *Config) AccountPolicyFor(provider, authID string, emails ...string) *AccountPolicy {
	if cfg == nil {
		return &AccountPolicy{}
	}
	return cfg.SDKConfig.AccountPolicyFor(provider, authID, emails...)
}

// AccountPolicyFor resolves the account policy for a given provider, authID, and optional emails.
// Priority: exact or wildcard auth-id match > provider match > default: true.
// Returns *AccountPolicy or empty if unconfigured (defaulting to unlimited MaxInFlight = 0).
func (cfg *SDKConfig) AccountPolicyFor(provider, authID string, emails ...string) *AccountPolicy {
	if cfg == nil || len(cfg.AccountPolicies) == 0 {
		return &AccountPolicy{}
	}

	provider = strings.TrimSpace(provider)
	authID = strings.TrimSpace(authID)

	var (
		exactAuthMatch    *AccountPolicy
		wildcardAuthMatch *AccountPolicy
		providerMatch     *AccountPolicy
		defaultMatch      *AccountPolicy
	)

	for i := range cfg.AccountPolicies {
		policy := &cfg.AccountPolicies[i]
		policyProvider := strings.TrimSpace(policy.Provider)
		policyAuthID := strings.TrimSpace(policy.AuthID)

		// Check if policy is scoped to a specific provider
		providerCompatible := policyProvider == "" || strings.EqualFold(policyProvider, provider)

		// 1. AuthID matches
		if policyAuthID != "" && providerCompatible {
			// Exact match check
			if exactMatchAuth(policyAuthID, authID, emails) {
				if exactAuthMatch == nil {
					exactAuthMatch = policy
				}
				continue
			}
			// Wildcard match check
			if wildcardMatchAuth(policyAuthID, authID, emails) {
				if wildcardAuthMatch == nil {
					wildcardAuthMatch = policy
				}
				continue
			}
		}

		// 2. Provider match (when policyAuthID is empty)
		if policyAuthID == "" && policyProvider != "" && strings.EqualFold(policyProvider, provider) {
			if providerMatch == nil {
				providerMatch = policy
			}
			continue
		}

		// 3. Default match
		if policy.Default && policyAuthID == "" && policyProvider == "" {
			if defaultMatch == nil {
				defaultMatch = policy
			}
		}
	}

	if exactAuthMatch != nil {
		return exactAuthMatch
	}
	if wildcardAuthMatch != nil {
		return wildcardAuthMatch
	}
	if providerMatch != nil {
		return providerMatch
	}
	if defaultMatch != nil {
		return defaultMatch
	}

	return &AccountPolicy{}
}

func exactMatchAuth(pattern, authID string, emails []string) bool {
	if strings.EqualFold(pattern, authID) {
		return true
	}
	for _, email := range emails {
		trimmed := strings.TrimSpace(email)
		if trimmed != "" && strings.EqualFold(pattern, trimmed) {
			return true
		}
	}
	return false
}

func wildcardMatchAuth(pattern, authID string, emails []string) bool {
	if strings.Contains(pattern, "*") {
		if misc.MatchWildcard(strings.ToLower(pattern), strings.ToLower(authID)) {
			return true
		}
		for _, email := range emails {
			trimmed := strings.TrimSpace(email)
			if trimmed != "" && misc.MatchWildcard(strings.ToLower(pattern), strings.ToLower(trimmed)) {
				return true
			}
		}
	}
	return false
}
