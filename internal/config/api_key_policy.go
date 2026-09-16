package config

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
)

// APIKeyPolicy restricts the models, provider configuration instances, and upstream
// accounts a single client API key may use. Every restriction list is optional; an
// empty list means the dimension is unrestricted for that key.
type APIKeyPolicy struct {
	// APIKey references an existing entry in api-keys. Policies that reference an
	// unknown key never take effect and never authenticate a key by themselves.
	APIKey string `yaml:"api-key" json:"api-key"`

	// ExcludedModels lists outward-facing model IDs or wildcard patterns ("*" matches
	// any substring) that the key may not request.
	ExcludedModels []string `yaml:"excluded-models,omitempty" json:"excluded-models,omitempty"`

	// ExcludedAIProviders lists the api-key value of provider configuration instances
	// the key may not use. It matches a concrete configuration instance, not a
	// provider type.
	ExcludedAIProviders []string `yaml:"excluded-ai-providers,omitempty" json:"excluded-ai-providers,omitempty"`

	// ExcludedAIAccounts lists upstream account emails or auth file ids the key may not use.
	ExcludedAIAccounts []string `yaml:"excluded-ai-accounts,omitempty" json:"excluded-ai-accounts,omitempty"`
}

// Empty reports whether the policy carries no restriction at all.
func (p APIKeyPolicy) Empty() bool {
	return len(p.ExcludedModels) == 0 && len(p.ExcludedAIProviders) == 0 && len(p.ExcludedAIAccounts) == 0
}

// APIKeyPolicySet is the compiled, immutable request-scoped view of one client API key's
// restrictions. It is safe to share across goroutines and must never expose the client key.
type APIKeyPolicySet struct {
	excludedModels    []string
	excludedProviders map[string]struct{}
	excludedAccounts  map[string]struct{}
}

// Empty reports whether the set carries no restriction, in which case all requests pass.
func (s *APIKeyPolicySet) Empty() bool {
	if s == nil {
		return true
	}
	return len(s.excludedModels) == 0 && len(s.excludedProviders) == 0 && len(s.excludedAccounts) == 0
}

// RestrictsAuth reports whether the set excludes any credential, by provider instance or by
// upstream account. It lets callers skip credential enumeration for model-only policies.
func (s *APIKeyPolicySet) RestrictsAuth() bool {
	if s == nil {
		return false
	}
	return len(s.excludedProviders) > 0 || len(s.excludedAccounts) > 0
}

// DeniesModel reports whether the outward-facing model name is forbidden by the policy.
//
// A request matches when the configured pattern matches the requested name, its
// thinking-suffix-stripped form, or its unprefixed form. Matching the unprefixed form keeps
// request enforcement and /v1/models filtering consistent for prefixed model catalogs.
func (s *APIKeyPolicySet) DeniesModel(model string) bool {
	if s == nil || len(s.excludedModels) == 0 {
		return false
	}
	candidates := modelMatchCandidates(model)
	if len(candidates) == 0 {
		return false
	}
	for _, pattern := range s.excludedModels {
		for _, candidate := range candidates {
			if misc.MatchWildcard(pattern, candidate) {
				return true
			}
		}
	}
	return false
}

// modelMatchCandidates returns the lowercased forms of a model name that policy patterns
// are matched against, de-duplicated and ordered from most to least specific.
func modelMatchCandidates(model string) []string {
	trimmed := strings.ToLower(strings.TrimSpace(model))
	if trimmed == "" {
		return nil
	}
	candidates := make([]string, 0, 3)
	appendCandidate := func(value string) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			return
		}
		for _, existing := range candidates {
			if existing == value {
				return
			}
		}
		candidates = append(candidates, value)
	}
	appendCandidate(trimmed)
	appendCandidate(thinkingBaseModel(trimmed))
	if idx := strings.LastIndex(trimmed, "/"); idx >= 0 && idx < len(trimmed)-1 {
		appendCandidate(trimmed[idx+1:])
	}
	return candidates
}

// DeniesAuth reports whether the upstream credential is forbidden by the policy. The
// provider instance is matched through the provider configuration api-key while accounts
// are matched through either the account email or the auth record id.
func (s *APIKeyPolicySet) DeniesAuth(authID, providerAPIKey, accountEmail string) bool {
	if s == nil {
		return false
	}
	if len(s.excludedProviders) > 0 {
		if key := strings.TrimSpace(providerAPIKey); key != "" {
			if _, denied := s.excludedProviders[key]; denied {
				return true
			}
		}
	}
	if len(s.excludedAccounts) > 0 {
		if id := strings.TrimSpace(authID); id != "" {
			if _, denied := s.excludedAccounts[strings.ToLower(id)]; denied {
				return true
			}
		}
		if email := strings.TrimSpace(accountEmail); email != "" {
			if _, denied := s.excludedAccounts[strings.ToLower(email)]; denied {
				return true
			}
		}
	}
	return false
}

// thinkingBaseModel strips a trailing reasoning suffix, for example "gpt-5(high)" -> "gpt-5".
func thinkingBaseModel(model string) string {
	trimmed := strings.TrimSpace(model)
	lastOpen := strings.LastIndex(trimmed, "(")
	if lastOpen <= 0 || !strings.HasSuffix(trimmed, ")") {
		return strings.ToLower(trimmed)
	}
	return strings.ToLower(strings.TrimSpace(trimmed[:lastOpen]))
}

// APIKeyPolicySetFor compiles the policy configured for the supplied client API key.
// It returns nil when the key has no policy, so an unconfigured key stays unrestricted.
func (cfg *Config) APIKeyPolicySetFor(apiKey string) *APIKeyPolicySet {
	if cfg == nil {
		return nil
	}
	return cfg.SDKConfig.APIKeyPolicySetFor(apiKey)
}

// APIKeyPolicySetFor compiles the policy configured for the supplied client API key.
// It returns nil when the key has no policy, so an unconfigured key stays unrestricted.
func (cfg *SDKConfig) APIKeyPolicySetFor(apiKey string) *APIKeyPolicySet {
	if cfg == nil {
		return nil
	}
	key := strings.TrimSpace(apiKey)
	if key == "" || len(cfg.APIKeyPolicies) == 0 {
		return nil
	}
	for i := range cfg.APIKeyPolicies {
		entry := cfg.APIKeyPolicies[i]
		if entry.APIKey != key {
			continue
		}
		set := &APIKeyPolicySet{excludedModels: entry.ExcludedModels}
		if len(entry.ExcludedAIProviders) > 0 {
			set.excludedProviders = make(map[string]struct{}, len(entry.ExcludedAIProviders))
			for _, value := range entry.ExcludedAIProviders {
				set.excludedProviders[value] = struct{}{}
			}
		}
		if len(entry.ExcludedAIAccounts) > 0 {
			set.excludedAccounts = make(map[string]struct{}, len(entry.ExcludedAIAccounts))
			for _, value := range entry.ExcludedAIAccounts {
				set.excludedAccounts[strings.ToLower(value)] = struct{}{}
			}
		}
		if set.Empty() {
			return nil
		}
		return set
	}
	return nil
}

// NormalizeAPIKeyPolicies trims entries, drops policies that carry no restriction, and keeps
// the first definition of a duplicated api-key. Misconfigured entries are dropped here so a
// bad policy can never disable authentication for the remaining client keys.
func NormalizeAPIKeyPolicies(entries []APIKeyPolicy) []APIKeyPolicy {
	if len(entries) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(entries))
	out := make([]APIKeyPolicy, 0, len(entries))
	for i := range entries {
		entry := entries[i]
		entry.APIKey = strings.TrimSpace(entry.APIKey)
		if entry.APIKey == "" {
			continue
		}
		if _, exists := seen[entry.APIKey]; exists {
			continue
		}
		seen[entry.APIKey] = struct{}{}
		entry.ExcludedModels = NormalizeExcludedModels(entry.ExcludedModels)
		entry.ExcludedAIProviders = normalizePolicyValues(entry.ExcludedAIProviders)
		entry.ExcludedAIAccounts = normalizePolicyValues(entry.ExcludedAIAccounts)
		if entry.Empty() {
			continue
		}
		out = append(out, entry)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizePolicyValues trims, drops empty entries, and de-duplicates policy values while
// preserving the configured spelling.
func normalizePolicyValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
