package api

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/usagelimit"
)

// setAPIKeyPolicies compiles the configured per-client policies into an immutable index and
// publishes it atomically. Only policies whose api-key is present in api-keys take effect,
// so a policy can never turn an unknown value into an authenticatable client key.
func (s *Server) setAPIKeyPolicies(cfg *config.Config) {
	if s == nil || cfg == nil {
		return
	}
	index := buildAPIKeyPolicyIndex(&cfg.SDKConfig)
	s.apiKeyPolicies.Store(index)
	// Usage accounting follows the compiled policies: only keys that carry a token allowance
	// are tracked, so a configuration without usage limits keeps no counters at all.
	usagelimit.Default().SetTrackedKeys(usageLimitedFingerprints(index))
}

// usageLimitedFingerprints collects the accounting identifiers of the keys that cap tokens.
func usageLimitedFingerprints(index *map[string]*config.APIKeyPolicySet) map[string]struct{} {
	tracked := make(map[string]struct{})
	if index == nil {
		return tracked
	}
	for _, set := range *index {
		if set.LimitsUsage() {
			tracked[set.Fingerprint()] = struct{}{}
		}
	}
	return tracked
}

// buildAPIKeyPolicyIndex compiles the policy list into a lookup map. It returns a pointer to
// an empty map (never nil) so the resolver can distinguish "no policies" from "not loaded".
func buildAPIKeyPolicyIndex(cfg *config.SDKConfig) *map[string]*config.APIKeyPolicySet {
	index := make(map[string]*config.APIKeyPolicySet)
	if cfg == nil || len(cfg.APIKeyPolicies) == 0 {
		return &index
	}
	known := make(map[string]struct{}, len(cfg.APIKeys))
	for _, key := range cfg.APIKeys {
		if trimmed := trimAPIKey(key); trimmed != "" {
			known[trimmed] = struct{}{}
		}
	}
	for i := range cfg.APIKeyPolicies {
		entry := cfg.APIKeyPolicies[i]
		if _, ok := known[entry.APIKey]; !ok {
			// The policy references a key that is not configured as a client key. It
			// restricts nothing and, importantly, does not register the key.
			continue
		}
		set := cfg.APIKeyPolicySetFor(entry.APIKey)
		if set == nil {
			continue
		}
		index[entry.APIKey] = set
	}
	return &index
}

// resolveAPIKeyPolicy returns the compiled restrictions for an authenticated client key.
// A nil result means the key is unrestricted, which matches the behaviour of every key that
// has no policy configured.
func (s *Server) resolveAPIKeyPolicy(apiKey string) *config.APIKeyPolicySet {
	if s == nil {
		return nil
	}
	index := s.apiKeyPolicies.Load()
	if index == nil {
		return nil
	}
	return (*index)[trimAPIKey(apiKey)]
}

func trimAPIKey(key string) string {
	return strings.TrimSpace(key)
}
