package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	proxyconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func policyConfig(apiKeys []string, policies ...proxyconfig.APIKeyPolicy) *proxyconfig.Config {
	cfg := &proxyconfig.Config{SDKConfig: sdkconfig.SDKConfig{APIKeys: apiKeys}}
	cfg.APIKeyPolicies = proxyconfig.NormalizeAPIKeyPolicies(policies)
	return cfg
}

func TestServerResolvesAPIKeyPolicyAfterReload(t *testing.T) {
	server := newTestServer(t)

	server.UpdateClients(policyConfig(
		[]string{"test-key", "sk-b"},
		proxyconfig.APIKeyPolicy{APIKey: "sk-b", ExcludedModels: []string{"gemini-2.5-*"}},
	))

	resolved := server.resolveAPIKeyPolicy("sk-b")
	if resolved == nil {
		t.Fatal("sk-b policy was not published")
	}
	if !resolved.DeniesModel("gemini-2.5-pro") {
		t.Fatal("sk-b policy lost its model exclusion")
	}
	if set := server.resolveAPIKeyPolicy("test-key"); set != nil {
		t.Fatalf("test-key resolved to %#v, want nil", set)
	}
	if set := server.resolveAPIKeyPolicy("sk-unknown"); set != nil {
		t.Fatalf("unknown key resolved to %#v, want nil", set)
	}

	// A reload that drops the policy must clear it.
	server.UpdateClients(policyConfig([]string{"test-key", "sk-b"}))
	if set := server.resolveAPIKeyPolicy("sk-b"); set != nil {
		t.Fatalf("policy survived a reload that removed it: %#v", set)
	}
}

// A policy that references a key absent from api-keys is skipped, so it can never turn that
// value into an authenticatable key.
func TestServerSkipsPolicyForUnknownAPIKey(t *testing.T) {
	server := newTestServer(t)

	server.UpdateClients(policyConfig(
		[]string{"test-key"},
		proxyconfig.APIKeyPolicy{APIKey: "sk-not-configured", ExcludedModels: []string{"*"}},
	))

	if set := server.resolveAPIKeyPolicy("sk-not-configured"); set != nil {
		t.Fatalf("policy for an unconfigured key resolved to %#v, want nil", set)
	}
	if set := server.resolveAPIKeyPolicy("test-key"); set != nil {
		t.Fatalf("unrelated key resolved to %#v, want nil", set)
	}
}

func TestBuildAPIKeyPolicyIndexDeduplicatesAndSkipsEmpty(t *testing.T) {
	cfg := &sdkconfig.SDKConfig{APIKeys: []string{"sk-a"}}
	cfg.APIKeyPolicies = proxyconfig.NormalizeAPIKeyPolicies([]proxyconfig.APIKeyPolicy{
		{APIKey: "sk-a", ExcludedModels: []string{"gpt-4"}},
		{APIKey: "sk-a", ExcludedModels: []string{"gpt-5"}},
		{APIKey: "sk-a"},
	})

	index := buildAPIKeyPolicyIndex(cfg)
	if index == nil {
		t.Fatal("index is nil")
	}
	if len(*index) != 1 {
		t.Fatalf("index = %#v, want one entry", *index)
	}
	set := (*index)["sk-a"]
	if set == nil || !set.DeniesModel("gpt-4") {
		t.Fatalf("indexed policy = %#v", set)
	}
}

// End-to-end: the authenticated client key's policy must reach the handler through the real
// HTTP path and hide a model that no allowed credential can serve.
func TestModelsEndpointHidesModelsUnusableForAPIKey(t *testing.T) {
	server := newTestServer(t)

	registry.GetGlobalRegistry().RegisterClient("e2e-allowed", "codex", []*registry.ModelInfo{
		{ID: "e2e-allowed-model"},
		{ID: "e2e-shared-model"},
	})
	registry.GetGlobalRegistry().RegisterClient("e2e-blocked", "codex", []*registry.ModelInfo{
		{ID: "e2e-blocked-model"},
		{ID: "e2e-shared-model"},
		{ID: "e2e-direct-model"},
	})
	t.Cleanup(func() {
		registry.GetGlobalRegistry().UnregisterClient("e2e-allowed")
		registry.GetGlobalRegistry().UnregisterClient("e2e-blocked")
	})

	server.handlers.AuthManager.Register(context.Background(), &coreauth.Auth{
		ID:         "e2e-allowed",
		Provider:   "codex",
		Status:     coreauth.StatusActive,
		Attributes: map[string]string{"api_key": "e2e-provider-allowed"},
	})
	server.handlers.AuthManager.Register(context.Background(), &coreauth.Auth{
		ID:         "e2e-blocked",
		Provider:   "codex",
		Status:     coreauth.StatusActive,
		Attributes: map[string]string{"api_key": "e2e-provider-blocked"},
	})

	server.UpdateClients(policyConfig(
		[]string{"test-key"},
		proxyconfig.APIKeyPolicy{
			APIKey:         "test-key",
			ExcludedModels: []string{"e2e-*direct"},
			ExcludedAIProviders: []string{
				"e2e-provider-blocked",
			},
		},
	))
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	server.engine.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "e2e-allowed-model") {
		t.Fatalf("allowed model missing from catalog: %s", body)
	}
	if !strings.Contains(body, "e2e-shared-model") {
		t.Fatalf("shared model missing from catalog: %s", body)
	}
	if strings.Contains(body, "e2e-direct-model") {
		t.Fatalf("directly excluded model was exposed: %s", body)
	}
	if strings.Contains(body, "e2e-blocked-model") {
		t.Fatalf("model served only by a policy-excluded provider was exposed: %s", body)
	}
}
