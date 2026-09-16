package configaccess

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

// authenticate drives the registered config-access provider through the global registry so
// the test exercises the same lookup the server performs.
func authenticate(t *testing.T, key string) (*sdkaccess.Result, *sdkaccess.AuthError) {
	t.Helper()

	var configProvider sdkaccess.Provider
	for _, provider := range sdkaccess.RegisteredProviders() {
		if provider.Identifier() == sdkaccess.DefaultAccessProviderName {
			configProvider = provider
			break
		}
	}
	if configProvider == nil {
		t.Fatal("config access provider is not registered")
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	return configProvider.Authenticate(context.Background(), req)
}

// A policy that references a client key absent from api-keys must not register that key as
// authenticatable, and must not disturb the keys that are configured.
func TestRegisterIgnoresAPIKeyPolicies(t *testing.T) {
	t.Cleanup(func() { sdkaccess.UnregisterProvider(sdkaccess.AccessProviderTypeConfigAPIKey) })

	Register(&sdkconfig.SDKConfig{
		APIKeys: []string{"sk-client-a"},
		APIKeyPolicies: []sdkconfig.APIKeyPolicy{
			{APIKey: "sk-not-in-api-keys", ExcludedModels: []string{"*"}},
		},
	})

	if _, authErr := authenticate(t, "sk-client-a"); authErr != nil {
		t.Fatalf("configured key was rejected: %v", authErr)
	}
	if _, authErr := authenticate(t, "sk-not-in-api-keys"); authErr == nil {
		t.Fatal("a policy-only key must not become an authenticatable client key")
	}
}

// An empty api-keys list still unregisters the provider, regardless of policies.
func TestRegisterEmptyAPIKeysWithPoliciesUnregistersProvider(t *testing.T) {
	t.Cleanup(func() { sdkaccess.UnregisterProvider(sdkaccess.AccessProviderTypeConfigAPIKey) })

	Register(&sdkconfig.SDKConfig{APIKeys: []string{"sk-client-a"}})
	if _, authErr := authenticate(t, "sk-client-a"); authErr != nil {
		t.Fatalf("baseline key was rejected: %v", authErr)
	}

	Register(&sdkconfig.SDKConfig{
		APIKeys: nil,
		APIKeyPolicies: []sdkconfig.APIKeyPolicy{
			{APIKey: "sk-client-a", ExcludedModels: []string{"*"}},
		},
	})

	for _, provider := range sdkaccess.RegisteredProviders() {
		if provider.Identifier() == sdkaccess.DefaultAccessProviderName {
			t.Fatal("config access provider remained registered with an empty api-keys list")
		}
	}
}
