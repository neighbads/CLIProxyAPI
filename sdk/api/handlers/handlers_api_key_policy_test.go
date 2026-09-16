package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"golang.org/x/net/context"
)

func compilePolicy(t *testing.T, apiKey string, entry internalconfig.APIKeyPolicy) *config.APIKeyPolicySet {
	t.Helper()

	entry.APIKey = apiKey
	set := (&internalconfig.Config{SDKConfig: internalconfig.SDKConfig{
		APIKeyPolicies: internalconfig.NormalizeAPIKeyPolicies([]internalconfig.APIKeyPolicy{entry}),
	}}).APIKeyPolicySetFor(apiKey)
	if set == nil {
		t.Fatal("compiled policy is nil")
	}
	return set
}

func policyContext(set *config.APIKeyPolicySet) context.Context {
	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ginCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	if set != nil {
		ginCtx.Set(APIKeyPolicyContextKey, set)
	}
	return context.WithValue(context.Background(), "gin", ginCtx)
}

func TestEnforceAPIKeyModelPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := &BaseAPIHandler{Cfg: &config.SDKConfig{}}
	policy := compilePolicy(t, "sk-a", internalconfig.APIKeyPolicy{ExcludedModels: []string{"gemini-2.5-*"}})

	ctx := policyContext(policy)
	if errMsg := handler.EnforceAPIKeyModelPolicy(ctx, "gemini-2.5-pro"); errMsg == nil {
		t.Fatal("excluded model was allowed")
	} else if errMsg.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", errMsg.StatusCode, http.StatusForbidden)
	}
	if errMsg := handler.EnforceAPIKeyModelPolicy(ctx, "gpt-5"); errMsg != nil {
		t.Fatalf("allowed model was rejected: %v", errMsg.Error)
	}

	// A key with no policy passes everything.
	unrestricted := policyContext(nil)
	if errMsg := handler.EnforceAPIKeyModelPolicy(unrestricted, "gemini-2.5-pro"); errMsg != nil {
		t.Fatalf("unrestricted key was rejected: %v", errMsg.Error)
	}
}

// The compiled policy must reach execution metadata without exposing the raw client key, and
// must not be settable from client-supplied fields.
func TestRequestExecutionMetadataCarriesCompiledPolicyNotRawKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	policy := compilePolicy(t, "sk-a", internalconfig.APIKeyPolicy{ExcludedModels: []string{"gpt-5"}})
	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ginCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	ginCtx.Set(APIKeyPolicyContextKey, policy)
	// A client-shaped field of the same name must have no effect.
	ginCtx.Set("api_key_policy", "client-supplied")
	ctx := context.WithValue(context.Background(), "gin", ginCtx)

	meta := requestExecutionMetadata(ctx)
	got, ok := meta[coreexecutor.APIKeyPolicyMetadataKey].(*config.APIKeyPolicySet)
	if !ok || got != policy {
		t.Fatalf("metadata policy = %#v, want the compiled set", meta[coreexecutor.APIKeyPolicyMetadataKey])
	}
	if !got.DeniesModel("gpt-5") {
		t.Fatal("metadata policy lost its restrictions")
	}
	for key, value := range meta {
		if text, isString := value.(string); isString && text == "sk-a" {
			t.Fatalf("metadata key %q leaked the raw client key", key)
		}
	}
}

// /v1/models must hide a model that no allowed credential can serve.
func TestFilterModelsForAPIKeyPolicyHidesUnusableModels(t *testing.T) {
	gin.SetMode(gin.TestMode)

	manager := newPolicyTestAuthManager(t)
	handler := &BaseAPIHandler{Cfg: &config.SDKConfig{}, AuthManager: manager}

	policy := compilePolicy(t, "sk-a", internalconfig.APIKeyPolicy{
		ExcludedModels:      []string{"blocked-direct"},
		ExcludedAIProviders: []string{"provider-key-blocked"},
	})

	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ginCtx.Set(APIKeyPolicyContextKey, policy)

	models := []map[string]any{
		{"id": "allowed-model"},
		{"id": "blocked-direct"},
		{"id": "blocked-by-provider"},
		{"id": "shared-model"},
	}
	filtered := handler.FilterModelsForAPIKeyPolicy(ginCtx, models)
	got := make(map[string]bool, len(filtered))
	for _, model := range filtered {
		got[model["id"].(string)] = true
	}
	if !got["allowed-model"] {
		t.Fatal("allowed-model was hidden")
	}
	if !got["shared-model"] {
		t.Fatal("shared-model was hidden even though an allowed credential serves it")
	}
	if got["blocked-direct"] {
		t.Fatal("blocked-direct was exposed")
	}
	if got["blocked-by-provider"] {
		t.Fatal("blocked-by-provider was exposed")
	}
}

// A key without a policy keeps the full catalog.
func TestFilterModelsForAPIKeyPolicyNoPolicyKeepsCatalog(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := &BaseAPIHandler{Cfg: &config.SDKConfig{}, AuthManager: newPolicyTestAuthManager(t)}
	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())

	models := []map[string]any{{"id": "allowed-model"}, {"id": "blocked-direct"}}
	if got := handler.FilterModelsForAPIKeyPolicy(ginCtx, models); len(got) != len(models) {
		t.Fatalf("filtered %d models, want %d", len(got), len(models))
	}
}

// Gemini entries carry the identifier in "name" with a "models/" prefix.
func TestFilterModelsForAPIKeyPolicyGeminiShape(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := &BaseAPIHandler{Cfg: &config.SDKConfig{}}
	policy := compilePolicy(t, "sk-a", internalconfig.APIKeyPolicy{ExcludedModels: []string{"gemini-2.5-*"}})
	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ginCtx.Set(APIKeyPolicyContextKey, policy)

	models := []map[string]any{
		{"name": "models/gemini-2.5-pro"},
		{"name": "models/gemini-2.0-pro"},
	}
	filtered := handler.FilterModelsForAPIKeyPolicy(ginCtx, models)
	if len(filtered) != 1 || filtered[0]["name"] != "models/gemini-2.0-pro" {
		t.Fatalf("filtered models = %#v", filtered)
	}
}

// policyTestAuths registers two credentials that share one model and differ on the rest.
var policyTestAuths = []struct {
	ID          string
	ProviderKey string
	Models      []string
}{
	{ID: "policy-auth-allowed", ProviderKey: "provider-key-allowed", Models: []string{"allowed-model", "shared-model"}},
	{ID: "policy-auth-blocked", ProviderKey: "provider-key-blocked", Models: []string{"blocked-by-provider", "shared-model"}},
}

func newPolicyTestAuthManager(t *testing.T) *coreauth.Manager {
	t.Helper()

	manager := coreauth.NewManager(nil, nil, nil)
	for _, spec := range policyTestAuths {
		auth := &coreauth.Auth{
			ID:         spec.ID,
			Provider:   "codex",
			Status:     coreauth.StatusActive,
			Attributes: map[string]string{"api_key": spec.ProviderKey},
		}
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatalf("register %s: %v", spec.ID, errRegister)
		}
		modelInfos := make([]*registry.ModelInfo, 0, len(spec.Models))
		for _, model := range spec.Models {
			modelInfos = append(modelInfos, &registry.ModelInfo{ID: model})
		}
		registry.GetGlobalRegistry().RegisterClient(spec.ID, "codex", modelInfos)
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(spec.ID) })
	}
	return manager
}
