package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func newAPIKeyPolicyHandler(t *testing.T, apiKeys []string) *Handler {
	t.Helper()

	return &Handler{
		cfg:            &config.Config{SDKConfig: config.SDKConfig{APIKeys: apiKeys}},
		configFilePath: writeTestConfigFile(t),
	}
}

func TestGetAPIKeyPolicies(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := newAPIKeyPolicyHandler(t, []string{"sk-a", "sk-b"})
	h.cfg.APIKeyPolicies = config.NormalizeAPIKeyPolicies([]config.APIKeyPolicy{
		{APIKey: "sk-b", ExcludedModels: []string{"gemini-2.5-*"}},
	})

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/api-key-policies", nil)

	h.GetAPIKeyPolicies(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		Policies []config.APIKeyPolicy `json:"api-key-policies"`
	}
	if errUnmarshal := json.Unmarshal(rec.Body.Bytes(), &body); errUnmarshal != nil {
		t.Fatalf("unmarshal response: %v; body=%s", errUnmarshal, rec.Body.String())
	}
	if len(body.Policies) != 1 || body.Policies[0].APIKey != "sk-b" {
		t.Fatalf("api-key-policies = %#v", body.Policies)
	}
	if len(body.Policies[0].ExcludedModels) != 1 || body.Policies[0].ExcludedModels[0] != "gemini-2.5-*" {
		t.Fatalf("excluded-models = %#v", body.Policies[0].ExcludedModels)
	}
}

func TestPutAPIKeyPolicies(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := newAPIKeyPolicyHandler(t, []string{"sk-a", "sk-b"})
	payload := `[{"api-key":"sk-b","excluded-models":["pro_0_2/gpt-5.5"],"excluded-ai-providers":["provider-1"],"excluded-ai-accounts":["user@example.com"]}]`

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPut, "/v0/management/api-key-policies", strings.NewReader(payload))
	c.Request.Header.Set("Content-Type", "application/json")

	h.PutAPIKeyPolicies(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if len(h.cfg.APIKeyPolicies) != 1 {
		t.Fatalf("policies = %#v", h.cfg.APIKeyPolicies)
	}
	entry := h.cfg.APIKeyPolicies[0]
	if entry.APIKey != "sk-b" || len(entry.ExcludedModels) != 1 || len(entry.ExcludedAIProviders) != 1 || len(entry.ExcludedAIAccounts) != 1 {
		t.Fatalf("stored policy = %#v", entry)
	}
	// The section must survive a round trip through the config file.
	loaded, errLoad := config.LoadConfigOptional(h.configFilePath, false)
	if errLoad != nil {
		t.Fatalf("reload config: %v", errLoad)
	}
	if len(loaded.APIKeyPolicies) != 1 || loaded.APIKeyPolicies[0].APIKey != "sk-b" {
		t.Fatalf("persisted policies = %#v", loaded.APIKeyPolicies)
	}
}

func TestPatchAPIKeyPoliciesUpserts(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := newAPIKeyPolicyHandler(t, []string{"sk-a", "sk-b"})
	h.cfg.APIKeyPolicies = config.NormalizeAPIKeyPolicies([]config.APIKeyPolicy{
		{APIKey: "sk-a", ExcludedModels: []string{"gpt-4"}},
	})

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPatch, "/v0/management/api-key-policies",
		strings.NewReader(`{"api-key":"sk-b","excluded-ai-accounts":["user@example.com"]}`))
	c.Request.Header.Set("Content-Type", "application/json")

	h.PatchAPIKeyPolicies(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if len(h.cfg.APIKeyPolicies) != 2 {
		t.Fatalf("policies = %#v", h.cfg.APIKeyPolicies)
	}
	byKey := make(map[string]config.APIKeyPolicy, len(h.cfg.APIKeyPolicies))
	for _, entry := range h.cfg.APIKeyPolicies {
		byKey[entry.APIKey] = entry
	}
	if got := byKey["sk-a"]; len(got.ExcludedModels) != 1 || got.ExcludedModels[0] != "gpt-4" {
		t.Fatalf("sk-a policy changed unexpectedly: %#v", got)
	}
	if got := byKey["sk-b"]; len(got.ExcludedAIAccounts) != 1 || got.ExcludedAIAccounts[0] != "user@example.com" {
		t.Fatalf("sk-b policy = %#v", got)
	}
	// Patching an existing key updates in place instead of appending a duplicate.
	rec2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(rec2)
	c2.Request = httptest.NewRequest(http.MethodPatch, "/v0/management/api-key-policies",
		strings.NewReader(`{"api-key":"sk-a","excluded-models":["gpt-5"]}`))
	c2.Request.Header.Set("Content-Type", "application/json")
	h.PatchAPIKeyPolicies(c2)

	if len(h.cfg.APIKeyPolicies) != 2 {
		t.Fatalf("policies after update = %#v", h.cfg.APIKeyPolicies)
	}
	for _, entry := range h.cfg.APIKeyPolicies {
		if entry.APIKey == "sk-a" && (len(entry.ExcludedModels) != 1 || entry.ExcludedModels[0] != "gpt-5") {
			t.Fatalf("sk-a policy = %#v", entry)
		}
	}
}

// An explicitly supplied index that addresses no entry must fail instead of silently
// falling through to an upsert that appends a duplicate.
func TestPatchAPIKeyPoliciesRejectsOutOfRangeIndex(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, tc := range []struct {
		name    string
		payload string
	}{
		{name: "above_len", payload: `{"index":9,"api-key":"sk-b","excluded-models":["gpt-5"]}`},
		{name: "negative", payload: `{"index":-1,"api-key":"sk-b","excluded-models":["gpt-5"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newAPIKeyPolicyHandler(t, []string{"sk-a", "sk-b"})
			h.cfg.APIKeyPolicies = config.NormalizeAPIKeyPolicies([]config.APIKeyPolicy{
				{APIKey: "sk-a", ExcludedModels: []string{"gpt-4"}},
			})

			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodPatch, "/v0/management/api-key-policies", strings.NewReader(tc.payload))
			c.Request.Header.Set("Content-Type", "application/json")

			h.PatchAPIKeyPolicies(c)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
			if len(h.cfg.APIKeyPolicies) != 1 {
				t.Fatalf("policies = %#v, want the original single entry", h.cfg.APIKeyPolicies)
			}
			if h.cfg.APIKeyPolicies[0].APIKey != "sk-a" {
				t.Fatalf("policies[0].api-key = %q, want sk-a", h.cfg.APIKeyPolicies[0].APIKey)
			}
		})
	}
}

// A valid index still updates the addressed entry in place.
func TestPatchAPIKeyPoliciesAcceptsValidIndex(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := newAPIKeyPolicyHandler(t, []string{"sk-a", "sk-b"})
	h.cfg.APIKeyPolicies = config.NormalizeAPIKeyPolicies([]config.APIKeyPolicy{
		{APIKey: "sk-a", ExcludedModels: []string{"gpt-4"}},
		{APIKey: "sk-b", ExcludedModels: []string{"gpt-4"}},
	})

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPatch, "/v0/management/api-key-policies",
		strings.NewReader(`{"index":1,"excluded-models":["gpt-5"]}`))
	c.Request.Header.Set("Content-Type", "application/json")

	h.PatchAPIKeyPolicies(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if len(h.cfg.APIKeyPolicies) != 2 {
		t.Fatalf("policies = %#v", h.cfg.APIKeyPolicies)
	}
	if got := h.cfg.APIKeyPolicies[1]; got.APIKey != "sk-b" || len(got.ExcludedModels) != 1 || got.ExcludedModels[0] != "gpt-5" {
		t.Fatalf("policies[1] = %#v", got)
	}
}

func TestDeleteAPIKeyPolicies(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := newAPIKeyPolicyHandler(t, []string{"sk-a", "sk-b"})
	h.cfg.APIKeyPolicies = config.NormalizeAPIKeyPolicies([]config.APIKeyPolicy{
		{APIKey: "sk-a", ExcludedModels: []string{"gpt-4"}},
		{APIKey: "sk-b", ExcludedModels: []string{"gpt-5"}},
	})

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodDelete, "/v0/management/api-key-policies?api-key=sk-a", nil)
	h.DeleteAPIKeyPolicies(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if len(h.cfg.APIKeyPolicies) != 1 || h.cfg.APIKeyPolicies[0].APIKey != "sk-b" {
		t.Fatalf("policies = %#v", h.cfg.APIKeyPolicies)
	}

	// A key without a policy reports 404 instead of silently succeeding.
	rec404 := httptest.NewRecorder()
	c404, _ := gin.CreateTestContext(rec404)
	c404.Request = httptest.NewRequest(http.MethodDelete, "/v0/management/api-key-policies?api-key=sk-missing", nil)
	h.DeleteAPIKeyPolicies(c404)
	if rec404.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec404.Code, http.StatusNotFound)
	}
	if len(h.cfg.APIKeyPolicies) != 1 {
		t.Fatalf("policies = %#v", h.cfg.APIKeyPolicies)
	}
}

// Existing /api-keys behaviour must stay untouched by the new endpoints.
func TestAPIKeysEndpointsUnchanged(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := newAPIKeyPolicyHandler(t, []string{"sk-a"})

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/api-keys", nil)
	h.GetAPIKeys(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body struct {
		APIKeys []string `json:"api-keys"`
	}
	if errUnmarshal := json.Unmarshal(rec.Body.Bytes(), &body); errUnmarshal != nil {
		t.Fatalf("unmarshal: %v", errUnmarshal)
	}
	if len(body.APIKeys) != 1 || body.APIKeys[0] != "sk-a" {
		t.Fatalf("api-keys = %#v, want a plain string array", body.APIKeys)
	}
}
