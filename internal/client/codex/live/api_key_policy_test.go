package live

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// providerExclusionPolicy compiles the policy the HTTP layer publishes for one client key.
func providerExclusionPolicy(t *testing.T, apiKey string, providers ...string) *internalconfig.APIKeyPolicySet {
	t.Helper()

	set := (&internalconfig.Config{SDKConfig: internalconfig.SDKConfig{
		APIKeyPolicies: internalconfig.NormalizeAPIKeyPolicies([]internalconfig.APIKeyPolicy{
			{APIKey: apiKey, ExcludedAIProviders: providers},
		}),
	}}).APIKeyPolicySetFor(apiKey)
	if set == nil {
		t.Fatal("compiled policy is nil")
	}
	return set
}

// TestHandlerLiveCallRespectsAPIKeyPolicy proves the /v1/live entry point carries the
// authenticated client key's policy into auth selection: the excluded provider instance is
// never selected and the upstream request goes to the allowed credential instead.
func TestHandlerLiveCallRespectsAPIKeyPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	manager := auth.NewManager(nil, &apiKeyFirstSelector{}, nil)
	executor := &captureExecutor{responseBody: &trackedResponseBody{Reader: strings.NewReader("v=0\r\n")}}
	manager.RegisterExecutor(executor)
	registerCredential(t, manager, &auth.Auth{
		ID:         "codex-oauth-blocked",
		Provider:   "codex",
		Status:     auth.StatusActive,
		Attributes: map[string]string{"auth_kind": auth.AuthKindOAuth, "api_key": "provider-instance-blocked"},
		Metadata:   map[string]any{"access_token": "blocked-token", "account_id": "blocked"},
	})
	registerCredential(t, manager, &auth.Auth{
		ID:         "codex-oauth-allowed",
		Provider:   "codex",
		Status:     auth.StatusActive,
		Attributes: map[string]string{"auth_kind": auth.AuthKindOAuth, "api_key": "provider-instance-allowed"},
		Metadata:   map[string]any{"access_token": "allowed-token", "account_id": "allowed"},
	})

	handler := NewHandler(manager, nil)
	router := gin.New()
	// A middleware plays the role of the authentication layer: it publishes the compiled
	// policy on the Gin context read back by the live handler.
	router.Use(func(c *gin.Context) {
		c.Set(handlers.APIKeyPolicyContextKey, providerExclusionPolicy(t, "sk-a", "provider-instance-blocked"))
		c.Next()
	})
	router.POST("/v1/live", handler.Handle)

	const boundary = "codex-realtime-call-boundary"
	body := multipartBody(boundary, "v=0\r\na=setup:actpass", `{"model":"gpt-live-1-codex"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/live", strings.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	if executor.selectedAuth == nil {
		t.Fatal("Codex executor did not receive a live request")
	}
	if executor.selectedAuth.ID != "codex-oauth-allowed" {
		t.Fatalf("selected auth = %q, want codex-oauth-allowed", executor.selectedAuth.ID)
	}
}

// When every credential is excluded the live entry point must fail instead of reaching the
// upstream, so no request is recorded by the executor.
func TestHandlerLiveCallRejectsWhenAllAuthsExcluded(t *testing.T) {
	gin.SetMode(gin.TestMode)

	manager := auth.NewManager(nil, &apiKeyFirstSelector{}, nil)
	executor := &captureExecutor{responseBody: &trackedResponseBody{Reader: strings.NewReader("v=0\r\n")}}
	manager.RegisterExecutor(executor)
	registerCredential(t, manager, &auth.Auth{
		ID:         "codex-oauth-blocked",
		Provider:   "codex",
		Status:     auth.StatusActive,
		Attributes: map[string]string{"auth_kind": auth.AuthKindOAuth, "api_key": "provider-instance-blocked"},
		Metadata:   map[string]any{"access_token": "blocked-token"},
	})

	handler := NewHandler(manager, nil)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(handlers.APIKeyPolicyContextKey, providerExclusionPolicy(t, "sk-a", "provider-instance-blocked"))
		c.Next()
	})
	router.POST("/v1/live", handler.Handle)

	const boundary = "codex-realtime-call-boundary"
	body := multipartBody(boundary, "v=0\r\na=setup:actpass", `{"model":"gpt-live-1-codex"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/live", strings.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code == http.StatusCreated {
		t.Fatalf("status = %d, want a selection failure; body=%s", recorder.Code, recorder.Body.String())
	}
	if executor.selectedAuth != nil {
		t.Fatalf("executor received auth %q, want no upstream request", executor.selectedAuth.ID)
	}
	if calls := executor.httpCalls.Load(); calls != 0 {
		t.Fatalf("executor http calls = %d, want 0", calls)
	}
}

// A captured selection predicate records exactly which auth IDs auth selection was offered.
type policyCaptureSelector struct {
	mu       sync.Mutex
	offered  []string
	selected string
}

func (s *policyCaptureSelector) Pick(_ context.Context, _ string, _ string, _ coreexecutor.Options, auths []*auth.Auth) (*auth.Auth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.offered = s.offered[:0]
	for _, candidate := range auths {
		s.offered = append(s.offered, candidate.ID)
	}
	if len(auths) == 0 {
		return nil, nil
	}
	s.selected = auths[0].ID
	return auths[0], nil
}

func (s *policyCaptureSelector) offeredIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.offered...)
}

// selectOAuth must attach the authenticated client key's policy to the execution metadata it
// forwards, so every live/realtime selection path filters provider-instance and account
// exclusions exactly like the shared execution chain.
func TestSelectOAuthAttachesAPIKeyPolicyMetadata(t *testing.T) {
	gin.SetMode(gin.TestMode)

	selector := &policyCaptureSelector{}
	manager := auth.NewManager(nil, selector, nil)
	manager.RegisterExecutor(&captureExecutor{})
	registerCredential(t, manager, &auth.Auth{
		ID:         "codex-oauth-blocked",
		Provider:   "codex",
		Status:     auth.StatusActive,
		Attributes: map[string]string{"auth_kind": auth.AuthKindOAuth, "api_key": "provider-instance-blocked"},
		Metadata:   map[string]any{"access_token": "blocked-token"},
	})
	registerCredential(t, manager, &auth.Auth{
		ID:         "codex-oauth-allowed",
		Provider:   "codex",
		Status:     auth.StatusActive,
		Attributes: map[string]string{"auth_kind": auth.AuthKindOAuth, "api_key": "provider-instance-allowed"},
		Metadata:   map[string]any{"access_token": "allowed-token"},
	})

	handler := NewHandler(manager, nil)

	t.Run("no policy offers every credential", func(t *testing.T) {
		ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ctx := context.WithValue(context.Background(), "gin", ginCtx)
		if _, _, errSelect := handler.selectOAuth(ctx, "gpt-live-1-codex", coreexecutor.Options{}); errSelect != nil {
			t.Fatalf("selectOAuth() error = %v", errSelect)
		}
		offered := selector.offeredIDs()
		if len(offered) != 2 {
			t.Fatalf("offered auths = %v, want both credentials", offered)
		}
	})

	t.Run("policy removes the excluded credential", func(t *testing.T) {
		policy := providerExclusionPolicy(t, "sk-a", "provider-instance-blocked")
		ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ginCtx.Set(handlers.APIKeyPolicyContextKey, policy)
		ctx := context.WithValue(context.Background(), "gin", ginCtx)

		_, selectedAuth, errSelect := handler.selectOAuth(ctx, "gpt-live-1-codex", coreexecutor.Options{})
		if errSelect != nil {
			t.Fatalf("selectOAuth() error = %v", errSelect)
		}
		if selectedAuth == nil || selectedAuth.ID != "codex-oauth-allowed" {
			t.Fatalf("selected = %v, want codex-oauth-allowed", selectedAuth)
		}
		offered := selector.offeredIDs()
		if len(offered) != 1 || offered[0] != "codex-oauth-allowed" {
			t.Fatalf("offered auths = %v, want only codex-oauth-allowed", offered)
		}
	})
}
