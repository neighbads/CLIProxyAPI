package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	proxyconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/ratelimit"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

type blockingTestExecutor struct {
	mu      sync.Mutex
	started chan struct{}
	release chan struct{}
}

func (e *blockingTestExecutor) Identifier() string { return "codex" }

func (e *blockingTestExecutor) Execute(context.Context, *auth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{}, nil
}

func (e *blockingTestExecutor) ExecuteStream(context.Context, *auth.Auth, coreexecutor.Request, coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	return nil, nil
}

func (e *blockingTestExecutor) Refresh(_ context.Context, a *auth.Auth) (*auth.Auth, error) {
	return a, nil
}

func (e *blockingTestExecutor) CountTokens(context.Context, *auth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{}, nil
}

func (e *blockingTestExecutor) PrepareRequest(req *http.Request, a *auth.Auth) error {
	return nil
}

func (e *blockingTestExecutor) HttpRequest(ctx context.Context, a *auth.Auth, req *http.Request) (*http.Response, error) {
	select {
	case e.started <- struct{}{}:
	default:
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-e.release:
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"results":[]}`)),
		}, nil
	}
}

func TestAPIKeyRateLimitEnforcement(t *testing.T) {
	ratelimit.Default().Reset()
	defer ratelimit.Default().Reset()

	server := newTestServer(t)

	cfg := &proxyconfig.Config{
		SDKConfig: sdkconfig.SDKConfig{
			APIKeys: []string{"sk-limited", "sk-unlimited"},
			APIKeyPolicies: proxyconfig.NormalizeAPIKeyPolicies([]proxyconfig.APIKeyPolicy{
				{
					APIKey: "sk-limited",
					RateLimits: proxyconfig.APIKeyRateLimits{
						MaxInFlight:  1,
						QueueRetries: 0,
					},
				},
			}),
		},
	}
	server.UpdateClients(cfg)

	blockExec := &blockingTestExecutor{
		started: make(chan struct{}, 10),
		release: make(chan struct{}),
	}
	server.handlers.AuthManager.RegisterExecutor(blockExec)
	credential := &auth.Auth{
		ID:         "codex-auth",
		Provider:   "codex",
		Status:     auth.StatusActive,
		Attributes: map[string]string{"auth_kind": "oauth"},
		Metadata:   map[string]any{"access_token": "codex-token", "account_id": "account-123"},
	}
	if _, err := server.handlers.AuthManager.Register(context.Background(), credential); err != nil {
		t.Fatalf("failed to register auth: %v", err)
	}
	registry.GetGlobalRegistry().RegisterClient(credential.ID, "codex", []*registry.ModelInfo{{ID: "gpt-5-codex"}})
	t.Cleanup(func() {
		registry.GetGlobalRegistry().UnregisterClient(credential.ID)
	})

	// 1. Send first request with sk-limited (runs in goroutine and blocks in executor)
	var (
		rr1 = httptest.NewRecorder()
		wg  sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		req := httptest.NewRequest(http.MethodPost, "/v1/alpha/search", strings.NewReader(`{"id":"search-1","model":"gpt-5-codex","query":"test"}`))
		req.Header.Set("Authorization", "Bearer sk-limited")
		server.engine.ServeHTTP(rr1, req)
	}()

	// Wait until request 1 has entered the executor
	select {
	case <-blockExec.started:
	case <-time.After(1 * time.Second):
		close(blockExec.release)
		wg.Wait()
		t.Fatalf("timed out waiting for request 1 to start; rr1.Code = %d, body = %s", rr1.Code, rr1.Body.String())
	}

	// 2. Send concurrent request with sk-limited -> should fail immediately with 429
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/v1/alpha/search", strings.NewReader(`{"id":"search-2","model":"gpt-5-codex","query":"test"}`))
	req2.Header.Set("Authorization", "Bearer sk-limited")
	server.engine.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("request 2 status = %d, want %d; body = %s", rr2.Code, http.StatusTooManyRequests, rr2.Body.String())
	}
	if got := rr2.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("request 2 Retry-After = %q, want 1", got)
	}
	if !strings.Contains(rr2.Body.String(), "rate_limit_exceeded") {
		t.Fatalf("request 2 body = %q, want rate_limit_exceeded", rr2.Body.String())
	}

	// 3. GET /v1/models with sk-limited is exempt -> should succeed (not 429)
	rr3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req3.Header.Set("Authorization", "Bearer sk-limited")
	server.engine.ServeHTTP(rr3, req3)

	if rr3.Code != http.StatusOK {
		t.Fatalf("request 3 status = %d, want 200; body = %s", rr3.Code, rr3.Body.String())
	}

	// 4. Release request 1
	close(blockExec.release)
	wg.Wait()

	if rr1.Code != http.StatusOK {
		t.Fatalf("request 1 status = %d, want 200; body = %s", rr1.Code, rr1.Body.String())
	}

	// 5. Subsequent request with sk-limited should now succeed
	blockExec2 := &blockingTestExecutor{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	close(blockExec2.release) // instant release
	server.handlers.AuthManager.RegisterExecutor(blockExec2)

	rr5 := httptest.NewRecorder()
	req5 := httptest.NewRequest(http.MethodPost, "/v1/alpha/search", strings.NewReader(`{"id":"search-3","model":"gpt-5-codex","query":"test"}`))
	req5.Header.Set("Authorization", "Bearer sk-limited")
	server.engine.ServeHTTP(rr5, req5)

	if rr5.Code != http.StatusOK {
		t.Fatalf("request 5 status = %d, want 200; body = %s", rr5.Code, rr5.Body.String())
	}
}

func TestAPIKeyRateLimitQueueEarlyWakeup(t *testing.T) {
	ratelimit.Default().Reset()
	defer ratelimit.Default().Reset()

	server := newTestServer(t)

	cfg := &proxyconfig.Config{
		SDKConfig: sdkconfig.SDKConfig{
			APIKeys: []string{"sk-queue"},
			APIKeyPolicies: proxyconfig.NormalizeAPIKeyPolicies([]proxyconfig.APIKeyPolicy{
				{
					APIKey: "sk-queue",
					RateLimits: proxyconfig.APIKeyRateLimits{
						MaxInFlight:  1,
						QueueRetries: 2,
					},
				},
			}),
		},
	}
	server.UpdateClients(cfg)

	blockExec := &blockingTestExecutor{
		started: make(chan struct{}, 10),
		release: make(chan struct{}),
	}
	server.handlers.AuthManager.RegisterExecutor(blockExec)
	credential := &auth.Auth{
		ID:         "codex-auth-queue",
		Provider:   "codex",
		Status:     auth.StatusActive,
		Attributes: map[string]string{"auth_kind": "oauth"},
		Metadata:   map[string]any{"access_token": "codex-token", "account_id": "account-123"},
	}
	if _, err := server.handlers.AuthManager.Register(context.Background(), credential); err != nil {
		t.Fatalf("failed to register auth: %v", err)
	}
	registry.GetGlobalRegistry().RegisterClient(credential.ID, "codex", []*registry.ModelInfo{{ID: "gpt-5-codex"}})
	t.Cleanup(func() {
		registry.GetGlobalRegistry().UnregisterClient(credential.ID)
	})

	// 1. Send first request (blocks in executor)
	var (
		rr1 = httptest.NewRecorder()
		wg1 sync.WaitGroup
	)
	wg1.Add(1)
	go func() {
		defer wg1.Done()
		req := httptest.NewRequest(http.MethodPost, "/v1/alpha/search", strings.NewReader(`{"id":"q-1","model":"gpt-5-codex","query":"test"}`))
		req.Header.Set("Authorization", "Bearer sk-queue")
		server.engine.ServeHTTP(rr1, req)
	}()

	select {
	case <-blockExec.started:
	case <-time.After(1 * time.Second):
		close(blockExec.release)
		wg1.Wait()
		t.Fatalf("timed out waiting for request 1 to start; code=%d, body=%s", rr1.Code, rr1.Body.String())
	}

	// 2. Send second request in goroutine (will enter queue wait)
	var (
		rr2 = httptest.NewRecorder()
		wg2 sync.WaitGroup
	)
	wg2.Add(1)
	go func() {
		defer wg2.Done()
		req := httptest.NewRequest(http.MethodPost, "/v1/alpha/search", strings.NewReader(`{"id":"q-2","model":"gpt-5-codex","query":"test"}`))
		req.Header.Set("Authorization", "Bearer sk-queue")
		server.engine.ServeHTTP(rr2, req)
	}()

	// Deterministically wait until request 2 is registered as waiting in queue
	fp := misc.APIKeyFingerprint("sk-queue")
	for ratelimit.Default().Waiters(fp) == 0 {
		time.Sleep(1 * time.Millisecond)
	}

	// 3. Release request 1 -> should wake request 2 early
	close(blockExec.release)
	wg1.Wait()

	if rr1.Code != http.StatusOK {
		t.Fatalf("request 1 code = %d, want 200", rr1.Code)
	}

	// Wait for request 2 to complete
	wg2.Wait()

	if rr2.Code != http.StatusOK {
		t.Fatalf("request 2 code = %d, want 200; body = %s", rr2.Code, rr2.Body.String())
	}
}
