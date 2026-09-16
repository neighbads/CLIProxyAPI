package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	proxyconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/home"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

// singleKeyPolicy compiles the policy the authentication middleware publishes for one key.
func singleKeyPolicy(t *testing.T, apiKey string, entry proxyconfig.APIKeyPolicy) *proxyconfig.APIKeyPolicySet {
	t.Helper()

	entry.APIKey = apiKey
	set := (&proxyconfig.Config{SDKConfig: sdkconfig.SDKConfig{
		APIKeyPolicies: proxyconfig.NormalizeAPIKeyPolicies([]proxyconfig.APIKeyPolicy{entry}),
	}}).APIKeyPolicySetFor(apiKey)
	if set == nil {
		t.Fatal("compiled policy is nil")
	}
	return set
}

// fakeHomeRedis is a minimal RESP2 server that answers the Home model catalog. HELLO is
// rejected so go-redis falls back to RESP2, which keeps the fake free of RESP3 push frames.
type fakeHomeRedis struct {
	listener  net.Listener
	payload   string
	gets      atomic.Int32
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	closeOnce sync.Once
}

func startFakeHomeRedis(t *testing.T, payload string) *fakeHomeRedis {
	t.Helper()

	listener, errListen := net.Listen("tcp", "127.0.0.1:0")
	if errListen != nil {
		t.Fatalf("listen: %v", errListen)
	}
	fake := &fakeHomeRedis{listener: listener, payload: payload, conns: make(map[net.Conn]struct{})}
	go func() {
		for {
			conn, errAccept := listener.Accept()
			if errAccept != nil {
				return
			}
			fake.track(conn)
			go fake.serve(conn)
		}
	}()
	t.Cleanup(fake.close)
	return fake
}

func (f *fakeHomeRedis) track(conn net.Conn) {
	f.mu.Lock()
	f.conns[conn] = struct{}{}
	f.mu.Unlock()
}

func (f *fakeHomeRedis) close() {
	f.closeOnce.Do(func() {
		_ = f.listener.Close()
		f.mu.Lock()
		for conn := range f.conns {
			_ = conn.Close()
		}
		f.conns = nil
		f.mu.Unlock()
	})
}

func (f *fakeHomeRedis) addr() (string, int) {
	host, portText, errSplit := net.SplitHostPort(f.listener.Addr().String())
	if errSplit != nil {
		panic(errSplit)
	}
	port, errPort := strconv.Atoi(portText)
	if errPort != nil {
		panic(errPort)
	}
	return host, port
}

func (f *fakeHomeRedis) serve(conn net.Conn) {
	defer func() {
		_ = conn.Close()
		f.mu.Lock()
		delete(f.conns, conn)
		f.mu.Unlock()
	}()

	reader := bufio.NewReader(conn)
	for {
		args, errRead := readFakeHomeCommand(reader)
		if errRead != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		switch strings.ToUpper(args[0]) {
		case "HELLO":
			// A Redis error keeps go-redis on RESP2 without failing the connection.
			if _, errWrite := io.WriteString(conn, "-ERR unknown command 'hello'\r\n"); errWrite != nil {
				return
			}
		case "GET":
			f.gets.Add(1)
			if _, errWrite := fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(f.payload), f.payload); errWrite != nil {
				return
			}
		default:
			if _, errWrite := io.WriteString(conn, "+OK\r\n"); errWrite != nil {
				return
			}
		}
	}
}

func readFakeHomeCommand(reader *bufio.Reader) ([]string, error) {
	line, errRead := reader.ReadString('\n')
	if errRead != nil {
		return nil, errRead
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("expected array header, got %q", line)
	}
	count, errCount := strconv.Atoi(line[1:])
	if errCount != nil {
		return nil, errCount
	}
	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		header, errBulk := reader.ReadString('\n')
		if errBulk != nil {
			return nil, errBulk
		}
		header = strings.TrimRight(header, "\r\n")
		if !strings.HasPrefix(header, "$") {
			return nil, fmt.Errorf("expected bulk header, got %q", header)
		}
		length, errLength := strconv.Atoi(header[1:])
		if errLength != nil {
			return nil, errLength
		}
		buf := make([]byte, length)
		if _, errFull := io.ReadFull(reader, buf); errFull != nil {
			return nil, errFull
		}
		if _, errDiscard := reader.Discard(2); errDiscard != nil {
			return nil, errDiscard
		}
		args = append(args, string(buf))
	}
	return args, nil
}

// homeCatalogServer enables Home on a test server and points the active Home client at a fake
// Home endpoint serving the supplied catalog, so the Home model handlers run for real.
func homeCatalogServer(t *testing.T, payload string) *Server {
	t.Helper()

	fake := startFakeHomeRedis(t, payload)
	server := newTestServer(t)
	server.cfg.Home.Enabled = true

	host, port := fake.addr()
	previous := home.Current()
	client := home.New(proxyconfig.HomeConfig{
		Enabled:                 true,
		Host:                    host,
		Port:                    port,
		DisableClusterDiscovery: true,
	})
	home.SetCurrent(client)
	t.Cleanup(func() {
		client.Close()
		home.SetCurrent(previous)
	})
	return server
}

func modelsListIDs(t *testing.T, body []byte) map[string]struct{} {
	t.Helper()

	var response struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Models []struct {
			Name string `json:"name"`
			Slug string `json:"slug"`
		} `json:"models"`
	}
	if errUnmarshal := json.Unmarshal(body, &response); errUnmarshal != nil {
		t.Fatalf("decode model list: %v; body=%s", errUnmarshal, body)
	}
	ids := make(map[string]struct{})
	for _, model := range response.Data {
		ids[model.ID] = struct{}{}
	}
	for _, model := range response.Models {
		if model.Slug != "" {
			ids[model.Slug] = struct{}{}
		}
		if model.Name != "" {
			ids[strings.TrimPrefix(model.Name, "models/")] = struct{}{}
		}
	}
	return ids
}

const homePolicyCatalog = `{
	"openai": [
		{"id": "home-openai-visible", "owned_by": "openai"},
		{"id": "home-openai-hidden", "owned_by": "openai"}
	],
	"claude": [
		{"id": "home-claude-visible", "owned_by": "anthropic"},
		{"id": "home-claude-hidden", "owned_by": "anthropic"}
	],
	"codex": [
		{"id": "home-codex-visible"},
		{"id": "home-codex-hidden"}
	],
	"gemini": [
		{"name": "models/home-gemini-visible", "id": "home-gemini-visible"},
		{"name": "models/home-gemini-hidden", "id": "home-gemini-hidden"}
	]
}`

func assertModelHidden(t *testing.T, ids map[string]struct{}, visible, hidden string) {
	t.Helper()

	if _, ok := ids[visible]; !ok {
		t.Fatalf("allowed model %q missing from %v", visible, ids)
	}
	if _, ok := ids[hidden]; ok {
		t.Fatalf("policy-excluded model %q was exposed in %v", hidden, ids)
	}
}

// The Home OpenAI catalog must apply the same per-client policy filtering as the SDK
// model-list endpoint, instead of ignoring the policy entirely.
func TestHomeModelsFilterByAPIKeyPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	server := homeCatalogServer(t, homePolicyCatalog)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	c.Set(apiKeyPolicyContextKey, singleKeyPolicy(t, "sk-a", proxyconfig.APIKeyPolicy{
		ExcludedModels: []string{"home-openai-hidden"},
	}))

	server.handleHomeModels(c)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	assertModelHidden(t, modelsListIDs(t, recorder.Body.Bytes()), "home-openai-visible", "home-openai-hidden")
}

// The Home Claude catalog (Anthropic-version requests) must filter too.
func TestHomeClaudeModelsFilterByAPIKeyPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	server := homeCatalogServer(t, homePolicyCatalog)
	server.cfg.ClaudeCode.DisableCloakingModelList = true
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	c.Request.Header.Set("Anthropic-Version", "2023-06-01")
	c.Set(apiKeyPolicyContextKey, singleKeyPolicy(t, "sk-a", proxyconfig.APIKeyPolicy{
		ExcludedModels: []string{"home-claude-hidden"},
	}))

	server.handleHomeModels(c)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	assertModelHidden(t, modelsListIDs(t, recorder.Body.Bytes()), "home-claude-visible", "home-claude-hidden")
}

// The Home Codex client catalog must filter too.
func TestHomeCodexClientModelsFilterByAPIKeyPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	server := homeCatalogServer(t, homePolicyCatalog)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/models?client_version=cpa", nil)
	c.Set(apiKeyPolicyContextKey, singleKeyPolicy(t, "sk-a", proxyconfig.APIKeyPolicy{
		ExcludedModels: []string{"home-codex-hidden"},
	}))

	server.handleHomeCodexClientModels(c, "cpa")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	assertModelHidden(t, modelsListIDs(t, recorder.Body.Bytes()), "home-codex-visible", "home-codex-hidden")
}

// The Home Gemini catalog must filter too.
func TestHomeGeminiModelsFilterByAPIKeyPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	server := homeCatalogServer(t, homePolicyCatalog)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1beta/models", nil)
	c.Set(apiKeyPolicyContextKey, singleKeyPolicy(t, "sk-a", proxyconfig.APIKeyPolicy{
		ExcludedModels: []string{"home-gemini-hidden"},
	}))

	server.handleHomeGeminiModels(c)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	assertModelHidden(t, modelsListIDs(t, recorder.Body.Bytes()), "home-gemini-visible", "home-gemini-hidden")
}

// A model hidden from the Home Gemini list must answer the same not-found shape as an unknown
// model, so it cannot be probed through the single-model endpoint.
func TestHomeGeminiSingleModelHidesPolicyExcludedModel(t *testing.T) {
	gin.SetMode(gin.TestMode)

	server := homeCatalogServer(t, homePolicyCatalog)
	policy := singleKeyPolicy(t, "sk-a", proxyconfig.APIKeyPolicy{
		ExcludedModels: []string{"home-gemini-hidden"},
	})

	t.Run("excluded model answers not found", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodGet, "/v1beta/models/home-gemini-hidden", nil)
		c.Params = gin.Params{{Key: "action", Value: "/home-gemini-hidden"}}
		c.Set(apiKeyPolicyContextKey, policy)

		server.handleHomeGeminiModel(c)

		if recorder.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusNotFound, recorder.Body.String())
		}
	})

	t.Run("allowed model still served", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodGet, "/v1beta/models/home-gemini-visible", nil)
		c.Params = gin.Params{{Key: "action", Value: "/home-gemini-visible"}}
		c.Set(apiKeyPolicyContextKey, policy)

		server.handleHomeGeminiModel(c)

		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
		}
		if !strings.Contains(recorder.Body.String(), "home-gemini-visible") {
			t.Fatalf("allowed model missing: %s", recorder.Body.String())
		}
	})
}

// The Home-backed Grok Shell catalog must filter too.
func TestGrokHomeModelsFilterByAPIKeyPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	server := homeCatalogServer(t, homePolicyCatalog)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	c.Request.Header.Set("User-Agent", "grok-shell/0.2.119")
	c.Set(apiKeyPolicyContextKey, singleKeyPolicy(t, "sk-a", proxyconfig.APIKeyPolicy{
		ExcludedModels: []string{"home-openai-hidden"},
	}))

	server.handleGrokModels(c)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	assertModelHidden(t, modelsListIDs(t, recorder.Body.Bytes()), "home-openai-visible", "home-openai-hidden")
}

// The non-Home Grok Shell branch reads the local registry directly and must filter too.
func TestGrokRegistryModelsFilterByAPIKeyPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	modelRegistry := registry.GetGlobalRegistry()
	clientID := "grok-policy-registry-branch"
	modelRegistry.RegisterClient(clientID, "openai", []*registry.ModelInfo{
		{ID: "grok-registry-visible"},
		{ID: "grok-registry-hidden"},
	})
	t.Cleanup(func() { modelRegistry.UnregisterClient(clientID) })

	server := newTestServer(t)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	c.Request.Header.Set("User-Agent", "grok-shell/0.2.119")
	c.Set(apiKeyPolicyContextKey, singleKeyPolicy(t, "sk-a", proxyconfig.APIKeyPolicy{
		ExcludedModels: []string{"grok-registry-hidden"},
	}))

	server.handleGrokModels(c)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	assertModelHidden(t, modelsListIDs(t, recorder.Body.Bytes()), "grok-registry-visible", "grok-registry-hidden")
}

// alphaSearchPolicySelector records which credentials auth selection was offered and always
// prefers preferID when it is present, so a credential the policy should have removed is
// deterministically selected if it is still offered.
type alphaSearchPolicySelector struct {
	preferID     string
	mu           sync.Mutex
	offered      []string
	metadata     map[string]any
	selectedAuth *coreauth.Auth
}

func (s *alphaSearchPolicySelector) Pick(_ context.Context, _ string, _ string, opts coreexecutor.Options, auths []*coreauth.Auth) (*coreauth.Auth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.offered = s.offered[:0]
	for _, candidate := range auths {
		s.offered = append(s.offered, candidate.ID)
	}
	s.metadata = opts.Metadata
	for _, candidate := range auths {
		if candidate.ID == s.preferID {
			s.selectedAuth = candidate
			return candidate, nil
		}
	}
	if len(auths) == 0 {
		return nil, nil
	}
	s.selectedAuth = auths[0]
	return auths[0], nil
}

func (s *alphaSearchPolicySelector) offeredIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.offered...)
}

func registerAlphaSearchOAuth(t *testing.T, manager *coreauth.Manager, model string, authID string) {
	t.Helper()

	if _, errRegister := manager.Register(context.Background(), &coreauth.Auth{
		ID:       authID,
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Metadata: map[string]any{"access_token": authID + "-token"},
	}); errRegister != nil {
		t.Fatalf("register %s: %v", authID, errRegister)
	}
	registry.GetGlobalRegistry().RegisterClient(authID, "codex", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(authID) })
}

// The alpha-search endpoint selects a credential itself, so it must attach the authenticated
// client key's policy: an excluded account is never offered to selection and never receives an
// upstream request.
func TestCodexAlphaSearchAttachesAPIKeyPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const searchModel = "gpt-5-codex"
	newServer := func(t *testing.T, authIDs ...string) (*Server, *alphaSearchPolicySelector, *codexSearchCaptureExecutor) {
		t.Helper()

		server := newTestServer(t)
		// Prefer the excluded credential so its removal from the candidate set is what
		// determines the outcome, not the selector's ordering.
		selector := &alphaSearchPolicySelector{preferID: "codex-oauth-blocked"}
		server.handlers.AuthManager.SetSelector(selector)
		executor := &codexSearchCaptureExecutor{}
		server.handlers.AuthManager.RegisterExecutor(executor)
		for _, authID := range authIDs {
			registerAlphaSearchOAuth(t, server.handlers.AuthManager, searchModel, authID)
		}
		server.UpdateClients(policyConfig(
			[]string{"test-key"},
			proxyconfig.APIKeyPolicy{
				APIKey:             "test-key",
				ExcludedAIAccounts: []string{"codex-oauth-blocked"},
			},
		))
		return server, selector, executor
	}

	t.Run("excluded account is not selected", func(t *testing.T) {
		server, selector, executor := newServer(t, "codex-oauth-blocked", "codex-oauth-allowed")

		req := httptest.NewRequest(http.MethodPost, "/v1/alpha/search", strings.NewReader(`{"model":"gpt-5-codex","query":"test"}`))
		req.Header.Set("Authorization", "Bearer test-key")
		recorder := httptest.NewRecorder()
		server.engine.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
		}
		if offered := selector.offeredIDs(); len(offered) != 1 || offered[0] != "codex-oauth-allowed" {
			t.Fatalf("offered credentials = %v, want only codex-oauth-allowed", offered)
		}
		if len(executor.authIDs) != 1 || executor.authIDs[0] != "codex-oauth-allowed" {
			t.Fatalf("upstream auth IDs = %v, want [codex-oauth-allowed]", executor.authIDs)
		}
		if executor.httpCalls != 1 {
			t.Fatalf("upstream HTTP calls = %d, want 1", executor.httpCalls)
		}
		if _, ok := selector.metadata[coreexecutor.APIKeyPolicyMetadataKey].(*sdkconfig.APIKeyPolicySet); !ok {
			t.Fatalf("selection metadata lacks the client key policy: %#v", selector.metadata)
		}
	})

	t.Run("all accounts excluded issues no upstream request", func(t *testing.T) {
		server, selector, executor := newServer(t, "codex-oauth-blocked")

		req := httptest.NewRequest(http.MethodPost, "/v1/alpha/search", strings.NewReader(`{"model":"gpt-5-codex","query":"test"}`))
		req.Header.Set("Authorization", "Bearer test-key")
		recorder := httptest.NewRecorder()
		server.engine.ServeHTTP(recorder, req)

		if recorder.Code == http.StatusOK {
			t.Fatalf("status = %d, want a selection failure; body=%s", recorder.Code, recorder.Body.String())
		}
		if offered := selector.offeredIDs(); len(offered) != 0 {
			t.Fatalf("offered credentials = %v, want none", offered)
		}
		if executor.httpCalls != 0 {
			t.Fatalf("upstream HTTP calls = %d, want 0", executor.httpCalls)
		}
	})
}
