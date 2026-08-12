package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/session"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestCodexWebsocketOptionsUsesIsolatedClaudeSession(t *testing.T) {
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"websockets": "true"}}
	headers := http.Header{}
	headers.Set(helps.ClaudeCodeSessionHeader, "session-a")
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
		Headers:      headers,
		Metadata: map[string]any{
			cliproxyexecutor.CallerScopeMetadataKey: "caller-a",
		},
	}

	got, ok := codexWebsocketOptions(context.Background(), auth, cliproxyexecutor.Request{}, opts)
	if !ok {
		t.Fatal("codexWebsocketOptions() did not enable websocket")
	}
	pooledID := metadataString(got.Metadata, codexPooledUpstreamSessionMetadataKey)
	if pooledID == "" {
		t.Fatal("pooled websocket session ID is empty")
	}
	if _, exists := opts.Metadata[codexPooledUpstreamSessionMetadataKey]; exists {
		t.Fatal("codexWebsocketOptions() mutated caller metadata")
	}

	gotAgain, ok := codexWebsocketOptions(context.Background(), auth, cliproxyexecutor.Request{}, opts)
	if !ok || metadataString(gotAgain.Metadata, codexPooledUpstreamSessionMetadataKey) != pooledID {
		t.Fatal("pooled websocket session ID is not stable")
	}
}

func TestCodexWebsocketOptionsUsesImmutableExecutionScope(t *testing.T) {
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"websockets": "true"}}
	headers := http.Header{}
	headers.Set(helps.ClaudeCodeSessionHeader, "session-rewritten")
	opts := cliproxyexecutor.Options{
		SourceFormat:    sdktranslator.FromString("claude"),
		Headers:         headers,
		OriginalRequest: []byte(`{"metadata":{"user_id":"{\"session_id\":\"session-rewritten\"}"}}`),
		Metadata: map[string]any{
			cliproxyexecutor.CallerScopeMetadataKey:              "caller-a",
			cliproxyexecutor.ClaudeCodeExecutionScopeMetadataKey: cliproxysession.ClaudeCodeExecutionScopeForIDs("session-original", "main"),
		},
	}

	got, ok := codexWebsocketOptions(context.Background(), auth, cliproxyexecutor.Request{}, opts)
	if !ok {
		t.Fatal("codexWebsocketOptions() did not enable websocket")
	}
	wantInput := strings.Join([]string{"codex-http-ws:v1", "caller-a", cliproxysession.ClaudeCodeExecutionScopeForIDs("session-original", "main")}, "\x00")
	wantSum := sha256.Sum256([]byte(wantInput))
	wantID := "codex-http-ws:" + hex.EncodeToString(wantSum[:])
	if gotID := metadataString(got.Metadata, codexPooledUpstreamSessionMetadataKey); gotID != wantID {
		t.Fatalf("pooled session ID = %q, want %q", gotID, wantID)
	}
}

func TestCodexWebsocketOptionsIsolatesClaudeAgents(t *testing.T) {
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"websockets": "true"}}
	rootHeaders := http.Header{}
	rootHeaders.Set(helps.ClaudeCodeSessionHeader, "session-a")
	childHeaders := rootHeaders.Clone()
	childHeaders.Set(helps.ClaudeCodeAgentHeader, "agent-a")
	base := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
		Metadata: map[string]any{
			cliproxyexecutor.CallerScopeMetadataKey: "caller-a",
		},
	}
	root := base
	root.Headers = rootHeaders
	child := base
	child.Headers = childHeaders

	rootOpts, rootOK := codexWebsocketOptions(context.Background(), auth, cliproxyexecutor.Request{}, root)
	childOpts, childOK := codexWebsocketOptions(context.Background(), auth, cliproxyexecutor.Request{}, child)
	if !rootOK || !childOK {
		t.Fatal("expected root and child requests to use websocket")
	}
	rootID := metadataString(rootOpts.Metadata, codexPooledUpstreamSessionMetadataKey)
	childID := metadataString(childOpts.Metadata, codexPooledUpstreamSessionMetadataKey)
	if rootID == "" || childID == "" || rootID == childID {
		t.Fatalf("pooled session IDs are not agent-isolated: root=%q child=%q", rootID, childID)
	}
}

func TestCodexWebsocketOptionsRequiresCallerAndSession(t *testing.T) {
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"websockets": "true"}}
	headers := http.Header{}
	headers.Set(helps.ClaudeCodeSessionHeader, "session-a")
	withoutCaller := cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude"), Headers: headers}
	if _, ok := codexWebsocketOptions(context.Background(), auth, cliproxyexecutor.Request{}, withoutCaller); ok {
		t.Fatal("websocket enabled without caller scope")
	}
	withoutSession := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
		Metadata:     map[string]any{cliproxyexecutor.CallerScopeMetadataKey: "caller-a"},
	}
	if _, ok := codexWebsocketOptions(context.Background(), auth, cliproxyexecutor.Request{}, withoutSession); ok {
		t.Fatal("websocket enabled without Claude session")
	}
}

func TestCodexPooledWebsocketWithLifecycleFallsBackToHTTPOn426(t *testing.T) {
	var fallbackCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "websocket upgrade required", http.StatusUpgradeRequired)
			return
		}
		fallbackCalls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-http\",\"output\":[],\"usage\":{\"input_tokens\":0,\"output_tokens\":0,\"total_tokens\":0}}}\n\n"))
	}))
	defer server.Close()

	store := &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	exec := &CodexWebsocketsExecutor{
		CodexExecutor: NewCodexExecutor(&config.Config{SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll}}),
		store:         store,
	}
	auth := &cliproxyauth.Auth{ID: "auth-a", Attributes: map[string]string{"api_key": "sk-test", "base_url": server.URL}}
	opts := cliproxyexecutor.Options{
		SourceFormat:       sdktranslator.FromString("codex"),
		ResponseFormat:     sdktranslator.FromString("codex"),
		ExecutionLifecycle: newTerminalFailureLifecycle(),
		Metadata:           map[string]any{codexPooledUpstreamSessionMetadataKey: "pooled-home-426"},
	}

	result, errExecute := exec.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "gpt-5-codex",
		Payload: []byte(`{"model":"gpt-5-codex","input":[]}`),
	}, opts)
	if errExecute != nil {
		t.Fatalf("ExecuteStream() error = %v", errExecute)
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("fallback stream error = %v", chunk.Err)
		}
	}
	if got := fallbackCalls.Load(); got != 1 {
		t.Fatalf("HTTP fallback calls = %d, want 1", got)
	}
	store.mu.Lock()
	_, exists := store.sessions["pooled-home-426"]
	store.mu.Unlock()
	if exists {
		t.Fatal("pooled session remains after HTTP fallback")
	}
}

func TestCodexPooledWebsocketStreamHandshakeErrorRemovesSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"unauthorized"}}`))
	}))
	defer server.Close()

	store := &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	exec := &CodexWebsocketsExecutor{
		CodexExecutor: NewCodexExecutor(&config.Config{SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll}}),
		store:         store,
	}
	auth := &cliproxyauth.Auth{ID: "auth-a", Attributes: map[string]string{"api_key": "sk-test", "base_url": server.URL}}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("codex"),
		Metadata:     map[string]any{codexPooledUpstreamSessionMetadataKey: "pooled-handshake-error"},
	}

	_, errExecute := exec.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "gpt-5-codex",
		Payload: []byte(`{"model":"gpt-5-codex","input":[]}`),
	}, opts)
	if errExecute == nil {
		t.Fatal("ExecuteStream() error = nil")
	}
	store.mu.Lock()
	_, exists := store.sessions["pooled-handshake-error"]
	store.mu.Unlock()
	if exists {
		t.Fatal("pooled session remains after handshake error")
	}
}

func TestCodexPooledWebsocketBootstrapCancelDropsSession(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	var upgrades atomic.Int32
	firstClosed := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection := upgrades.Add(1)
		conn, errUpgrade := upgrader.Upgrade(w, r, nil)
		if errUpgrade != nil {
			t.Errorf("upgrade websocket: %v", errUpgrade)
			return
		}
		defer func() { _ = conn.Close() }()
		if _, _, errRead := conn.ReadMessage(); errRead != nil {
			t.Errorf("read request: %v", errRead)
			return
		}
		if connection == 1 {
			created := []byte(`{"type":"response.created","response":{"id":"resp-a"}}`)
			if errWrite := conn.WriteMessage(websocket.TextMessage, created); errWrite != nil {
				t.Errorf("write created response: %v", errWrite)
				return
			}
			_, _, _ = conn.ReadMessage()
			close(firstClosed)
			return
		}
		completed := []byte(`{"type":"response.completed","response":{"id":"resp-b","output":[],"usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0}}}`)
		if errWrite := conn.WriteMessage(websocket.TextMessage, completed); errWrite != nil {
			t.Errorf("write completed response: %v", errWrite)
		}
	}))
	defer server.Close()

	store := &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	cfg := &config.Config{
		SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll},
		Codex:     config.CodexConfig{StreamBootstrapBuffering: true},
	}
	exec := &CodexWebsocketsExecutor{CodexExecutor: NewCodexExecutor(cfg), store: store}
	auth := &cliproxyauth.Auth{ID: "auth-a", Attributes: map[string]string{"api_key": "sk-test", "base_url": server.URL}}
	req := cliproxyexecutor.Request{Model: "gpt-5-codex", Payload: []byte(`{"model":"gpt-5-codex","input":[{"role":"user","content":"hello"}]}`)}
	metadata := map[string]any{codexPooledUpstreamSessionMetadataKey: "pooled-bootstrap-cancel"}
	ctx, cancel := context.WithCancel(context.Background())
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("codex"),
		Metadata:     metadata,
		WebSocketResponseObserver: func(_ context.Context, event cliproxyexecutor.WebSocketResponseEvent) {
			if event.EventType == "response.created" {
				cancel()
			}
		},
	}

	if result, errExecute := exec.ExecuteStream(ctx, auth, req, opts); result != nil || errExecute != context.Canceled {
		t.Fatalf("canceled ExecuteStream() = %#v, %v; want nil, context.Canceled", result, errExecute)
	}
	select {
	case <-firstClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled pooled websocket was not closed")
	}
	store.mu.Lock()
	_, exists := store.sessions["pooled-bootstrap-cancel"]
	store.mu.Unlock()
	if exists {
		t.Fatal("pooled session remains after bootstrap cancellation")
	}

	result, errExecute := exec.ExecuteStream(context.Background(), auth, req, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("codex"),
		Metadata:     metadata,
	})
	if errExecute != nil {
		t.Fatalf("replacement ExecuteStream() error = %v", errExecute)
	}
	var combined []byte
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("replacement stream error = %v", chunk.Err)
		}
		combined = append(combined, chunk.Payload...)
	}
	if !strings.Contains(string(combined), "resp-b") || strings.Contains(string(combined), "resp-a") {
		t.Fatalf("replacement stream = %s, want only resp-b", combined)
	}
	if got := upgrades.Load(); got != 2 {
		t.Fatalf("websocket upgrades = %d, want 2", got)
	}
	exec.CloseExecutionSession("pooled-bootstrap-cancel")
}

func TestCodexPooledWebsocketQueuedRequestSkipsDroppedSession(t *testing.T) {
	store := &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	exec := &CodexWebsocketsExecutor{store: store}
	stale := exec.getOrCreateSessionWithMode("pooled-stale", true)
	stale.reqMu.Lock()

	started := make(chan struct{})
	locked := make(chan bool, 1)
	go func() {
		close(started)
		locked <- exec.lockSessionIfCurrent(stale)
	}()
	<-started
	exec.dropPooledSession(stale, "request_error")
	stale.reqMu.Unlock()
	if <-locked {
		t.Fatal("dropped pooled session was accepted after its request lock became available")
	}

	current := exec.lockSessionWithMode("pooled-stale", true)
	if current == nil || current == stale {
		t.Fatalf("current pooled session = %#v, want a new session", current)
	}
	store.mu.Lock()
	stored := store.sessions["pooled-stale"]
	store.mu.Unlock()
	if stored != current {
		t.Fatal("replacement session is not the current pooled session")
	}
	current.reqMu.Unlock()
}

func TestCodexPooledWebsocketReconnectRemainsReusable(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	var upgrades atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrades.Add(1)
		conn, errUpgrade := upgrader.Upgrade(w, r, nil)
		if errUpgrade != nil {
			t.Errorf("upgrade websocket: %v", errUpgrade)
			return
		}
		defer func() { _ = conn.Close() }()
		for {
			if _, _, errRead := conn.ReadMessage(); errRead != nil {
				return
			}
			completed := []byte(`{"type":"response.completed","response":{"id":"resp-1","output":[],"usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0}}}`)
			if errWrite := conn.WriteMessage(websocket.TextMessage, completed); errWrite != nil {
				return
			}
		}
	}))
	defer server.Close()

	store := &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	exec := &CodexWebsocketsExecutor{
		CodexExecutor: NewCodexExecutor(&config.Config{SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll}}),
		store:         store,
	}
	auth := &cliproxyauth.Auth{ID: "auth-a", Attributes: map[string]string{"api_key": "sk-test", "base_url": server.URL}}
	sess := exec.getOrCreateSessionWithMode("pooled-reconnect", true)
	wsURL, errURL := buildCodexResponsesWebsocketURL(server.URL + "/responses")
	if errURL != nil {
		t.Fatalf("build websocket URL: %v", errURL)
	}
	conn, _, _, errDial := exec.ensureUpstreamConn(context.Background(), auth, sess, auth.ID, wsURL, http.Header{})
	if errDial != nil {
		t.Fatalf("ensure initial websocket: %v", errDial)
	}
	exec.invalidateUpstreamConnRetainingPooledSession(sess, conn, "test_reconnect", context.Canceled)

	store.mu.Lock()
	stored := store.sessions["pooled-reconnect"]
	store.mu.Unlock()
	if stored != sess {
		t.Fatal("pooled session was removed before reconnect")
	}

	req := cliproxyexecutor.Request{Model: "gpt-5-codex", Payload: []byte(`{"model":"gpt-5-codex","input":[{"role":"user","content":"hello"}]}`)}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("codex"),
		Metadata: map[string]any{
			codexPooledUpstreamSessionMetadataKey: "pooled-reconnect",
		},
	}
	for i := 0; i < 2; i++ {
		if _, errExecute := exec.Execute(context.Background(), auth, req, opts); errExecute != nil {
			t.Fatalf("Execute() request %d error = %v", i+1, errExecute)
		}
	}
	if got := upgrades.Load(); got != 2 {
		t.Fatalf("websocket upgrades = %d, want 2", got)
	}
	exec.CloseExecutionSession("pooled-reconnect")
}

func TestCodexPooledWebsocketReusesConnectionAcrossRequests(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	var upgrades atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrades.Add(1)
		conn, errUpgrade := upgrader.Upgrade(w, r, nil)
		if errUpgrade != nil {
			t.Errorf("upgrade websocket: %v", errUpgrade)
			return
		}
		defer func() { _ = conn.Close() }()
		for i := 0; i < 2; i++ {
			if _, _, errRead := conn.ReadMessage(); errRead != nil {
				t.Errorf("read request %d: %v", i+1, errRead)
				return
			}
			completed := []byte(`{"type":"response.completed","response":{"id":"resp-1","output":[],"usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0}}}`)
			if errWrite := conn.WriteMessage(websocket.TextMessage, completed); errWrite != nil {
				t.Errorf("write response %d: %v", i+1, errWrite)
				return
			}
		}
	}))
	defer server.Close()

	store := &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	exec := &CodexWebsocketsExecutor{
		CodexExecutor: NewCodexExecutor(&config.Config{SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll}}),
		store:         store,
	}
	auth := &cliproxyauth.Auth{ID: "auth-a", Attributes: map[string]string{"api_key": "sk-test", "base_url": server.URL}}
	req := cliproxyexecutor.Request{Model: "gpt-5-codex", Payload: []byte(`{"model":"gpt-5-codex","input":[{"role":"user","content":"hello"}]}`)}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("codex"),
		Metadata: map[string]any{
			codexPooledUpstreamSessionMetadataKey: "pooled-reuse",
		},
	}

	for i := 0; i < 2; i++ {
		if _, errExecute := exec.Execute(context.Background(), auth, req, opts); errExecute != nil {
			t.Fatalf("Execute() request %d error = %v", i+1, errExecute)
		}
	}
	if got := upgrades.Load(); got != 1 {
		t.Fatalf("websocket upgrades = %d, want 1", got)
	}
	exec.CloseExecutionSession("pooled-reuse")
}
