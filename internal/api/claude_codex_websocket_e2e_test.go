package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gorilla/websocket"
	proxyconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestClaudeMessagesReusesCodexUpstreamWebsocket(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	var upgrades atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrades.Add(1)
		conn, errUpgrade := upgrader.Upgrade(w, r, nil)
		if errUpgrade != nil {
			t.Errorf("upgrade websocket: %v", errUpgrade)
			return
		}
		defer func() { _ = conn.Close() }()
		for requestIndex := 0; requestIndex < 2; requestIndex++ {
			if _, _, errRead := conn.ReadMessage(); errRead != nil {
				t.Errorf("read websocket request %d: %v", requestIndex+1, errRead)
				return
			}
			responseID := fmt.Sprintf("resp-%d", requestIndex+1)
			events := []string{
				fmt.Sprintf(`{"type":"response.created","response":{"id":%q,"model":"gpt-5-codex"}}`, responseID),
				`{"type":"response.output_item.done","item":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]},"output_index":0}`,
				fmt.Sprintf(`{"type":"response.completed","response":{"id":%q,"output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`, responseID),
			}
			for _, event := range events {
				if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(event)); errWrite != nil {
					t.Errorf("write websocket response %d: %v", requestIndex+1, errWrite)
					return
				}
			}
		}
	}))
	defer upstream.Close()

	server := newTestServer(t)
	server.handlers.AuthManager.RegisterExecutor(runtimeexecutor.NewCodexAutoExecutor(&proxyconfig.Config{SDKConfig: proxyconfig.SDKConfig{DisableImageGeneration: proxyconfig.DisableImageGenerationAll}}))
	credentials := []*coreauth.Auth{
		{
			ID:       "claude-codex-websocket-e2e-a",
			Provider: "codex",
			Status:   coreauth.StatusActive,
			Attributes: map[string]string{
				"api_key":    "sk-test-a",
				"base_url":   upstream.URL,
				"websockets": "true",
			},
		},
		{
			ID:       "claude-codex-websocket-e2e-b",
			Provider: "codex",
			Status:   coreauth.StatusActive,
			Attributes: map[string]string{
				"api_key":    "sk-test-b",
				"base_url":   upstream.URL,
				"websockets": "true",
			},
		},
	}
	for _, credential := range credentials {
		if _, errRegister := server.handlers.AuthManager.Register(context.Background(), credential); errRegister != nil {
			t.Fatalf("register Codex auth %s: %v", credential.ID, errRegister)
		}
		server.handlers.AuthManager.RefreshSchedulerEntry(credential.ID)
		registry.GetGlobalRegistry().RegisterClient(credential.ID, credential.Provider, []*registry.ModelInfo{{ID: "gpt-5-codex"}})
	}
	t.Cleanup(func() {
		for _, credential := range credentials {
			registry.GetGlobalRegistry().UnregisterClient(credential.ID)
		}
		server.handlers.AuthManager.CloseExecutionSession(coreauth.CloseAllExecutionSessionsID)
	})

	body := `{"model":"gpt-5-codex","max_tokens":128,"stream":true,"messages":[{"role":"user","content":"hello"}]}`
	for requestIndex := 0; requestIndex < 2; requestIndex++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer test-key")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Anthropic-Version", "2023-06-01")
		req.Header.Set("X-Claude-Code-Session-Id", "claude-e2e-session")
		recorder := httptest.NewRecorder()
		server.engine.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200; body=%s", requestIndex+1, recorder.Code, recorder.Body.String())
		}
		if got := recorder.Header().Get("Content-Type"); !strings.Contains(got, "text/event-stream") {
			t.Fatalf("request %d Content-Type = %q, want SSE", requestIndex+1, got)
		}
		responseBody := recorder.Body.String()
		for _, event := range []string{"event: message_start", "event: content_block_delta", `"text":"ok"`, "event: message_stop"} {
			if !strings.Contains(responseBody, event) {
				t.Fatalf("request %d response missing %q: %s", requestIndex+1, event, responseBody)
			}
		}
	}
	if got := upgrades.Load(); got != 1 {
		t.Fatalf("upstream websocket upgrades = %d, want 1", got)
	}
}
