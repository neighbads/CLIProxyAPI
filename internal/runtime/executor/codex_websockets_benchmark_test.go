package executor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func BenchmarkCodexTransportSequential(b *testing.B) {
	b.Run("pooled_websocket", func(b *testing.B) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, errUpgrade := upgrader.Upgrade(w, r, nil)
			if errUpgrade != nil {
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
		auth := &cliproxyauth.Auth{ID: "bench-ws", Attributes: map[string]string{"api_key": "sk-test", "base_url": server.URL}}
		req := benchmarkCodexRequest()
		opts := benchmarkCodexOptions()
		opts.Metadata = map[string]any{codexPooledUpstreamSessionMetadataKey: "bench-pooled"}

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, errExecute := exec.Execute(context.Background(), auth, req, opts); errExecute != nil {
				b.Fatal(errExecute)
			}
		}
		b.StopTimer()
		exec.CloseExecutionSession("bench-pooled")
	})

	b.Run("one_shot_websocket", func(b *testing.B) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, errUpgrade := upgrader.Upgrade(w, r, nil)
			if errUpgrade != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			if _, _, errRead := conn.ReadMessage(); errRead != nil {
				return
			}
			completed := []byte(`{"type":"response.completed","response":{"id":"resp-1","output":[],"usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0}}}`)
			_ = conn.WriteMessage(websocket.TextMessage, completed)
		}))
		defer server.Close()

		exec := NewCodexWebsocketsExecutor(&config.Config{SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll}})
		auth := &cliproxyauth.Auth{ID: "bench-one-shot-ws", Attributes: map[string]string{"api_key": "sk-test", "base_url": server.URL}}
		req := benchmarkCodexRequest()
		opts := benchmarkCodexOptions()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, errExecute := exec.Execute(context.Background(), auth, req, opts); errExecute != nil {
				b.Fatal(errExecute)
			}
		}
	})

	b.Run("http_keep_alive", func(b *testing.B) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprint(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-1\",\"output\":[],\"usage\":{\"input_tokens\":0,\"output_tokens\":0,\"total_tokens\":0}}}\n\n")
		}))
		defer server.Close()

		exec := NewCodexExecutor(&config.Config{SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll}})
		auth := &cliproxyauth.Auth{ID: "bench-http", Attributes: map[string]string{"api_key": "sk-test", "base_url": server.URL}}
		req := benchmarkCodexRequest()
		opts := benchmarkCodexOptions()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, errExecute := exec.Execute(context.Background(), auth, req, opts); errExecute != nil {
				b.Fatal(errExecute)
			}
		}
	})
}

func benchmarkCodexRequest() cliproxyexecutor.Request {
	return cliproxyexecutor.Request{
		Model:   "gpt-5-codex",
		Payload: []byte(`{"model":"gpt-5-codex","input":[{"role":"user","content":"hello"}]}`),
	}
}

func benchmarkCodexOptions() cliproxyexecutor.Options {
	return cliproxyexecutor.Options{
		SourceFormat:   sdktranslator.FromString("codex"),
		ResponseFormat: sdktranslator.FromString("codex"),
	}
}
