package auth

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/session"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestPreferCodexWebsocketAuthsForIsolatedClaudeSession(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Claude-Code-Session-Id", "session-a")
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
		Headers:      headers,
		Metadata: map[string]any{
			cliproxyexecutor.CallerScopeMetadataKey: "caller-a",
		},
	}
	httpAuth := &Auth{ID: "http"}
	websocketAuth := &Auth{ID: "websocket", Attributes: map[string]string{"websockets": "true"}}

	got := preferCodexWebsocketAuths(context.Background(), "codex", opts, []*Auth{httpAuth, websocketAuth}, true, false)
	if len(got) != 1 || got[0] != websocketAuth {
		t.Fatalf("preferred auths = %#v, want websocket auth", got)
	}
}

func TestPreferCodexWebsocketAuthsAcceptsByteCallerScope(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Claude-Code-Session-Id", "session-a")
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
		Headers:      headers,
		Metadata: map[string]any{
			cliproxyexecutor.CallerScopeMetadataKey: []byte("caller-a"),
		},
	}
	httpAuth := &Auth{ID: "http"}
	websocketAuth := &Auth{ID: "websocket", Attributes: map[string]string{"websockets": "true"}}

	got := preferCodexWebsocketAuths(context.Background(), "codex", opts, []*Auth{httpAuth, websocketAuth}, true, false)
	if len(got) != 1 || got[0] != websocketAuth {
		t.Fatalf("preferred auths = %#v, want websocket auth", got)
	}
}

func TestManagerSchedulerPrefersCodexWebsocketForIsolatedClaudeSession(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Claude-Code-Session-Id", "session-a")
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
		Headers:      headers,
		Metadata: map[string]any{
			cliproxyexecutor.CallerScopeMetadataKey: "caller-a",
		},
	}

	for _, selector := range []Selector{&RoundRobinSelector{}, &WeightedRoundRobinSelector{}, &FillFirstSelector{}} {
		manager := NewManager(nil, selector, nil)
		manager.RegisterExecutor(schedulerTestExecutor{provider: "codex"})
		for _, candidate := range []*Auth{
			{ID: "http", Provider: "codex", Attributes: map[string]string{"priority": "10", AttributeWeight: "100"}},
			{ID: "websocket-a", Provider: "codex", Attributes: map[string]string{"priority": "10", "websockets": "true", AttributeWeight: "3"}},
			{ID: "websocket-b", Provider: "codex", Attributes: map[string]string{"priority": "10", "websockets": "true", AttributeWeight: "1"}},
		} {
			if _, errRegister := manager.Register(context.Background(), candidate); errRegister != nil {
				t.Fatalf("%T Register(%s) error = %v", selector, candidate.ID, errRegister)
			}
		}
		selectedID := ""
		for i := 0; i < 3; i++ {
			got, _, errPick := manager.pickNext(context.Background(), "codex", "", opts, nil)
			if errPick != nil {
				t.Fatalf("%T pickNext() error = %v", selector, errPick)
			}
			if got == nil || !authWebsocketsEnabled(got) {
				t.Fatalf("%T pickNext() auth = %#v, want websocket auth", selector, got)
			}
			if selectedID == "" {
				selectedID = got.ID
			} else if got.ID != selectedID {
				t.Fatalf("%T pickNext() auth changed from %q to %q", selector, selectedID, got.ID)
			}
		}
	}
}

func TestAfterAuthInterceptorCannotMutateExecutionMetadata(t *testing.T) {
	const originalScope = "claude:v1:8:original:agent:4:main"
	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{
			cliproxyexecutor.ClaudeCodeExecutionScopeMetadataKey: originalScope,
		},
		RequestAfterAuthInterceptor: func(_ context.Context, request cliproxyexecutor.RequestAfterAuthInterceptRequest) cliproxyexecutor.RequestAfterAuthInterceptResponse {
			request.Metadata[cliproxyexecutor.ClaudeCodeExecutionScopeMetadataKey] = "rewritten"
			return cliproxyexecutor.RequestAfterAuthInterceptResponse{}
		},
	}
	_, got, errIntercept := applyRequestAfterAuthInterceptor(context.Background(), schedulerTestExecutor{provider: "codex"}, "codex", cliproxyexecutor.Request{}, opts, "")
	if errIntercept != nil {
		t.Fatalf("applyRequestAfterAuthInterceptor() error = %v", errIntercept)
	}
	if scope := selectorMetadataString(got.Metadata, cliproxyexecutor.ClaudeCodeExecutionScopeMetadataKey); scope != originalScope {
		t.Fatalf("execution scope = %q, want %q", scope, originalScope)
	}
}

func TestCodexWebsocketAffinityKeyUsesImmutableExecutionScope(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Claude-Code-Session-Id", "session-original")
	req := cliproxyexecutor.Request{Payload: []byte(`{"messages":[{"role":"user","content":"hello"}]}`)}
	_, opts := cliproxysession.Enrich(req, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
		Headers:      headers,
		Metadata: map[string]any{
			cliproxyexecutor.CallerScopeMetadataKey: "caller-a",
		},
	})
	originalKey := codexWebsocketAffinityKey(opts)
	if originalKey == "" {
		t.Fatal("original affinity key is empty")
	}

	opts.Headers = headers.Clone()
	opts.Headers.Set("X-Claude-Code-Session-Id", "session-rewritten")
	opts.OriginalRequest = []byte(`{"metadata":{"user_id":"{\"session_id\":\"session-rewritten\"}"}}`)
	if got := codexWebsocketAffinityKey(opts); got != originalKey {
		t.Fatalf("rewritten affinity key = %q, want original %q", got, originalKey)
	}
}

func TestCodexWebsocketAffinityKeyIsolatesCallerAndAgent(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Claude-Code-Session-Id", "session-a")
	base := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
		Headers:      headers,
		Metadata: map[string]any{
			cliproxyexecutor.CallerScopeMetadataKey: "caller-a",
		},
	}
	baseKey := codexWebsocketAffinityKey(base)
	if baseKey == "" {
		t.Fatal("base affinity key is empty")
	}

	otherCaller := base
	otherCaller.Metadata = map[string]any{cliproxyexecutor.CallerScopeMetadataKey: "caller-b"}
	if got := codexWebsocketAffinityKey(otherCaller); got == "" || got == baseKey {
		t.Fatalf("caller affinity key = %q, want non-empty key different from %q", got, baseKey)
	}

	child := base
	child.Headers = headers.Clone()
	child.Headers.Set("X-Claude-Code-Agent-Id", "agent-a")
	if got := codexWebsocketAffinityKey(child); got == "" || got == baseKey {
		t.Fatalf("agent affinity key = %q, want non-empty key different from %q", got, baseKey)
	}
}

func TestSchedulerCodexWebsocketAffinityFailsOver(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Claude-Code-Session-Id", "session-a")
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
		Headers:      headers,
		Metadata: map[string]any{
			cliproxyexecutor.CallerScopeMetadataKey: "caller-a",
		},
	}
	authA := &Auth{ID: "websocket-a", Provider: "codex", Attributes: map[string]string{"websockets": "true"}}
	authB := &Auth{ID: "websocket-b", Provider: "codex", Attributes: map[string]string{"websockets": "true"}}
	scheduler := newSchedulerForTest(&RoundRobinSelector{}, authA, authB)

	selected, errPick := scheduler.pickSingle(context.Background(), "codex", "", opts, nil)
	if errPick != nil {
		t.Fatalf("initial pickSingle() error = %v", errPick)
	}
	if selected == nil {
		t.Fatal("initial pickSingle() auth = nil")
	}

	remaining := authA
	if selected.ID == authA.ID {
		remaining = authB
	}
	got, errPick := scheduler.pickSingle(context.Background(), "codex", "", opts, map[string]struct{}{selected.ID: {}})
	if errPick != nil {
		t.Fatalf("failover pickSingle() error = %v", errPick)
	}
	if got == nil || got.ID != remaining.ID {
		t.Fatalf("failover pickSingle() auth = %#v, want %s", got, remaining.ID)
	}
}

func TestWeightedCodexWebsocketAffinityDistribution(t *testing.T) {
	authA := &Auth{ID: "websocket-a", Attributes: map[string]string{AttributeWeight: "3"}}
	authB := &Auth{ID: "websocket-b", Attributes: map[string]string{AttributeWeight: "1"}}
	counts := map[string]int{}
	for i := 0; i < 10000; i++ {
		selected := stableCodexWebsocketAuth(fmt.Sprintf("session-%d", i), []*Auth{authA, authB}, true)
		if selected == nil {
			t.Fatal("stableCodexWebsocketAuth() = nil")
		}
		counts[selected.ID]++
	}
	shareA := float64(counts[authA.ID]) / 10000
	if shareA < 0.72 || shareA > 0.78 {
		t.Fatalf("weighted affinity counts = %#v, auth A share %.4f; want approximately 0.75", counts, shareA)
	}
}

func TestDirectSelectorDownstreamWebsocketKeepsRoundRobin(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Claude-Code-Session-Id", "session-a")
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
		Headers:      headers,
		Metadata: map[string]any{
			cliproxyexecutor.CallerScopeMetadataKey: "caller-a",
		},
	}
	auths := []*Auth{
		{ID: "websocket-a", Provider: "codex", Attributes: map[string]string{"websockets": "true"}},
		{ID: "websocket-b", Provider: "codex", Attributes: map[string]string{"websockets": "true"}},
	}
	selector := &RoundRobinSelector{}
	ctx := cliproxyexecutor.WithDownstreamWebsocket(context.Background())
	first, errPick := selector.Pick(ctx, "codex", "", opts, auths)
	if errPick != nil {
		t.Fatalf("first Pick() error = %v", errPick)
	}
	second, errPick := selector.Pick(ctx, "codex", "", opts, auths)
	if errPick != nil {
		t.Fatalf("second Pick() error = %v", errPick)
	}
	if first == nil || second == nil || first.ID == second.ID {
		t.Fatalf("downstream websocket picks = %#v, %#v; want round-robin", first, second)
	}
}

func TestDirectSelectorStickyRequestDoesNotAdvanceRoundRobin(t *testing.T) {
	auths := []*Auth{
		{ID: "websocket-a", Provider: "codex", Attributes: map[string]string{"websockets": "true"}},
		{ID: "websocket-b", Provider: "codex", Attributes: map[string]string{"websockets": "true"}},
	}
	selector := &RoundRobinSelector{}
	ordinary := cliproxyexecutor.Options{}
	first, errPick := selector.Pick(context.Background(), "codex", "", ordinary, auths)
	if errPick != nil {
		t.Fatalf("first ordinary Pick() error = %v", errPick)
	}

	stickyHeaders := http.Header{}
	stickyHeaders.Set("X-Claude-Code-Session-Id", "session-a")
	sticky := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
		Headers:      stickyHeaders,
		Metadata: map[string]any{
			cliproxyexecutor.CallerScopeMetadataKey: "caller-a",
		},
	}
	if _, errPick = selector.Pick(context.Background(), "codex", "", sticky, auths); errPick != nil {
		t.Fatalf("sticky Pick() error = %v", errPick)
	}
	second, errPick := selector.Pick(context.Background(), "codex", "", ordinary, auths)
	if errPick != nil {
		t.Fatalf("second ordinary Pick() error = %v", errPick)
	}
	if first == nil || second == nil || first.ID == second.ID {
		t.Fatalf("ordinary picks = %#v, %#v; want uninterrupted round-robin", first, second)
	}
}

func TestDirectSelectorStickyRequestDoesNotResetWeightedState(t *testing.T) {
	auths := []*Auth{
		{ID: "websocket-a", Provider: "codex", Attributes: map[string]string{"websockets": "true", AttributeWeight: "3"}},
		{ID: "websocket-b", Provider: "codex", Attributes: map[string]string{"websockets": "true", AttributeWeight: "1"}},
	}
	baseline := &WeightedRoundRobinSelector{}
	actual := &WeightedRoundRobinSelector{}
	ordinary := cliproxyexecutor.Options{}
	for i := 0; i < 2; i++ {
		if _, errPick := baseline.Pick(context.Background(), "codex", "", ordinary, auths); errPick != nil {
			t.Fatalf("baseline warmup Pick() error = %v", errPick)
		}
		if _, errPick := actual.Pick(context.Background(), "codex", "", ordinary, auths); errPick != nil {
			t.Fatalf("actual warmup Pick() error = %v", errPick)
		}
	}

	stickyHeaders := http.Header{}
	stickyHeaders.Set("X-Claude-Code-Session-Id", "session-a")
	sticky := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
		Headers:      stickyHeaders,
		Metadata: map[string]any{
			cliproxyexecutor.CallerScopeMetadataKey: "caller-a",
		},
	}
	if _, errPick := actual.Pick(context.Background(), "codex", "", sticky, auths); errPick != nil {
		t.Fatalf("sticky Pick() error = %v", errPick)
	}
	want, errPick := baseline.Pick(context.Background(), "codex", "", ordinary, auths)
	if errPick != nil {
		t.Fatalf("baseline next Pick() error = %v", errPick)
	}
	got, errPick := actual.Pick(context.Background(), "codex", "", ordinary, auths)
	if errPick != nil {
		t.Fatalf("actual next Pick() error = %v", errPick)
	}
	if want == nil || got == nil || got.ID != want.ID {
		t.Fatalf("weighted next picks = actual:%#v baseline:%#v", got, want)
	}
}

func TestSchedulerCodexClaudeWebsocketPreferencePreservesPriority(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Claude-Code-Session-Id", "session-a")
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
		Headers:      headers,
		Metadata: map[string]any{
			cliproxyexecutor.CallerScopeMetadataKey: "caller-a",
		},
	}
	scheduler := newSchedulerForTest(
		&RoundRobinSelector{},
		&Auth{ID: "http-high", Provider: "codex", Attributes: map[string]string{"priority": "10"}},
		&Auth{ID: "websocket-low", Provider: "codex", Attributes: map[string]string{"priority": "0", "websockets": "true"}},
	)

	got, errPick := scheduler.pickSingle(context.Background(), "codex", "", opts, nil)
	if errPick != nil {
		t.Fatalf("pickSingle() error = %v", errPick)
	}
	if got == nil || got.ID != "http-high" {
		t.Fatalf("pickSingle() auth = %#v, want http-high", got)
	}
}

func TestPreferCodexWebsocketAuthsKeepsHTTPForCompact(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Claude-Code-Session-Id", "session-a")
	httpAuth := &Auth{ID: "http"}
	websocketAuth := &Auth{ID: "websocket", Attributes: map[string]string{"websockets": "true"}}
	auths := []*Auth{httpAuth, websocketAuth}
	opts := cliproxyexecutor.Options{
		Alt:          "responses/compact",
		SourceFormat: sdktranslator.FromString("claude"),
		Headers:      headers,
		Metadata: map[string]any{
			cliproxyexecutor.CallerScopeMetadataKey: "caller-a",
		},
	}

	got := preferCodexWebsocketAuths(context.Background(), "codex", opts, auths, true, false)
	if len(got) != len(auths) {
		t.Fatalf("preferred auth count = %d, want %d", len(got), len(auths))
	}
}

func TestPreferCodexWebsocketAuthsKeepsHTTPWithoutIsolation(t *testing.T) {
	httpAuth := &Auth{ID: "http"}
	websocketAuth := &Auth{ID: "websocket", Attributes: map[string]string{"websockets": "true"}}
	auths := []*Auth{httpAuth, websocketAuth}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
		Headers:      http.Header{"X-Claude-Code-Session-Id": []string{"session-a"}},
	}

	got := preferCodexWebsocketAuths(context.Background(), "codex", opts, auths, true, false)
	if len(got) != len(auths) {
		t.Fatalf("preferred auth count = %d, want %d", len(got), len(auths))
	}
}
