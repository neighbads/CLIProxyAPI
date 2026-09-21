package auth

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/ratelimit"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestSessionAffinity_AccountRateLimit_QueueAndAcquire(t *testing.T) {
	ctx := context.Background()
	provider := "concurrency-test-provider"
	model := "test-model"
	authID := "auth-busy-1"

	manager := NewManager(nil, nil, nil)
	tracker := ratelimit.New(10 * time.Millisecond) // short base interval for fast tests

	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Hour,
	})
	defer affinity.Stop()
	affinity.SetAccountTracker(tracker)
	affinity.SetAccountPolicies([]internalconfig.AccountPolicy{
		{
			AuthID: authID,
			RateLimits: internalconfig.AccountRateLimits{
				MaxInFlight:  1,
				QueueRetries: 5,
			},
		},
	})
	manager.SetSelector(affinity)
	manager.RegisterExecutor(schedulerTestExecutor{provider: provider})

	auth := &Auth{ID: authID, Provider: provider, Status: StatusActive}
	if _, err := manager.Register(WithSkipPersist(ctx), auth); err != nil {
		t.Fatalf("Register: %v", err)
	}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, provider, []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })

	sessionOpts := cliproxyexecutor.Options{
		Metadata: map[string]any{
			cliproxyexecutor.DerivedSessionIDMetadataKey: "session-prompt-cache-1",
		},
	}

	// 1. First pick: binds session to authID and acquires slot
	picked1, _, _, err := manager.pickNextMixed(ctx, []string{provider}, model, sessionOpts, nil)
	if err != nil {
		t.Fatalf("pickNextMixed 1 failed: %v", err)
	}
	if picked1.ID != authID {
		t.Fatalf("picked1 = %s, want %s", picked1.ID, authID)
	}

	// Manually simulate execution slot acquisition by holding 1 slot
	rel1, errAcq := tracker.Acquire(ctx, authID, 1, 0)
	if errAcq != nil {
		t.Fatalf("tracker.Acquire 1 failed: %v", errAcq)
	}
	if tracker.InFlight(authID) != 1 {
		t.Fatalf("inFlight = %d, want 1", tracker.InFlight(authID))
	}

	// 2. Second pick for same session in background: should queue because slot is occupied
	var (
		picked2  *Auth
		pick2Err error
		wg       sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		optsCopy := cliproxyexecutor.Options{
			Metadata: map[string]any{
				cliproxyexecutor.DerivedSessionIDMetadataKey: "session-prompt-cache-1",
			},
		}
		picked2, _, _, pick2Err = manager.pickNextMixed(ctx, []string{provider}, model, optsCopy, nil)
	}()

	// Wait until goroutine is queued as a waiter
	for tracker.Waiters(authID) == 0 {
		time.Sleep(2 * time.Millisecond)
	}

	// Release first slot, which triggers early wakeup
	rel1()

	wg.Wait()
	if pick2Err != nil {
		t.Fatalf("pick2Err: %v", pick2Err)
	}
	if picked2 == nil || picked2.ID != authID {
		t.Fatalf("picked2 = %v, want %s (maintaining session affinity)", picked2, authID)
	}

	// Clean up any pre-acquired slot
	cleanupAcquiredSlot(sessionOpts.Metadata)
}

func TestSessionAffinity_AccountRateLimit_RetriesExhausted_UnbindAndFallback(t *testing.T) {
	ctx := context.Background()
	provider := "concurrency-unbind-provider"
	model := "test-model"
	authA := "auth-a-primary"
	authB := "auth-b-fallback"

	manager := NewManager(nil, nil, nil)
	tracker := ratelimit.New(5 * time.Millisecond)

	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Hour,
	})
	defer affinity.Stop()
	affinity.SetAccountTracker(tracker)
	affinity.SetAccountPolicies([]internalconfig.AccountPolicy{
		{
			AuthID: authA,
			RateLimits: internalconfig.AccountRateLimits{
				MaxInFlight:  1,
				QueueRetries: 1, // Only 1 retry -> quick exhaustion
			},
		},
		{
			AuthID: authB,
			RateLimits: internalconfig.AccountRateLimits{
				MaxInFlight:  10,
				QueueRetries: 0,
			},
		},
	})
	manager.SetSelector(affinity)
	manager.RegisterExecutor(schedulerTestExecutor{provider: provider})

	for _, a := range []*Auth{
		{ID: authA, Provider: provider, Status: StatusActive, Attributes: map[string]string{"priority": "1"}},
		{ID: authB, Provider: provider, Status: StatusActive, Attributes: map[string]string{"priority": "0"}},
	} {
		if _, err := manager.Register(WithSkipPersist(ctx), a); err != nil {
			t.Fatalf("Register: %v", err)
		}
		registry.GetGlobalRegistry().RegisterClient(a.ID, provider, []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
	}

	sessionOpts := cliproxyexecutor.Options{
		Metadata: map[string]any{
			cliproxyexecutor.DerivedSessionIDMetadataKey: "session-exhaust-1",
		},
	}

	// Initial pick binds to authA (priority 1)
	p1, _, _, err := manager.pickNextMixed(ctx, []string{provider}, model, sessionOpts, nil)
	if err != nil || p1.ID != authA {
		t.Fatalf("initial pick = %v, err = %v; want %s", p1, err, authA)
	}

	// Saturate authA
	relA, errAcq := tracker.Acquire(ctx, authA, 1, 0)
	if errAcq != nil {
		t.Fatalf("Acquire authA: %v", errAcq)
	}
	defer relA()

	// Next pick on same session: authA is busy, retries exhaust -> unbinds and falls back to authB
	optsNext := cliproxyexecutor.Options{
		Metadata: map[string]any{
			cliproxyexecutor.DerivedSessionIDMetadataKey: "session-exhaust-1",
		},
	}
	p2, _, _, err := manager.pickNextMixed(ctx, []string{provider}, model, optsNext, nil)
	if err != nil {
		t.Fatalf("next pick failed: %v", err)
	}
	if p2.ID != authB {
		t.Fatalf("picked %s after retry exhaustion, want fallback %s", p2.ID, authB)
	}
}

func TestSpilloverAcrossPriorityTiers(t *testing.T) {
	ctx := context.Background()
	provider := "spillover-provider"
	model := "test-model"
	highAuth := "high-tier-auth"
	lowAuth := "low-tier-auth"

	manager := NewManager(nil, nil, nil)
	tracker := ratelimit.New(5 * time.Millisecond)

	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Hour,
	})
	defer affinity.Stop()
	affinity.SetAccountTracker(tracker)
	affinity.SetAccountPolicies([]internalconfig.AccountPolicy{
		{
			AuthID: highAuth,
			RateLimits: internalconfig.AccountRateLimits{
				MaxInFlight:  1,
				QueueRetries: 1, // Quick exhaustion to allow fast spillover
			},
		},
		{
			AuthID: lowAuth,
			RateLimits: internalconfig.AccountRateLimits{
				MaxInFlight:  5,
				QueueRetries: 0,
			},
		},
	})
	manager.SetSelector(affinity)
	manager.RegisterExecutor(schedulerTestExecutor{provider: provider})

	for _, a := range []*Auth{
		{ID: highAuth, Provider: provider, Status: StatusActive, Attributes: map[string]string{"priority": "2"}},
		{ID: lowAuth, Provider: provider, Status: StatusActive, Attributes: map[string]string{"priority": "1"}},
	} {
		if _, err := manager.Register(WithSkipPersist(ctx), a); err != nil {
			t.Fatalf("Register: %v", err)
		}
		registry.GetGlobalRegistry().RegisterClient(a.ID, provider, []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
	}

	// Saturated high tier
	relHigh, errAcq := tracker.Acquire(ctx, highAuth, 1, 0)
	if errAcq != nil {
		t.Fatalf("Acquire highAuth: %v", errAcq)
	}
	defer relHigh()

	// Base selection should spill over from priority 2 to priority 1 because priority 2 is busy
	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{},
	}
	picked, _, _, err := manager.pickNextMixed(ctx, []string{provider}, model, opts, nil)
	if err != nil {
		t.Fatalf("pick failed: %v", err)
	}
	if picked.ID != lowAuth {
		t.Fatalf("picked = %s, want spillover to %s", picked.ID, lowAuth)
	}
}

func TestStreamHoldsAccountSlotUntilClosed(t *testing.T) {
	chunks := make(chan cliproxyexecutor.StreamChunk, 2)
	streamResult := &cliproxyexecutor.StreamResult{
		Chunks: chunks,
	}

	released := false
	release := func() {
		released = true
	}

	wrapped := wrapStreamWithRelease(context.Background(), streamResult, release)
	if released {
		t.Fatal("release was called before stream finished")
	}

	// Send chunk 1
	chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("hello")}
	chunk1 := <-wrapped.Chunks
	if string(chunk1.Payload) != "hello" {
		t.Fatalf("chunk1 = %s, want hello", string(chunk1.Payload))
	}
	if released {
		t.Fatal("release was called while stream is still open")
	}

	// Close chunks
	close(chunks)

	// Drain remaining
	for range wrapped.Chunks {
	}

	// Give goroutine a moment to run defer
	time.Sleep(5 * time.Millisecond)

	if !released {
		t.Fatal("release was not called after stream chunks closed")
	}
}

func TestWrapStreamWithReleaseContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	chunks := make(chan cliproxyexecutor.StreamChunk)
	streamResult := &cliproxyexecutor.StreamResult{
		Chunks: chunks,
	}

	released := make(chan struct{})
	var once sync.Once
	release := func() {
		once.Do(func() {
			close(released)
		})
	}

	_ = wrapStreamWithRelease(ctx, streamResult, release)

	// Send chunk into streamResult while downstream out channel is unread
	go func() {
		chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("blocked")}
	}()

	// Wait for chunk to be pending on out channel
	time.Sleep(10 * time.Millisecond)

	// Cancel context while downstream is blocked
	cancel()

	select {
	case <-released:
		// Success: release called upon context cancellation
	case <-time.After(500 * time.Millisecond):
		t.Fatal("release was not called upon context cancellation")
	}
}

func TestRateLimitExceededDoesNotTriggerCooldown(t *testing.T) {
	ctx := context.Background()
	authID := "rate-limited-auth"
	provider := "test-provider"
	model := "test-model"

	manager := NewManager(nil, nil, nil)
	auth := &Auth{ID: authID, Provider: provider, Status: StatusActive}
	if _, err := manager.Register(WithSkipPersist(ctx), auth); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Simulate Result with ErrRateLimitExceeded
	res := Result{
		AuthID:   authID,
		Provider: provider,
		Model:    model,
		Success:  false,
		Error:    resultErrorFromError(ratelimit.ErrRateLimitExceeded),
	}

	manager.MarkResult(ctx, res)

	// Auth and model should NOT be in cooldown
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	a := manager.auths[authID]
	if a == nil {
		t.Fatal("auth not found")
	}

	state := existingModelState(a, canonicalModelKey(model))
	if state != nil {
		if !state.NextRetryAfter.IsZero() && state.NextRetryAfter.After(time.Now()) {
			t.Fatalf("model state NextRetryAfter = %v, expected zero/not cooling", state.NextRetryAfter)
		}
		if state.Quota.Exceeded {
			t.Fatal("model state quota should not be exceeded")
		}
	}
	if a.Quota.Exceeded {
		t.Fatal("auth quota should not be exceeded")
	}
}

type blockingTestExecutor struct {
	provider string
	blockCh  chan struct{}
	streamCh chan cliproxyexecutor.StreamChunk
}

func (e *blockingTestExecutor) Identifier() string {
	return e.provider
}

func (e *blockingTestExecutor) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if e.blockCh != nil {
		select {
		case <-ctx.Done():
			return cliproxyexecutor.Response{}, ctx.Err()
		case <-e.blockCh:
		}
	}
	return cliproxyexecutor.Response{Payload: []byte(`{"result":"ok"}`)}, nil
}

func (e *blockingTestExecutor) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	ch := e.streamCh
	if ch == nil {
		c := make(chan cliproxyexecutor.StreamChunk)
		close(c)
		ch = c
	}
	return &cliproxyexecutor.StreamResult{Chunks: ch}, nil
}

func (e *blockingTestExecutor) Refresh(ctx context.Context, auth *Auth) (*Auth, error) {
	return auth, nil
}

func (e *blockingTestExecutor) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if e.blockCh != nil {
		select {
		case <-ctx.Done():
			return cliproxyexecutor.Response{}, ctx.Err()
		case <-e.blockCh:
		}
	}
	return cliproxyexecutor.Response{}, nil
}

func (e *blockingTestExecutor) HttpRequest(ctx context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
	return nil, nil
}

func TestManagerExecute_InFlightLimitingAndRelease(t *testing.T) {
	ctx := context.Background()
	authID := "exec-concurrency-auth"
	provider := "exec-concurrency-provider"
	model := "test-model"

	manager := NewManager(nil, nil, nil)
	tracker := ratelimit.AccountTracker()
	tracker.Reset()

	blockCh := make(chan struct{})
	exec := &blockingTestExecutor{provider: provider, blockCh: blockCh}
	manager.RegisterExecutor(exec)

	cfg := &internalconfig.Config{
		SDKConfig: internalconfig.SDKConfig{
			AccountPolicies: []internalconfig.AccountPolicy{
				{
					AuthID: authID,
					RateLimits: internalconfig.AccountRateLimits{
						MaxInFlight:  1,
						QueueRetries: 0,
					},
				},
			},
		},
	}
	manager.SetConfig(cfg)

	auth := &Auth{ID: authID, Provider: provider, Status: StatusActive}
	if _, err := manager.Register(WithSkipPersist(ctx), auth); err != nil {
		t.Fatalf("Register: %v", err)
	}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, provider, []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })

	req := cliproxyexecutor.Request{Model: model}
	opts := cliproxyexecutor.Options{}

	// Request 1: starts and blocks in executor
	var wg sync.WaitGroup
	var resp1 cliproxyexecutor.Response
	var err1 error
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp1, err1 = manager.Execute(ctx, []string{provider}, req, opts)
	}()

	// Wait until request 1 has acquired the in-flight slot
	for tracker.InFlight(authID) == 0 {
		time.Sleep(1 * time.Millisecond)
	}

	// Request 2: should fail with rate limit exceeded
	_, err2 := manager.Execute(ctx, []string{provider}, req, opts)
	if !errors.Is(err2, ratelimit.ErrRateLimitExceeded) {
		t.Fatalf("err2 = %v, want %v", err2, ratelimit.ErrRateLimitExceeded)
	}

	// Unblock request 1
	close(blockCh)
	wg.Wait()

	if err1 != nil {
		t.Fatalf("err1: %v", err1)
	}
	if string(resp1.Payload) != `{"result":"ok"}` {
		t.Fatalf("resp1 payload = %s", string(resp1.Payload))
	}

	// Slot must be released
	if got := tracker.InFlight(authID); got != 0 {
		t.Fatalf("inFlight after resp1 = %d, want 0", got)
	}

	// Request 3: slot is free, should succeed
	exec.blockCh = nil
	resp3, err3 := manager.Execute(ctx, []string{provider}, req, opts)
	if err3 != nil {
		t.Fatalf("err3: %v", err3)
	}
	if string(resp3.Payload) != `{"result":"ok"}` {
		t.Fatalf("resp3 payload = %s", string(resp3.Payload))
	}
}

func TestManagerExecuteStream_InFlightSlotHeldUntilStreamCloses(t *testing.T) {
	ctx := context.Background()
	authID := "stream-concurrency-auth"
	provider := "stream-concurrency-provider"
	model := "test-model"

	manager := NewManager(nil, nil, nil)
	tracker := ratelimit.AccountTracker()
	tracker.Reset()

	streamCh := make(chan cliproxyexecutor.StreamChunk, 2)
	streamCh <- cliproxyexecutor.StreamChunk{Payload: []byte("initial-chunk")}
	exec := &blockingTestExecutor{provider: provider, streamCh: streamCh}
	manager.RegisterExecutor(exec)

	cfg := &internalconfig.Config{
		SDKConfig: internalconfig.SDKConfig{
			AccountPolicies: []internalconfig.AccountPolicy{
				{
					AuthID: authID,
					RateLimits: internalconfig.AccountRateLimits{
						MaxInFlight:  1,
						QueueRetries: 0,
					},
				},
			},
		},
	}
	manager.SetConfig(cfg)

	auth := &Auth{ID: authID, Provider: provider, Status: StatusActive}
	if _, err := manager.Register(WithSkipPersist(ctx), auth); err != nil {
		t.Fatalf("Register: %v", err)
	}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, provider, []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })

	req := cliproxyexecutor.Request{Model: model}
	opts := cliproxyexecutor.Options{}

	// Stream request starts
	streamResult, errStream := manager.ExecuteStream(ctx, []string{provider}, req, opts)
	if errStream != nil {
		t.Fatalf("ExecuteStream: %v", errStream)
	}
	if streamResult == nil {
		t.Fatal("ExecuteStream returned nil result")
	}

	// While stream is open, slot must be held
	if got := tracker.InFlight(authID); got != 1 {
		t.Fatalf("inFlight during stream = %d, want 1", got)
	}

	// Concurrent execute should fail with ErrRateLimitExceeded
	_, err2 := manager.Execute(ctx, []string{provider}, req, opts)
	if !errors.Is(err2, ratelimit.ErrRateLimitExceeded) {
		t.Fatalf("err2 = %v, want %v", err2, ratelimit.ErrRateLimitExceeded)
	}

	// Send chunk and close stream
	streamCh <- cliproxyexecutor.StreamChunk{Payload: []byte("stream-chunk-1")}
	close(streamCh)

	// Drain chunks
	for range streamResult.Chunks {
	}

	// Allow goroutine to release slot
	time.Sleep(5 * time.Millisecond)

	if got := tracker.InFlight(authID); got != 0 {
		t.Fatalf("inFlight after stream drained = %d, want 0", got)
	}
}

func TestManagerExecute_BackwardCompatibility_NoPolicies(t *testing.T) {
	ctx := context.Background()
	authID := "unlimited-auth"
	provider := "unlimited-provider"
	model := "test-model"

	manager := NewManager(nil, nil, nil)
	tracker := ratelimit.AccountTracker()
	tracker.Reset()

	exec := &blockingTestExecutor{provider: provider}
	manager.RegisterExecutor(exec)

	// No AccountPolicies configured
	auth := &Auth{ID: authID, Provider: provider, Status: StatusActive}
	if _, err := manager.Register(WithSkipPersist(ctx), auth); err != nil {
		t.Fatalf("Register: %v", err)
	}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, provider, []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })

	req := cliproxyexecutor.Request{Model: model}
	opts := cliproxyexecutor.Options{}

	// Multiple concurrent executions should all succeed without rate limit errors
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := manager.Execute(ctx, []string{provider}, req, opts)
			if err != nil {
				t.Errorf("Execute: %v", err)
			}
			if string(resp.Payload) != `{"result":"ok"}` {
				t.Errorf("resp payload = %s", string(resp.Payload))
			}
		}()
	}
	wg.Wait()

	// InFlight should remain 0 (unlimited bypass)
	if got := tracker.InFlight(authID); got != 0 {
		t.Fatalf("inFlight for unconfigured policy = %d, want 0", got)
	}
}
