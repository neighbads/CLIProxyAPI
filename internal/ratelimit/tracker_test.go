package ratelimit

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestTrackerImmediateAcquireAndRelease(t *testing.T) {
	tracker := New(10 * time.Millisecond)
	fp := "test-key-1"

	release1, err := tracker.Acquire(context.Background(), fp, 2, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := tracker.InFlight(fp); got != 1 {
		t.Fatalf("InFlight = %d, want 1", got)
	}

	release2, err := tracker.Acquire(context.Background(), fp, 2, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := tracker.InFlight(fp); got != 2 {
		t.Fatalf("InFlight = %d, want 2", got)
	}

	// 3rd acquire with queueRetries=0 should fail immediately
	_, err = tracker.Acquire(context.Background(), fp, 2, 0)
	if err != ErrRateLimitExceeded {
		t.Fatalf("err = %v, want ErrRateLimitExceeded", err)
	}

	// Release one
	release1()
	if got := tracker.InFlight(fp); got != 1 {
		t.Fatalf("InFlight after release1 = %d, want 1", got)
	}

	// Idempotent release
	release1()
	if got := tracker.InFlight(fp); got != 1 {
		t.Fatalf("InFlight after second release1 = %d, want 1", got)
	}

	// Release second
	release2()
	if got := tracker.InFlight(fp); got != 0 {
		t.Fatalf("InFlight after release2 = %d, want 0", got)
	}
}

func TestTrackerEarlyWakeupOnSlotRelease(t *testing.T) {
	// Base interval is 500ms; with early wakeup, acquire should complete as soon as slot is freed
	tracker := New(500 * time.Millisecond)
	fp := "test-key-wakeup"

	rel, err := tracker.Acquire(context.Background(), fp, 1, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var (
		waitErr error
		waitRel func()
		wg      sync.WaitGroup
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		waitRel, waitErr = tracker.Acquire(context.Background(), fp, 1, 3)
	}()

	// Deterministically wait until the goroutine is registered as waiting in queue
	for tracker.Waiters(fp) == 0 {
		time.Sleep(1 * time.Millisecond)
	}

	// Now release the slot
	rel()

	wg.Wait()

	if waitErr != nil {
		t.Fatalf("unexpected waitErr: %v", waitErr)
	}
	if waitRel != nil {
		waitRel()
	}
}

func TestTrackerQueueRetriesExhausted(t *testing.T) {
	tracker := New(5 * time.Millisecond)
	fp := "test-key-exhaust"

	rel, err := tracker.Acquire(context.Background(), fp, 1, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer rel()

	// 2 retries with 5ms base -> wait 5ms + 10ms = 15ms, then fail
	start := time.Now()
	_, err = tracker.Acquire(context.Background(), fp, 1, 2)
	elapsed := time.Since(start)

	if err != ErrRateLimitExceeded {
		t.Fatalf("err = %v, want ErrRateLimitExceeded", err)
	}
	if elapsed < 10*time.Millisecond {
		t.Fatalf("elapsed = %v, expected at least ~15ms wait", elapsed)
	}
}

func TestTrackerContextCancellation(t *testing.T) {
	tracker := New(1 * time.Second)
	fp := "test-key-cancel"

	rel, err := tracker.Acquire(context.Background(), fp, 1, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer rel()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err = tracker.Acquire(ctx, fp, 1, 5)
	if err != context.DeadlineExceeded {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
}

func TestTrackerUnlimitedBypass(t *testing.T) {
	tracker := New(10 * time.Millisecond)

	// maxInFlight <= 0
	rel, err := tracker.Acquire(context.Background(), "fp", 0, 0)
	if err != nil || rel == nil {
		t.Fatalf("expected nil error and non-nil rel, got err=%v", err)
	}
	rel()

	// empty fingerprint
	rel, err = tracker.Acquire(context.Background(), "", 1, 0)
	if err != nil || rel == nil {
		t.Fatalf("expected nil error and non-nil rel, got err=%v", err)
	}
	rel()
}

func TestAccountTrackerInstance(t *testing.T) {
	tr := AccountTracker()
	if tr == nil {
		t.Fatal("AccountTracker() returned nil")
	}
	if tr != AccountTracker() {
		t.Fatal("AccountTracker() should return singleton instance")
	}
}
