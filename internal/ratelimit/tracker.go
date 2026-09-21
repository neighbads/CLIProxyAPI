// Package ratelimit tracks and limits in-flight concurrent requests per client API key,
// providing exponential backoff queueing and early wakeup when slots are released.
package ratelimit

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrRateLimitExceeded is returned when the in-flight concurrency limit is reached
// and all queue retry attempts have been exhausted.
var ErrRateLimitExceeded = errors.New("rate limit exceeded: max in-flight requests reached")

// keyLimiter tracks in-flight requests and waiter notifications for a single key.
type keyLimiter struct {
	mu           sync.Mutex
	inFlight     int
	waiters      int
	notify       chan struct{}
	baseInterval time.Duration
}

func newKeyLimiter(baseInterval time.Duration) *keyLimiter {
	return &keyLimiter{
		notify:       make(chan struct{}),
		baseInterval: baseInterval,
	}
}

func (l *keyLimiter) release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.inFlight > 0 {
		l.inFlight--
	}
	close(l.notify)
	l.notify = make(chan struct{})
}

func (l *keyLimiter) acquire(ctx context.Context, maxInFlight, queueRetries int) (func(), error) {
	if maxInFlight <= 0 {
		return func() {}, nil
	}

	// Fast path: try to acquire immediately
	l.mu.Lock()
	if l.inFlight < maxInFlight {
		l.inFlight++
		l.mu.Unlock()
		var once sync.Once
		return func() {
			once.Do(l.release)
		}, nil
	}
	l.mu.Unlock()

	if queueRetries <= 0 {
		return nil, ErrRateLimitExceeded
	}

	base := l.baseInterval
	if base <= 0 {
		base = time.Second
	}

	l.mu.Lock()
	l.waiters++
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		l.waiters--
		l.mu.Unlock()
	}()

	for retry := 0; retry < queueRetries; retry++ {
		interval := base * (1 << retry)
		timer := time.NewTimer(interval)
		attemptDone := false
		for !attemptDone {
			l.mu.Lock()
			notifyCh := l.notify
			if l.inFlight < maxInFlight {
				l.inFlight++
				l.mu.Unlock()
				timer.Stop()
				var once sync.Once
				return func() {
					once.Do(l.release)
				}, nil
			}
			l.mu.Unlock()

			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
				attemptDone = true
			case <-notifyCh:
				// Slot freed up, re-check under lock
			}
		}
	}

	// Final check before failing: slot may have freed on the boundary of the last timer
	l.mu.Lock()
	if l.inFlight < maxInFlight {
		l.inFlight++
		l.mu.Unlock()
		var once sync.Once
		return func() {
			once.Do(l.release)
		}, nil
	}
	l.mu.Unlock()

	return nil, ErrRateLimitExceeded
}

// Tracker manages in-flight concurrency limiters per client API key (keyed by fingerprint).
type Tracker struct {
	mu           sync.Mutex
	limiters     map[string]*keyLimiter
	baseInterval time.Duration
}

// New creates a new Tracker with the given base retry interval.
// If baseInterval <= 0, it defaults to 1 second.
func New(baseInterval time.Duration) *Tracker {
	if baseInterval <= 0 {
		baseInterval = time.Second
	}
	return &Tracker{
		limiters:     make(map[string]*keyLimiter),
		baseInterval: baseInterval,
	}
}

var defaultTracker = New(time.Second)

// Default returns the process-wide default Tracker.
func Default() *Tracker {
	return defaultTracker
}

func (t *Tracker) getLimiter(fingerprint string) *keyLimiter {
	t.mu.Lock()
	defer t.mu.Unlock()
	limiter, ok := t.limiters[fingerprint]
	if !ok {
		limiter = newKeyLimiter(t.baseInterval)
		t.limiters[fingerprint] = limiter
	}
	return limiter
}

// Acquire acquires an in-flight slot for the given fingerprint.
// If maxInFlight <= 0 or fingerprint is empty, it returns a no-op release function and nil.
// If the limit is reached, it queues up to queueRetries with exponential backoff.
// Returns a release function and an error (ErrRateLimitExceeded or context error).
func (t *Tracker) Acquire(ctx context.Context, fingerprint string, maxInFlight, queueRetries int) (func(), error) {
	if t == nil || fingerprint == "" || maxInFlight <= 0 {
		return func() {}, nil
	}
	limiter := t.getLimiter(fingerprint)
	return limiter.acquire(ctx, maxInFlight, queueRetries)
}

// InFlight returns the current number of in-flight requests for fingerprint.
func (t *Tracker) InFlight(fingerprint string) int {
	if t == nil || fingerprint == "" {
		return 0
	}
	t.mu.Lock()
	limiter, ok := t.limiters[fingerprint]
	t.mu.Unlock()
	if !ok {
		return 0
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	return limiter.inFlight
}

// Waiters returns the number of goroutines waiting for a slot for fingerprint.
func (t *Tracker) Waiters(fingerprint string) int {
	if t == nil || fingerprint == "" {
		return 0
	}
	t.mu.Lock()
	limiter, ok := t.limiters[fingerprint]
	t.mu.Unlock()
	if !ok {
		return 0
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	return limiter.waiters
}

// Reset clears all limiters (primarily for testing).
func (t *Tracker) Reset() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.limiters = make(map[string]*keyLimiter)
}
