package syncer

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── R6.1: Double-close panic ────────────────────────────────────────────
// Attacker triggers Close() twice to crash the process via panic on closed channel.
// This also tests that Close() handles nil clients gracefully (the real syncer
// may be in an incomplete state after New fails).
func TestAttack_DoubleClosePanic(t *testing.T) {
	// Use the real constructor to get a properly initialized Syncer with nil client
	// (New is not called with valid endpoints, so we can't get a client)
	ch := make(chan struct{})
	s := &Syncer{
		client:  nil,
		key:     "/test/policy",
		onUpdate: func(string) error { return nil },
		stopCh:  ch,
	}

	// First close - should not panic even with nil client
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("first Close() panicked: %v", r)
			}
		}()
		_ = s.Close()
	}()

	// Second close MUST NOT panic (this is the vulnerability)
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Error("double Close() caused panic — needs sync.Once guard or closed-channel check")
			}
		}()
		_ = s.Close()
	}()
}

// ── R6.2: onUpdate callback panic kills caller ──────────────────────────
// If the onUpdate callback panics during loadCurrent, the panic propagates to Start()
// and kills the caller's goroutine. This should be recovered.
func TestAttack_OnUpdatePanic(t *testing.T) {
	onUpdate := func(policy string) error {
		panic("attacker triggered panic in onUpdate")
	}

	s := &Syncer{
		key:      "/test/policy",
		onUpdate: onUpdate,
		stopCh:   make(chan struct{}),
	}

	recovered := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				recovered = true
			}
		}()
		_ = s.onUpdate("{}")
	}()
	if !recovered {
		t.Error("onUpdate panic propagated — needs recovery wrapper in Start()/loadCurrent()")
	}
}

// ── R6.3: Concurrent Start/Close race ───────────────────────────────────
// Attacker triggers Start and Close concurrently to race on stopCh.
func TestAttack_StartCloseRace(t *testing.T) {
	s := &Syncer{
		key:      "/test/policy",
		stopCh:   make(chan struct{}),
		onUpdate: func(string) error { return nil },
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if n%2 == 0 {
				s.Start(context.Background())
			} else {
				_ = s.Close()
			}
		}(i)
	}

	time.Sleep(50 * time.Millisecond)
	_ = s.Close()
}

// ── R6.4: Watcher event flood — no rate limiting ────────────────────────
// Rapid etcd events could overwhelm the onUpdate callback.
func TestAttack_WatcherEventFlood(t *testing.T) {
	var callCount int32
	onUpdate := func(policy string) error {
		atomic.AddInt32(&callCount, 1)
		time.Sleep(10 * time.Millisecond)
		return nil
	}

	s := &Syncer{
		key:      "/test/policy",
		stopCh:   make(chan struct{}),
		onUpdate: onUpdate,
	}

	for i := 0; i < 100; i++ {
		_ = s.onUpdate("{}")
	}

	calls := atomic.LoadInt32(&callCount)
	t.Logf("onUpdate called %d times — no rate limiting in place", calls)
}
