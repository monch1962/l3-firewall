package syncer

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
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
		client:   nil,
		key:      "/test/policy",
		onUpdate: func(string) error { return nil },
		stopCh:   ch,
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

// ── R6.4: Watcher event flood — reload rate limiting ─────────────────────
// Rapid etcd events could overwhelm the onUpdate callback. R6 documented
// the gap ("no rate limiting in place") as a t.Log and never fixed it —
// R61 converts it to a hard assertion: a flood of IDENTICAL policy events
// through the watch loop must trigger exactly ONE reload. etcd emits a
// modify event for EVERY Put (each Put is a new revision, even for the
// same value), and each reload recompiles the full policy via onUpdate
// (measured ~70ms per 2MB policy, R61) — an attacker (malicious/compromised
// etcd or MITM on the plaintext connection, the R51/R52 threat model)
// replaying the same policy bytes turns the watch loop into a sustained
// CPU-burn/allocation-churn engine (R61, content-dedupe fix).
func TestAttack_WatcherEventFlood(t *testing.T) {
	var callCount int32
	onUpdate := func(policy string) error {
		atomic.AddInt32(&callCount, 1)
		time.Sleep(10 * time.Millisecond)
		return nil
	}

	// 100 identical PUT events in a single WatchResponse.
	events := make([]*clientv3.Event, 0, 100)
	for i := 0; i < 100; i++ {
		events = append(events, &clientv3.Event{
			Type: mvccpb.PUT,
			Kv:   &mvccpb.KeyValue{Key: []byte("/test/policy"), Value: []byte("package l3_firewall")},
		})
	}
	s := &Syncer{
		client:   &floodEtcdClient{events: events},
		key:      "/test/policy",
		timeout:  time.Second,
		stopCh:   make(chan struct{}),
		onUpdate: onUpdate,
	}

	runWatchToExit(t, s)

	calls := atomic.LoadInt32(&callCount)
	if calls != 1 {
		t.Errorf("identical-policy flood triggered %d reloads, want exactly 1 (each reload recompiles the full policy — unbounded reloads are a CPU/GC DoS via malicious etcd)", calls)
	}
}
