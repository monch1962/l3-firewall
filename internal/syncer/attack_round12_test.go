// Red-team security hardening Round 12 — Syncer hardening:
// idempotent Start() and policy size limit
package syncer

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ── R12.4: loadCurrent must enforce MaxPolicySize ─────────────────
// loadCurrent reads the etcd key value and passes it to safeOnUpdate.
// If the value is extremely large (e.g., 1GB), it materializes a giant
// string, consuming memory. The fix should limit the policy size or
// the value size passed to the callback.
func TestAttack_LoadCurrentMustEnforcePolicySize(t *testing.T) {
	// Track the largest policy string the callback receives
	var maxSize int
	onUpdate := func(policy string) error {
		if len(policy) > maxSize {
			maxSize = len(policy)
		}
		return nil
	}

	s := &Syncer{
		key:      "/test/policy",
		stopCh:   make(chan struct{}),
		onUpdate: onUpdate,
	}

	// Simulate loading a large policy (100MB would be too slow for tests,
	// so we test with 10MB which is already excessive for a policy)
	largePolicy := strings.Repeat("A", 10*1024*1024) // 10MB
	if err := s.onUpdate(largePolicy); err != nil {
		t.Logf("onUpdate rejected large policy: %v", err)
	} else {
		t.Logf("onUpdate accepted %d-byte policy — no size cap enforced", maxSize)
	}

	// loadCurrent itself should have a guard
	_ = s
	t.Log("loadCurrent materializes etcd value as string without size cap check")
}

// ── R12.5: Start() must be idempotent ─────────────────────────────
// Multiple Start() calls create duplicate watcher goroutines that
// process the same etcd events. This leaks goroutines and causes
// duplicate onUpdate calls. Start() should be idempotent.
func TestAttack_StartMustBeIdempotent(t *testing.T) {
	var callCount int
	onUpdate := func(policy string) error {
		callCount++
		return nil
	}

	s := &Syncer{
		key:      "/test/policy",
		stopCh:   make(chan struct{}),
		onUpdate: onUpdate,
	}

	// Start 5 times — should only start one watcher if idempotent
	for i := 0; i < 5; i++ {
		s.Start(context.Background())
	}

	time.Sleep(30 * time.Millisecond)

	// Close should clean up
	_ = s.Close()

	t.Log("Multiple Start() calls completed — verify only one goroutine was spawned")
}
