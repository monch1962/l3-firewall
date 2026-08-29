// Red-team security hardening Round 66 — syncer reconnect × rate-limiter
// interaction: the R63 pending-policy slot is flushed AFTER the R65 resync
// applied a newer policy (policy regression).
//
// R63 queues distinct policies in a pending slot when they arrive within
// minReloadInterval of the last reload, applying only the LATEST once the
// interval elapses. R65 reconnects a terminated watch and RESYNCS the
// current policy via Get before re-establishing the watch. The hole is the
// INTERACTION: the pending slot lives OUTSIDE the reconnect loop (R65
// moved it there so a watch restart does not reset the rate limiter), so a
// policy queued just before the stream died survives the reconnect and is
// flushed by the pending timer AFTER the resync has already applied the
// newer current value — the firewall REGRESSES to the stale policy.
//
// Attack (the R51/R52 threat model: malicious/compromised etcd or a MITM
// on the plaintext connection): while a legitimate (or attacker-staged)
// policy sits in the pending window, kill the watch stream; the resync
// Get reads the CURRENT value (e.g. an emergency block-everything policy
// pushed during an incident — exactly what R65 exists to protect) and
// applies it; the pending timer then flushes the OLDER policy on top,
// reverting the firewall to the stale state. Because the resync also
// advanced lastPolicy past the pending content, a replay of the newer
// policy is dedupe-skipped — the firewall is STUCK on the stale policy
// until the next distinct update.
//
// R66 FIX: the reconnect path clears the pending slot when the resync
// read a DIFFERENT policy than the queued one — the Get runs at a
// revision >= the pending event's, so the resync value is authoritative
// and newer. When the resync read the SAME content (pending == current),
// the slot is kept so the normal timer flush performs the single apply.
// When the resync read NOTHING (etcd down), the pending policy is the
// best-known state and is kept as before.
package syncer

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// ── R66.1: stale pending policy must not overwrite the resync result ────
// P0 is applied first (arming the rate-limit window: lastReload=now).
// P1 arrives within the window → queued pending, NOT applied. The watch
// stream then dies. The reconnect resync Get reads P2 (the current,
// newer value) and applies it. Pre-fix, the pending timer then flushes
// P1 AFTER P2 — the applied sequence is [P0, P2, P1] and the firewall
// runs a stale policy. Post-fix, P1 is never applied: [P0, P2].
func TestAttack_ReconnectStalePendingOverwritesResync(t *testing.T) {
	const key = "/test/key"
	const policyP0 = "package l3_firewall -- p0" // first applied: arms the rate window
	const policyP1 = "package l3_firewall -- p1" // queued pending, never applied
	const policyP2 = "package l3_firewall -- p2" // current value the resync reads

	client := &phaseEtcdClient{
		phases: []clientv3.WatchChan{
			closedWatchChan(
				clientv3.WatchResponse{Events: []*clientv3.Event{putEvent(key, policyP0)}},
				clientv3.WatchResponse{Events: []*clientv3.Event{putEvent(key, policyP1)}},
			), // P0 applied, P1 queued pending, then the stream dies
			make(chan clientv3.WatchResponse), // blocked: no further events (R65: no close → no re-reconnect)
		},
		getFn: func(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
			// The CURRENT value at reconnect: a newer policy (e.g. an
			// emergency block-everything pushed while the stream was down).
			return &clientv3.GetResponse{Kvs: []*mvccpb.KeyValue{{Key: []byte(key), Value: []byte(policyP2)}}}, nil
		},
	}
	var appliedMu sync.Mutex
	var applied []string
	s := &Syncer{
		client:  client,
		key:     key,
		timeout: time.Second,
		stopCh:  make(chan struct{}),
		onUpdate: func(policy string) error {
			appliedMu.Lock()
			applied = append(applied, policy)
			appliedMu.Unlock()
			return nil
		},
	}

	go s.watch(context.Background())
	defer close(s.stopCh)

	// The reconnect resync must apply the current policy P2.
	ok := poll(3*time.Second, func() bool {
		appliedMu.Lock()
		defer appliedMu.Unlock()
		return len(applied) >= 1 && applied[len(applied)-1] == policyP2
	})
	if !ok {
		appliedMu.Lock()
		defer appliedMu.Unlock()
		t.Fatalf("reconnect resync never applied the current policy %q (applied=%v)", policyP2, applied)
	}

	// Give the (pre-fix) pending timer ample time to fire its stale flush,
	// and the reconnect loop time to re-issue Watch (its second call lands
	// after the watchReconnectDelay backoff).
	time.Sleep(500 * time.Millisecond)
	if c := client.calls(); c < 2 {
		t.Errorf("Watch() called %d times, want >= 2 — the reconnect must have happened for this scenario", c)
	}

	appliedMu.Lock()
	defer appliedMu.Unlock()
	for _, p := range applied {
		if p == policyP1 {
			t.Errorf("R66 RED: stale pending policy %q was applied AFTER the newer resynced policy %q — the R63 pending slot survives the R65 reconnect and overwrites the resync with an older policy; an attacker who kills the watch stream while a policy is queued can revert the firewall to a stale policy, undoing emergency block-everything updates", policyP1, policyP2)
			return
		}
	}
	if len(applied) == 0 || applied[len(applied)-1] != policyP2 {
		t.Errorf("last applied policy %q, want %q — the resync result must be the final state", applied[len(applied)-1], policyP2)
	}
}

// ── R66.2: resync reading the SAME content as the pending slot must
// still apply it exactly once (the pending flush performs the apply). ──
// Regression guard: clearing the pending slot unconditionally on resync
// would LOSE a pending policy that equals the current value (it was
// queued but never applied — lastPolicy only records queue time, and the
// resync's applyPolicy dedupe skips it). The slot must be kept so the
// timer performs the single apply.
func TestAttack_ReconnectResyncSameContentStillAppliesOnce(t *testing.T) {
	const key = "/test/key"
	const policyP0 = "package l3_firewall -- p0" // first applied: arms the rate window
	const policyP1 = "package l3_firewall -- p1" // pending == current value at resync

	client := &phaseEtcdClient{
		phases: []clientv3.WatchChan{
			closedWatchChan(
				clientv3.WatchResponse{Events: []*clientv3.Event{putEvent(key, policyP0)}},
				clientv3.WatchResponse{Events: []*clientv3.Event{putEvent(key, policyP1)}},
			), // P0 applied, P1 queued pending, then the stream dies
			make(chan clientv3.WatchResponse), // blocked: no further events
		},
		getFn: func(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
			// The current value equals the pending policy.
			return &clientv3.GetResponse{Kvs: []*mvccpb.KeyValue{{Key: []byte(key), Value: []byte(policyP1)}}}, nil
		},
	}
	var appliedMu sync.Mutex
	var applied []string
	s := &Syncer{
		client:  client,
		key:     key,
		timeout: time.Second,
		stopCh:  make(chan struct{}),
		onUpdate: func(policy string) error {
			appliedMu.Lock()
			applied = append(applied, policy)
			appliedMu.Unlock()
			return nil
		},
	}

	go s.watch(context.Background())
	defer close(s.stopCh)

	// P1 must be applied exactly once (via the pending flush).
	ok := poll(3*time.Second, func() bool {
		appliedMu.Lock()
		defer appliedMu.Unlock()
		count := 0
		for _, p := range applied {
			if p == policyP1 {
				count++
			}
		}
		return count == 1
	})
	appliedMu.Lock()
	defer appliedMu.Unlock()
	if !ok {
		t.Errorf("pending policy %q was applied %d times, want exactly 1 (the pending flush must perform the single apply when the resync reads the same content)", policyP1, countP(applied, policyP1))
	}
}

func countP(applied []string, target string) int {
	n := 0
	for _, p := range applied {
		if p == target {
			n++
		}
	}
	return n
}
