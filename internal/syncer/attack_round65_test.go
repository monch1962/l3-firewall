// Red-team security hardening Round 65 — syncer watch-loop RESILIENCE
// (the R61/R63 flood defenses left the failure direction unbound).
//
// R61 bounded identical-content replay, R63 bounded the reload rate for
// distinct policies — but the watch loop treats a TERMINATED watch as
// the END of sync. clientv3 closes the watch channel — after delivering
// a final Canceled/errored WatchResponse — whenever a watch cannot be
// resumed: server-side cancel (watch session expiry, server limits),
// mvcc compaction past the start revision (ErrCompacted), or an
// unrecoverable stream error. The pre-R65 loop's `if !ok { return }`
// exits the goroutine PERMANENTLY with no log line and no reconnect.
//
// Attack (the R51/R52 threat model: malicious/compromised etcd or a
// MITM on the plaintext connection): one hostile frame that fails the
// watch stream kills the policy update plane forever. Every subsequent
// legitimate policy push — including an emergency block-everything
// policy deployed DURING an active incident — is silently dropped. The
// firewall runs on stale policy indefinitely, with zero observability
// (no error is ever logged).
//
// R65 FIX: a terminated watch is re-established. The loop logs the
// termination, resyncs the latest policy via Get (compaction-proof, and
// it throttles the reconnect cycle when etcd is down via s.timeout),
// waits a bounded backoff (watchReconnectDelay), and re-issues Watch.
// The R63 rate-limit state (lastReload/pendingPolicy) lives OUTSIDE the
// reconnect loop so a watch restart does not reset the limiter.
package syncer

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// phaseEtcdClient delivers one WatchResponse batch per Watch() call —
// each phase channel is closed by the caller, modeling clientv3's
// close-after-final-response termination — then blocks forever on
// subsequent calls (the loop stays alive until stopCh). Counts Watch()
// invocations so tests can assert reconnects happened.
type phaseEtcdClient struct {
	mu         sync.Mutex
	phases     []clientv3.WatchChan
	watchCalls int
	getFn      func(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error)
}

func (p *phaseEtcdClient) Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	if p.getFn == nil {
		return &clientv3.GetResponse{}, nil
	}
	return p.getFn(ctx, key, opts...)
}

func (p *phaseEtcdClient) Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.watchCalls++
	if len(p.phases) == 0 {
		return make(chan clientv3.WatchResponse) // block forever — loop stays alive until stopCh
	}
	ch := p.phases[0]
	p.phases = p.phases[1:]
	return ch
}

func (p *phaseEtcdClient) Close() error { return nil }

func (p *phaseEtcdClient) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.watchCalls
}

func closedWatchChan(resps ...clientv3.WatchResponse) clientv3.WatchChan {
	ch := make(chan clientv3.WatchResponse, len(resps))
	for _, r := range resps {
		ch <- r
	}
	close(ch)
	return ch
}

func putEvent(key, val string) *clientv3.Event {
	return &clientv3.Event{
		Type: mvccpb.PUT,
		Kv:   &mvccpb.KeyValue{Key: []byte(key), Value: []byte(val)},
	}
}

// poll returns true once cond holds, polling until the timeout elapses.
func poll(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// ── R65.1: a closed watch channel must not end policy sync ──────────────
// RED (pre-fix): the watch channel closes after the first batch
// (clientv3's termination signal) and the loop exits permanently — the
// second policy is never applied and Watch() is never called again.
func TestAttack_WatchChannelCloseSilentlyKillsPolicySync(t *testing.T) {
	const key = "/test/key"
	client := &phaseEtcdClient{
		phases: []clientv3.WatchChan{
			closedWatchChan(clientv3.WatchResponse{Events: []*clientv3.Event{putEvent(key, "package l3_firewall -- A")}}),
			closedWatchChan(clientv3.WatchResponse{Events: []*clientv3.Event{putEvent(key, "package l3_firewall -- B")}}),
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
	ok := poll(3*time.Second, func() bool {
		appliedMu.Lock()
		defer appliedMu.Unlock()
		return len(applied) >= 2
	})
	close(s.stopCh)

	appliedMu.Lock()
	defer appliedMu.Unlock()
	if !ok {
		t.Errorf("R65 RED: after the watch channel closed, policy B was never applied (got %d of 2) — a single watch failure permanently kills policy sync; every subsequent legitimate policy push (including emergency block-everything policies) is silently dropped", len(applied))
	}
	if len(applied) > 0 && applied[len(applied)-1] != "package l3_firewall -- B" {
		t.Errorf("last applied policy %q, want %q", applied[len(applied)-1], "package l3_firewall -- B")
	}
	if c := client.calls(); c < 2 {
		t.Errorf("Watch() called %d times, want >= 2 — the loop must re-establish the watch after termination", c)
	}
}

// ── R65.2: a Canceled/errored watch response must not end policy sync ───
// clientv3 watch.go: a watch that cannot be resumed sends a final
// WatchResponse with Canceled=true (Err() non-nil) before closing the
// channel (compaction, server-side cancel, unrecoverable stream error).
// Pre-R65 that ended policy sync permanently — same silent-kill impact
// as R65.1.
func TestAttack_WatchCanceledResponseTerminatesSync(t *testing.T) {
	const key = "/test/key"
	client := &phaseEtcdClient{
		phases: []clientv3.WatchChan{
			closedWatchChan(clientv3.WatchResponse{Canceled: true}),
			closedWatchChan(clientv3.WatchResponse{Events: []*clientv3.Event{putEvent(key, "package l3_firewall -- C")}}),
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
	ok := poll(3*time.Second, func() bool {
		appliedMu.Lock()
		defer appliedMu.Unlock()
		return len(applied) >= 1
	})
	close(s.stopCh)

	appliedMu.Lock()
	defer appliedMu.Unlock()
	if !ok {
		t.Errorf("R65 RED: a canceled watch response ended sync — policy C never applied; the loop must reconnect after a Canceled response")
	}
	if c := client.calls(); c < 2 {
		t.Errorf("Watch() called %d times, want >= 2 — the loop must re-establish the watch after a canceled response", c)
	}
}

// ── R65.3: the reconnect resyncs the policy missed during the gap ──────
// Events delivered while the stream was down are lost; the reconnect
// must resync the latest state via Get (compaction-proof) before
// trusting the new watch — otherwise a policy pushed during the outage
// is never applied.
func TestAttack_WatchReconnectResyncsMissedPolicy(t *testing.T) {
	const key = "/test/key"
	// getCalls: the resync Get returns the MISSED policy exactly once
	// (the update written while the stream was down); later Gets return
	// empty (the current state is whatever the watch has delivered).
	var getCalls int32
	client := &phaseEtcdClient{
		phases: []clientv3.WatchChan{
			closedWatchChan(), // stream fails before delivering anything
			closedWatchChan(clientv3.WatchResponse{Events: []*clientv3.Event{putEvent(key, "package l3_firewall -- v3")}}),
		},
		getFn: func(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
			n := getCalls
			getCalls++
			if n == 0 {
				// The update that happened while the stream was down.
				return &clientv3.GetResponse{Kvs: []*mvccpb.KeyValue{{Key: []byte(key), Value: []byte("package l3_firewall -- v2")}}}, nil
			}
			return &clientv3.GetResponse{}, nil
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
	ok := poll(3*time.Second, func() bool {
		appliedMu.Lock()
		defer appliedMu.Unlock()
		return len(applied) >= 2
	})
	close(s.stopCh)

	appliedMu.Lock()
	defer appliedMu.Unlock()
	if !ok {
		t.Errorf("R65 RED: the reconnect did not resync the missed policy — got %d of 2 applications; a policy pushed during the watch outage is lost forever", len(applied))
		return
	}
	if applied[0] != "package l3_firewall -- v2" {
		t.Errorf("first applied policy %q, want the missed %q (the reconnect must resync the latest state before trusting the new watch)", applied[0], "package l3_firewall -- v2")
	}
	if applied[len(applied)-1] != "package l3_firewall -- v3" {
		t.Errorf("last applied policy %q, want %q", applied[len(applied)-1], "package l3_firewall -- v3")
	}
}
