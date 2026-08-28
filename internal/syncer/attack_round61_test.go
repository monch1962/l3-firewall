package syncer

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// ── R61: watch-loop policy-reload flood (R6 documentation-test debt) ────
//
// Attack: a malicious/compromised etcd server (or a MITM on the plaintext
// etcd connection — syncer.Config wires no TLS, the R51/R52 threat model)
// floods the watch stream with policy events. EVERY event invokes onUpdate
// (cmd/server wires it to opaEval.Load, a full Rego recompile — measured
// ~70ms per 2MB policy on this host, R61). R13/R54 bound the per-event
// VALUE size (10MB) but nothing bounds the event COUNT or reload RATE:
//  - identical content replayed N times (etcd emits a modify event for
//    EVERY Put, even a same-value Put — each is a new revision) costs N
//    full recompiles,
//  - a single oversized WatchResponse (clientv3's default 16MB receive
//    limit can carry ~400k minimal events) costs ~400k recompiles.
// Sustained compile churn pegs a CPU core, drives allocation/GC pressure
// across the whole process (NFQUEUE hot-path latency → queue overflow →
// ALL traffic dropped) and floods the log (disk fill) — availability DoS
// against the firewall's control-plane dependency.
//
// R61 fix: (1) content dedupe — an identical policy replay never reloads
// twice; (2) an oversized WatchResponse applies only its LAST event (every
// event on a single-key watch carries the FULL current value, so the last
// event IS the latest state); (3) DELETE events (nil value) are skipped
// instead of churning a failed reload each.

// floodEtcdClient delivers a single WatchResponse carrying a caller-chosen
// event list, then stays open (R65: a closed channel no longer ends the
// watch loop — it triggers a reconnect; the test terminates via stopCh).
type floodEtcdClient struct {
	mu        sync.Mutex
	delivered bool
	events    []*clientv3.Event
}

func (f *floodEtcdClient) Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	return &clientv3.GetResponse{}, nil
}

func (f *floodEtcdClient) Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch := make(chan clientv3.WatchResponse, 1)
	if !f.delivered {
		f.delivered = true
		ch <- clientv3.WatchResponse{Events: f.events}
	}
	return ch
}

func (f *floodEtcdClient) Close() error { return nil }

// runWatchToExit runs s.watch() in a goroutine until stopCh is closed.
// R61/R63 tests deliver a bounded set of events and then end the loop via
// stopCh: since R65 the loop no longer exits when the watch channel closes
// (a closed channel is a stream FAILURE that triggers a reconnect, not the
// end of sync). The grace period lets the delivered events be processed
// before the loop is stopped.
func runWatchToExit(t *testing.T, s *Syncer) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		s.watch(context.Background())
		close(done)
	}()
	time.Sleep(500 * time.Millisecond) // process the delivered events
	close(s.stopCh)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watch loop did not exit after stopCh close")
	}
}

// ── R61.1: Same-policy replay must not reload (see rewritten R6.4 test for
// the identical-content flood; this one covers the burst-bound dimension).

// ── R61.2: Oversized WatchResponse applies only the latest state ────────
// A single response carrying more events than maxWatchEventsPerResponse
// must NOT process every event (up to ~400k recompiles from one 16MB wire
// response). Only the last event — the latest policy state — is applied.
func TestAttack_WatchEventBurstBoundedToLatestState(t *testing.T) {
	var callCount int32
	var applied atomic.Value // string

	events := make([]*clientv3.Event, 0, maxWatchEventsPerResponse+5)
	lastVal := ""
	for i := 0; i < maxWatchEventsPerResponse+5; i++ {
		v := fmt.Sprintf("package l3_firewall -- distinct version %d", i)
		lastVal = v
		events = append(events, &clientv3.Event{
			Type: mvccpb.PUT,
			Kv:   &mvccpb.KeyValue{Key: []byte("/test/key"), Value: []byte(v)},
		})
	}

	s := &Syncer{
		client:  &floodEtcdClient{events: events},
		key:     "/test/key",
		timeout: time.Second,
		stopCh:  make(chan struct{}),
		onUpdate: func(policy string) error {
			atomic.AddInt32(&callCount, 1)
			applied.Store(policy)
			return nil
		},
	}

	runWatchToExit(t, s)

	if c := atomic.LoadInt32(&callCount); c != 1 {
		t.Errorf("oversized watch response triggered %d reloads, want 1 (each distinct event recompiles the policy — a 16MB response can carry ~400k events: unbounded CPU burn)", c)
	}
	if got := applied.Load().(string); got != lastVal {
		t.Errorf("applied policy %q, want latest %q (burst must converge on the newest state, not an intermediate one)", got, lastVal)
	}
}

// ── R61.3: DELETE events must not trigger a failed reload ───────────────
// A DELETE event carries no policy value (nil Kv.Value). Pre-R61 every
// delete invoked onUpdate("") which failed the empty-policy check — each
// delete churned a failed reload + error log. Deletes are skipped with a
// warning; the last applied policy stays in force.
func TestAttack_WatchDeleteEventNoReload(t *testing.T) {
	var callCount int32
	s := &Syncer{
		client: &floodEtcdClient{events: []*clientv3.Event{{
			Type: mvccpb.DELETE,
			Kv:   &mvccpb.KeyValue{Key: []byte("/test/key"), Value: nil},
		}}},
		key:     "/test/key",
		timeout: time.Second,
		stopCh:  make(chan struct{}),
		onUpdate: func(policy string) error {
			atomic.AddInt32(&callCount, 1)
			return nil
		},
	}

	runWatchToExit(t, s)

	if c := atomic.LoadInt32(&callCount); c != 0 {
		t.Errorf("DELETE event triggered %d reload attempts, want 0 (a delete carries no policy value — each attempt is a wasted reload + error log)", c)
	}
}

// ── R61.4: Regression — distinct policies within one response collapse ─
// The dedupe must not collapse IDENTICAL content, but since R63 the
// reload RATE is bounded: two genuinely different policies arriving
// within minReloadInterval (same batch, same watch response) collapse
// to the LATEST — a policy syncer is eventual-consistency by nature and
// every event carries the full value, so applying the newest state is
// correct (the R61.2 latest-wins semantics applied to the ≤10000 case).
// Distinct policies spaced beyond the interval each apply — covered by
// TestAttack_WatchDistinctPoliciesSpacedStillEachApply (R63.2).
func TestAttack_WatchDistinctPoliciesEachApply(t *testing.T) {
	var callCount int32
	s := &Syncer{
		client: &floodEtcdClient{events: []*clientv3.Event{
			{Type: mvccpb.PUT, Kv: &mvccpb.KeyValue{Key: []byte("/test/key"), Value: []byte("package l3_firewall -- v1")}},
			{Type: mvccpb.PUT, Kv: &mvccpb.KeyValue{Key: []byte("/test/key"), Value: []byte("package l3_firewall -- v2")}},
		}},
		key:     "/test/key",
		timeout: time.Second,
		stopCh:  make(chan struct{}),
		onUpdate: func(policy string) error {
			atomic.AddInt32(&callCount, 1)
			return nil
		},
	}

	runWatchToExit(t, s)

	if c := atomic.LoadInt32(&callCount); c != 1 {
		t.Errorf("distinct policies within the rate-limit window triggered %d reloads, want 1 (R63: reloads are time-bounded; only the latest state applies)", c)
	}
}
