package syncer

import (
	"context"
	"fmt"
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
// event list, then closes the channel (watch() exits after processing).
type floodEtcdClient struct {
	events []*clientv3.Event
}

func (f *floodEtcdClient) Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	return &clientv3.GetResponse{}, nil
}

func (f *floodEtcdClient) Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan {
	ch := make(chan clientv3.WatchResponse, 1)
	ch <- clientv3.WatchResponse{Events: f.events}
	close(ch)
	return ch
}

func (f *floodEtcdClient) Close() error { return nil }

// runWatchToExit runs s.watch() to completion (the fake client closes its
// channel after one response). Fails the test if the loop does not exit.
func runWatchToExit(t *testing.T, s *Syncer) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		s.watch(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watch loop did not exit after channel close")
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

// ── R61.4: Regression — distinct policies still each apply ─────────────
// The dedupe must only collapse IDENTICAL content: two genuinely different
// policies in one response both reach onUpdate.
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

	if c := atomic.LoadInt32(&callCount); c != 2 {
		t.Errorf("distinct policies triggered %d reloads, want 2 (dedupe must not collapse different content)", c)
	}
}
