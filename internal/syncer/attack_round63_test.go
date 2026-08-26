// Red-team security hardening Round 63 — syncer watch-loop reload RATE
// (the R61 count/count-dedupe fix left the time dimension unbound).
//
// R61 bounded (1) identical-content replay (content dedupe) and (2) the
// per-response event COUNT (maxWatchEventsPerResponse collapse), but a
// stream of DISTINCT policies — each under the 10000-event collapse
// threshold — still triggers one onUpdate per event with no TIME-based
// bound. Each onUpdate is a full Rego recompile (cmd/server wires it to
// opaEval.Load; measured ~70ms per 2MB policy, R61); a malicious or
// compromised etcd (or a MITM on the plaintext connection, the R51/R52
// threat model) pushing a sustained stream of distinct small policies
// turns the watch loop into a sustained CPU/allocation-churn engine —
// the R6 "no rate limiting" documentation finding, which R61 closed
// only for the identical-replay dimension.
//
// R63 FIX: a minimum reload interval (minReloadInterval = 100ms, the
// same posture as threatintel.StartRefresher's minInterval). Distinct
// policies arriving within the interval are collapsed — only the
// LATEST is applied once the interval elapses (a policy syncer is
// eventual-consistency by nature; every event carries the full policy
// value, so the latest event IS the latest state — the same
// latest-wins semantics R61.2 already applies to oversized bursts). A
// timer guarantees the collapsed policy is flushed even if the watch
// stream goes idle.
package syncer

import (
	"context"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// funcEtcdClient is a client backed by caller-supplied functions —
// needed for tests that deliver multiple WatchResponses with a delay.
type funcEtcdClient struct {
	getFn   func(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error)
	watchFn func(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan
	closeFn func() error
}

func (f *funcEtcdClient) Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	if f.getFn == nil {
		return &clientv3.GetResponse{}, nil
	}
	return f.getFn(ctx, key, opts...)
}

func (f *funcEtcdClient) Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan {
	if f.watchFn == nil {
		return nil
	}
	return f.watchFn(ctx, key, opts...)
}

func (f *funcEtcdClient) Close() error {
	if f.closeFn == nil {
		return nil
	}
	return f.closeFn()
}

// distinctFloodEtcdClient delivers a single WatchResponse carrying a
// caller-chosen list of DISTINCT policy events (all under the
// maxWatchEventsPerResponse collapse threshold, so R61's count bound
// does not apply), then closes the channel.
type distinctFloodEtcdClient struct {
	events []*clientv3.Event
}

func (f *distinctFloodEtcdClient) Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	return &clientv3.GetResponse{}, nil
}

func (f *distinctFloodEtcdClient) Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan {
	ch := make(chan clientv3.WatchResponse, 1)
	ch <- clientv3.WatchResponse{Events: f.events}
	close(ch)
	return ch
}

func (f *distinctFloodEtcdClient) Close() error { return nil }

// ── R63.1: distinct-policy flood must be rate-limited ──────────────────
// RED (pre-fix): 5000 distinct policies in one response (under the R61
// collapse threshold, so every event is processed) trigger 5000
// onUpdate calls — 5000 full policy recompiles from a single wire
// response, and the same again per response indefinitely. GREEN
// (post-fix): distinct events within minReloadInterval collapse to the
// latest; at most one reload per interval.
func TestAttack_WatchDistinctPolicyFloodRateLimited(t *testing.T) {
	var callCount int32
	var applied atomic.Value // string

	const n = 5000 // distinct policies, all under the 10000 collapse cap
	events := make([]*clientv3.Event, 0, n)
	lastVal := ""
	for i := 0; i < n; i++ {
		v := "package l3_firewall -- distinct version " + strconv.Itoa(i)
		lastVal = v
		events = append(events, &clientv3.Event{
			Type: mvccpb.PUT,
			Kv:   &mvccpb.KeyValue{Key: []byte("/test/key"), Value: []byte(v)},
		})
	}

	s := &Syncer{
		client:  &distinctFloodEtcdClient{events: events},
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

	calls := atomic.LoadInt32(&callCount)
	if calls > 2 {
		t.Errorf("R63 RED: distinct-policy flood triggered %d reloads in one response — no time-based reload bound (R6 'no rate limiting'); each reload recompiles the full policy", calls)
	}
	if got := applied.Load().(string); got != lastVal {
		t.Errorf("applied policy %q, want latest %q (rate limiting must collapse to the newest state, not an intermediate one)", got, lastVal)
	}
}

// ── R63.2: distinct policies spaced beyond the interval each apply ─────
// Regression guard: the rate limiter must not delay legitimate policy
// updates. Distinct policies arriving more than minReloadInterval apart
// each reach onUpdate.
func TestAttack_WatchDistinctPoliciesSpacedStillEachApply(t *testing.T) {
	var callCount int32

	// Two responses, each carrying one distinct policy, the second
	// arriving well after minReloadInterval.
	type spacedClient struct {
		first, second string
	}
	sc := &spacedClient{first: "package l3_firewall -- v1", second: "package l3_firewall -- v2"}
	s := &Syncer{
		client: &funcEtcdClient{
			getFn: func(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
				return &clientv3.GetResponse{}, nil
			},
			watchFn: func(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan {
				ch := make(chan clientv3.WatchResponse, 2)
				ch <- clientv3.WatchResponse{Events: []*clientv3.Event{{
					Type: mvccpb.PUT,
					Kv:   &mvccpb.KeyValue{Key: []byte("/test/key"), Value: []byte(sc.first)},
				}}}
				go func() {
					time.Sleep(200 * time.Millisecond) // > minReloadInterval
					ch <- clientv3.WatchResponse{Events: []*clientv3.Event{{
						Type: mvccpb.PUT,
						Kv:   &mvccpb.KeyValue{Key: []byte("/test/key"), Value: []byte(sc.second)},
					}}}
					close(ch)
				}()
				return ch
			},
			closeFn: func() error { return nil },
		},
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
		t.Errorf("spaced distinct policies triggered %d reloads, want 2 (legitimate updates beyond the rate-limit window must each apply)", c)
	}
}
