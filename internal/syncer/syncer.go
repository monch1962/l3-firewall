// Package syncer synchronizes firewall policy from etcd.
package syncer

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// maxPolicySize prevents memory exhaustion from an oversized etcd policy value.
// A firewall policy is typically a few KB; 10MB is an extreme upper bound.
const maxPolicySize = 10 * 1024 * 1024

// maxWatchEventsPerResponse bounds the number of events processed from a
// single WatchResponse. R13/R54 bound the per-event VALUE size but not the
// event COUNT: a single response within clientv3's 16MB receive limit can
// carry ~400k minimal events, each triggering a full policy recompile via
// onUpdate — unbounded CPU burn from one wire response (R61 — the R58
// bound-one-dimension rule applied to the watch path). An oversized
// response is collapsed to its LAST event before processing: every event
// on a single-key watch (no WithPrevKV) carries the FULL current value, so
// the last event IS the latest policy state.
const maxWatchEventsPerResponse = 10000

// etcdClient is the minimal client surface the syncer needs. Extracted as
// an interface so tests can inject a stub whose Get stalls — proving the
// per-call timeout prevents the startup hang (R46). *clientv3.Client
// satisfies it implicitly.
type etcdClient interface {
	Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error)
	Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan
	Close() error
}

// Syncer watches an etcd key for policy updates and triggers hot-reload.
type Syncer struct {
	client    etcdClient
	key       string
	timeout   time.Duration      // per-operation deadline for Get (R46)
	onUpdate  func(string) error // called with new policy content
	stopCh    chan struct{}
	closeOnce sync.Once // ensures Close() is idempotent
	startOnce sync.Once // ensures Start() is idempotent

	// policyMu + lastPolicy dedupe policy content. etcd emits a modify
	// event for EVERY Put — a same-value Put is a new revision and still
	// produces an event — and every event drives onUpdate (a full Rego
	// recompile via opaEval.Load, ~70ms per 2MB policy, measured R61). An
	// attacker replaying identical policy bytes (malicious/compromised
	// etcd or MITM on the plaintext connection, the R51/R52 threat model)
	// turns the watch loop into a sustained CPU/allocation-churn engine.
	// lastPolicy records the LAST PROCESSED content (applied or rejected),
	// so an identical replay never reloads twice (R61 — the R6 "no rate
	// limiting" documentation finding, finally fixed).
	policyMu   sync.Mutex
	lastPolicy string
}

// Config controls the etcd syncer.
type Config struct {
	Endpoints []string // etcd endpoints
	Key       string   // etcd key to watch for policy
	Timeout   time.Duration
}

// New creates an etcd policy syncer.
func New(cfg Config, onUpdate func(string) error) (*Syncer, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, nil
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Key == "" {
		cfg.Key = "/l3-firewall/policy"
	}

	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   cfg.Endpoints,
		DialTimeout: cfg.Timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("connecting to etcd: %w", err)
	}

	return &Syncer{
		client:   cli,
		key:      cfg.Key,
		timeout:  cfg.Timeout,
		onUpdate: onUpdate,
		stopCh:   make(chan struct{}),
	}, nil
}

// Start begins watching the etcd key for changes.
// Idempotent — subsequent calls are no-ops.
func (s *Syncer) Start(ctx context.Context) {
	if s == nil {
		return
	}
	s.startOnce.Do(func() {
		// Load initial policy
		s.loadCurrent(ctx)
		// Start watcher
		go s.watch(ctx)
	})
}

// applyPolicy dedupes policy content before the onUpdate callback is
// invoked. It records the last PROCESSED content (applied or rejected) so
// an identical replay never triggers a second recompile: etcd emits a
// modify event for every Put, even a same-value Put, and each reload
// recompiles the full policy (R61 — the R6 "no rate limiting" gap). The
// last-ATTEMPTED (not last-successful) content is tracked so a policy that
// fails to compile is also compiled at most once per distinct content.
// Returns true when the caller should invoke onUpdate.
func (s *Syncer) applyPolicy(policy string) bool {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	if policy == s.lastPolicy {
		return false
	}
	s.lastPolicy = policy
	return true
}

func (s *Syncer) loadCurrent(ctx context.Context) {
	if s == nil || s.client == nil {
		return
	}
	// Bound the Get with the config timeout: main() calls Start with
	// context.Background() (no deadline), and a raw Get on that context
	// hangs forever if the etcd endpoint accepts the connection but never
	// responds — blocking Start synchronously so the firewall never
	// reaches eng.Run() (startup DoS, R46). The timeout also covers a
	// half-open connection where DialTimeout already elapsed.
	getCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	resp, err := s.client.Get(getCtx, s.key)
	if err != nil {
		slog.Warn("etcd: failed to get initial policy", "key", s.key, "error", err)
		return
	}
	// A Get response missing its kv entirely (nil response) or whose first
	// element is a nil KeyValue pointer must not panic loadCurrent: it runs
	// synchronously inside Start on the MAIN goroutine with no recover
	// anywhere on the path, so a panic there crashes the whole process at
	// startup (R52 — the R51 watch-loop nil-shape guard applied to the
	// initial-load path, which dereferenced resp.Kvs[0].Value unguarded).
	if resp == nil || len(resp.Kvs) == 0 || resp.Kvs[0] == nil {
		slog.Warn("etcd: initial Get response missing key/value, skipping")
		return
	}
	// Enforce policy size limit BEFORE converting the value to a string:
	// the conversion copies the full value into memory, so a post-copy
	// len(policy) check (pre-R54) defeats the cap's purpose — the
	// allocation the cap exists to prevent has already happened (R42/R13
	// check-before-allocate doctrine; R42's readPolicyFile enforces the
	// cap via fstat + LimitReader before the bytes ever reach memory).
	if len(resp.Kvs[0].Value) > maxPolicySize {
		slog.Warn("etcd: initial policy exceeds max size, skipping",
			"key", s.key, "size", len(resp.Kvs[0].Value), "max", maxPolicySize)
		return
	}
	policy := string(resp.Kvs[0].Value)
	// Content dedupe (R61): the same policy is already applied — a reload
	// would recompile identical content for nothing.
	if !s.applyPolicy(policy) {
		slog.Debug("etcd: initial policy unchanged, skipping", "key", s.key)
		return
	}
	// Wrap callback in panic recovery to prevent goroutine death
	if err := safeOnUpdate(s.onUpdate, policy); err != nil {
		slog.Warn("etcd: failed to load initial policy", "error", err)
	} else {
		slog.Info("etcd: loaded policy from", "key", s.key)
	}
}

func (s *Syncer) watch(ctx context.Context) {
	if s == nil || s.client == nil {
		return
	}
	wch := s.client.Watch(ctx, s.key)
	for {
		select {
		case <-s.stopCh:
			return
		case wresp, ok := <-wch:
			if !ok {
				return
			}
			// Bound the event COUNT dimension (R58 rule): R13/R54 cap the
			// per-event VALUE size, but a single response within clientv3's
			// receive limit can carry ~400k minimal events, each triggering
			// a full policy recompile — unbounded CPU burn from one wire
			// response (R61). Collapse an oversized response to its LAST
			// event: every event on this single-key watch (no WithPrevKV)
			// carries the full current value, so the last event IS the
			// latest policy state; intermediates are irrelevant to a policy
			// syncer (eventual consistency).
			events := wresp.Events
			if len(events) > maxWatchEventsPerResponse {
				slog.Warn("etcd: watch response carries excessive events, applying only the latest state",
					"key", s.key, "count", len(events), "max", maxWatchEventsPerResponse)
				events = events[len(events)-1:]
			}
			for _, ev := range events {
				// A watch event missing its key/value (nil event pointer
				// or nil Kv — possible from a malformed/malicious etcd
				// wire response, which clientv3 casts into *Event pointers
				// without filtering) must not panic the watch goroutine:
				// an unrecovered panic there crashes the whole process
				// (R51 — the nil deref was the only unprotected statement
				// in the watch loop).
				if ev == nil || ev.Kv == nil {
					slog.Warn("etcd: watch event missing key/value, skipping")
					continue
				}
				// DELETE events carry no policy value (nil Kv.Value):
				// applying one always failed the empty-policy check,
				// churning a failed reload + error log per delete. Skip
				// with a warning and keep the last applied policy (R61).
				if ev.Type == mvccpb.DELETE {
					slog.Warn("etcd: policy key deleted, keeping last applied policy", "key", s.key)
					continue
				}
				// Enforce policy size limit BEFORE the string conversion —
				// same check-before-allocate ordering as loadCurrent (R54):
				// string() copies the value, so a post-copy check lets an
				// oversized value allocate fully before being rejected.
				if len(ev.Kv.Value) > maxPolicySize {
					slog.Warn("etcd: policy update exceeds max size, skipping",
						"key", s.key, "size", len(ev.Kv.Value), "max", maxPolicySize)
					continue
				}
				policy := string(ev.Kv.Value)
				// Content dedupe (R61): an identical replay never reloads
				// twice — see applyPolicy.
				if !s.applyPolicy(policy) {
					slog.Debug("etcd: policy unchanged, skipping reload", "key", s.key)
					continue
				}
				slog.Info("etcd: policy updated", "key", s.key, "type", ev.Type)
				// Wrap callback in panic recovery to prevent goroutine death
				if err := safeOnUpdate(s.onUpdate, policy); err != nil {
					slog.Warn("etcd: failed to apply policy update", "error", err)
				}
			}
		}
	}
}

// safeOnUpdate calls the onUpdate callback with panic recovery.
// If the callback panics, the panic is recovered and returned as an error.
func safeOnUpdate(fn func(string) error, policy string) (err error) {
	if fn == nil {
		return fmt.Errorf("onUpdate callback is nil")
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("onUpdate panic: %v", r)
			slog.Error("etcd: recovered panic in onUpdate callback", "panic", fmt.Sprintf("%v", r))
		}
	}()
	return fn(policy)
}

// Close shuts down the syncer and closes the etcd connection.
// Idempotent: the closeOnce guard covers the WHOLE close — the stopCh
// AND client.Close(). Before R54 the once guarded only the channel, so a
// second Close() re-invoked client.Close(): clientv3 tolerates double
// calls but the etcdClient interface (R46) makes no such promise for
// arbitrary implementations, and the idempotency contract exists exactly
// so a double Close cannot corrupt a client (R6 double-close panic class).
func (s *Syncer) Close() error {
	if s == nil {
		return nil
	}
	var err error
	s.closeOnce.Do(func() {
		close(s.stopCh)
		if s.client != nil {
			err = s.client.Close()
		}
	})
	return err
}
