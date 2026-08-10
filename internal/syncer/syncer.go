// Package syncer synchronizes firewall policy from etcd.
package syncer

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// maxPolicySize prevents memory exhaustion from an oversized etcd policy value.
// A firewall policy is typically a few KB; 10MB is an extreme upper bound.
const maxPolicySize = 10 * 1024 * 1024

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
	started   bool
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
		s.started = true
		// Load initial policy
		s.loadCurrent(ctx)
		// Start watcher
		go s.watch(ctx)
	})
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
	if len(resp.Kvs) > 0 {
		policy := string(resp.Kvs[0].Value)
		// Enforce policy size limit to prevent memory exhaustion
		if len(policy) > maxPolicySize {
			slog.Warn("etcd: initial policy exceeds max size, skipping",
				"key", s.key, "size", len(policy), "max", maxPolicySize)
			return
		}
		// Wrap callback in panic recovery to prevent goroutine death
		if err := safeOnUpdate(s.onUpdate, policy); err != nil {
			slog.Warn("etcd: failed to load initial policy", "error", err)
		} else {
			slog.Info("etcd: loaded policy from", "key", s.key)
		}
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
			for _, ev := range wresp.Events {
				policy := string(ev.Kv.Value)
				// Enforce policy size limit to prevent memory exhaustion from
				// oversized etcd values arriving via watcher updates.
				// Matching the same check in loadCurrent().
				if len(policy) > maxPolicySize {
					slog.Warn("etcd: policy update exceeds max size, skipping",
						"key", s.key, "size", len(policy), "max", maxPolicySize)
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
func (s *Syncer) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		close(s.stopCh)
	})
	if s.client == nil {
		return nil
	}
	return s.client.Close()
}
