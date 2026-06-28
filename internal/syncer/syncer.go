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

// Syncer watches an etcd key for policy updates and triggers hot-reload.
type Syncer struct {
	client   *clientv3.Client
	key      string
	onUpdate func(string) error // called with new policy content
	stopCh   chan struct{}
	closeOnce sync.Once
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
		client:  cli,
		key:     cfg.Key,
		onUpdate: onUpdate,
		stopCh:  make(chan struct{}),
	}, nil
}

// Start begins watching the etcd key for changes.
func (s *Syncer) Start(ctx context.Context) {
	if s == nil {
		return
	}

	// Load initial policy
	s.loadCurrent(ctx)

	// Start watcher
	go s.watch(ctx)
}

func (s *Syncer) loadCurrent(ctx context.Context) {
	if s == nil || s.client == nil {
		return
	}
	resp, err := s.client.Get(ctx, s.key)
	if err != nil {
		slog.Warn("etcd: failed to get initial policy", "key", s.key, "error", err)
		return
	}
	if len(resp.Kvs) > 0 {
		policy := string(resp.Kvs[0].Value)
		if err := s.onUpdate(policy); err != nil {
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
				slog.Info("etcd: policy updated", "key", s.key, "type", ev.Type)
				if err := s.onUpdate(policy); err != nil {
					slog.Warn("etcd: failed to apply policy update", "error", err)
				}
			}
		}
	}
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
