package syncer

import (
	"context"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// ── R54.1: Close() must invoke client.Close() at most once ─────────────
// The closeOnce guard (added R6) guarantees at-most-once close of stopCh,
// but s.client.Close() is called on EVERY Close() invocation:
//
//	s.closeOnce.Do(func() { close(s.stopCh) })
//	return s.client.Close()
//
// clientv3's own Close happens to tolerate double calls (grpc guards the
// underlying conn), but the etcdClient interface (R46 — threat model:
// arbitrary implementations, e.g. a client wrapping an attacker-influenced
// endpoint that is not idempotent, or a future TLS/custom transport client)
// makes no such promise. The closeOnce's own comment contract — "ensures
// Close() is idempotent" — covers the whole method, not just the channel.
// A second Close() must be a no-op: re-invoking client.Close() on a
// non-idempotent implementation could panic or corrupt shared state
// (R6 double-close panic class, at the interface boundary instead of the
// channel).

// countingCloseEtcdClient counts Close calls to prove idempotency.
type countingCloseEtcdClient struct {
	closeCalls int
}

func (c *countingCloseEtcdClient) Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	return nil, nil
}

func (c *countingCloseEtcdClient) Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan {
	return nil
}

func (c *countingCloseEtcdClient) Close() error {
	c.closeCalls++
	return nil
}

func TestAttack_CloseInvokesClientCloseOnce(t *testing.T) {
	client := &countingCloseEtcdClient{}
	s := &Syncer{
		client:  client,
		key:     "/l3-firewall/policy",
		timeout: 200 * time.Millisecond,
		stopCh:  make(chan struct{}),
	}

	if err := s.Close(); err != nil {
		t.Fatalf("first Close() returned error: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close() returned error: %v", err)
	}

	if client.closeCalls != 1 {
		t.Errorf("client.Close() invoked %d times across two Close() calls — Close must be idempotent (want 1)", client.closeCalls)
	}
}
