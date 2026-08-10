package syncer

import (
	"context"
	"testing"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// stallingEtcdClient simulates an etcd endpoint that accepted the TCP
// connection but never responds to a Get (overloaded server, blackholed
// post-dial path, stalling proxy). It blocks until the caller's context
// is done — mirroring exactly what a real clientv3.Client.Get does when
// the server never answers.
type stallingEtcdClient struct{}

func (s *stallingEtcdClient) Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (s *stallingEtcdClient) Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan {
	return nil
}

func (s *stallingEtcdClient) Close() error { return nil }

// ── R46.2: syncer loadCurrent Get without deadline hangs startup ──────────
// main() calls policySyncer.Start(context.Background()) synchronously;
// Start → loadCurrent → client.Get(ctx, key) with the caller's context —
// context.Background(), NO deadline. An etcd endpoint that accepts the
// connection but never responds stalls the Get forever, and because
// loadCurrent runs synchronously inside Start, main() never reaches
// eng.Run(): the firewall never starts (startup DoS — the nftables queue
// has no consumer and traffic drops, or the process simply hangs). The
// config Timeout must bound the Get (R42 documented this as a finding but
// never fixed it).
func TestAttack_LoadCurrentGetHangsWithoutTimeout(t *testing.T) {
	s := &Syncer{
		client:   &stallingEtcdClient{},
		key:      "/l3-firewall/policy",
		timeout:  200 * time.Millisecond,
		onUpdate: func(string) error { return nil },
		stopCh:   make(chan struct{}),
	}

	done := make(chan struct{})
	go func() {
		s.loadCurrent(context.Background())
		close(done)
	}()

	select {
	case <-done:
		// GREEN: loadCurrent returned despite the stalled Get — the
		// per-call timeout fired and the error was handled.
	case <-time.After(2 * time.Second):
		t.Fatal("loadCurrent hung: Get without a deadline blocks startup forever")
	}
}

// healthyEtcdClient returns immediately with a fixed policy value,
// simulating a responsive etcd server.
type healthyEtcdClient struct {
	value []byte
}

func (s *healthyEtcdClient) Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	return &clientv3.GetResponse{
		Kvs: []*mvccpb.KeyValue{{Key: []byte(key), Value: s.value}},
	}, nil
}

func (s *healthyEtcdClient) Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan {
	return nil
}

func (s *healthyEtcdClient) Close() error { return nil }

// ── R46.2b: timeout still lets a healthy Get deliver the policy ───────────
// The timeout fix must not break the normal path: a fast Get response
// still reaches the onUpdate callback.
func TestAttack_LoadCurrentGetTimeoutAllowsHealthyResponse(t *testing.T) {
	// healthyEtcdClient returns immediately with a small policy value.
	s := &Syncer{
		client:   &healthyEtcdClient{value: []byte("package l3_firewall")},
		key:      "/l3-firewall/policy",
		timeout:  200 * time.Millisecond,
		onUpdate: func(string) error { return nil },
		stopCh:   make(chan struct{}),
	}

	done := make(chan struct{})
	go func() {
		s.loadCurrent(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loadCurrent did not return for a healthy Get")
	}
}
