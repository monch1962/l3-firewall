package syncer

import (
	"context"
	"testing"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// ── R52: loadCurrent dereferences resp.Kvs[0] with no nil-element check ──
//
// R51 hardened the watch loop against malformed wire shapes (nil Event /
// nil Kv → skip with warning) but the sibling initial-load path,
// loadCurrent, has the identical unguarded dereference:
//
//	if len(resp.Kvs) > 0 {
//	    policy := string(resp.Kvs[0].Value)  // ← resp.Kvs[0] may be nil
//	}
//
// A GetResponse whose Kvs slice contains a nil *mvccpb.KeyValue element —
// the malformed-wire shape a malicious/compromised etcd server (or a MITM
// on the plaintext connection, R51's threat model) can produce — panics
// loadCurrent. Worse than the R51 watch case: loadCurrent runs
// SYNCHRONOUSLY inside Start() on the MAIN goroutine with no recover
// anywhere on the path (main → Start → loadCurrent), so the panic crashes
// the whole firewall process at startup — a control-plane DoS that
// prevents the engine from ever reaching eng.Run().

// nilKvElementEtcdClient returns a GetResponse whose Kvs slice contains a
// nil *mvccpb.KeyValue element — the shape a malformed wire response
// produces after clientv3's unfiltered cast (R51 class).
type nilKvElementEtcdClient struct{}

func (m *nilKvElementEtcdClient) Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	return &clientv3.GetResponse{
		Kvs: []*mvccpb.KeyValue{nil},
	}, nil
}

func (m *nilKvElementEtcdClient) Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan {
	return nil
}

func (m *nilKvElementEtcdClient) Close() error { return nil }

func TestAttack_LoadCurrentNilKvElementNoPanic(t *testing.T) {
	s := &Syncer{
		client:   &nilKvElementEtcdClient{},
		key:      "/l3-firewall/policy",
		timeout:  200 * time.Millisecond,
		onUpdate: func(string) error { return nil },
		stopCh:   make(chan struct{}),
	}

	// loadCurrent runs on the main goroutine in production (no recover) —
	// a panic there crashes the whole process. Recover here so the RED
	// panic is observable without crashing the test binary.
	panicked := make(chan interface{}, 1)
	done := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panicked <- r
			}
		}()
		s.loadCurrent(context.Background())
		close(done)
	}()

	select {
	case p := <-panicked:
		t.Fatalf("loadCurrent panicked on nil Kv element in Get response: %v", p)
	case <-done:
		// GREEN: nil element skipped with a warning, no panic.
	case <-time.After(2 * time.Second):
		t.Fatal("loadCurrent did not return for a nil-Kv-element Get response")
	}
}

// ── R52b: loadCurrent with a nil GetResponse and nil error ──────────────
// A client implementation (or wire shape) returning (nil, nil) panics on
// resp.Kvs with the same effect: process crash at startup.
type nilResponseEtcdClient struct{}

func (m *nilResponseEtcdClient) Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	return nil, nil
}

func (m *nilResponseEtcdClient) Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan {
	return nil
}

func (m *nilResponseEtcdClient) Close() error { return nil }

func TestAttack_LoadCurrentNilResponseNoPanic(t *testing.T) {
	s := &Syncer{
		client:   &nilResponseEtcdClient{},
		key:      "/l3-firewall/policy",
		timeout:  200 * time.Millisecond,
		onUpdate: func(string) error { return nil },
		stopCh:   make(chan struct{}),
	}

	panicked := make(chan interface{}, 1)
	done := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panicked <- r
			}
		}()
		s.loadCurrent(context.Background())
		close(done)
	}()

	select {
	case p := <-panicked:
		t.Fatalf("loadCurrent panicked on nil GetResponse: %v", p)
	case <-done:
		// GREEN: nil response handled without panic.
	case <-time.After(2 * time.Second):
		t.Fatal("loadCurrent did not return for a nil GetResponse")
	}
}

// ── R52c: healthy Get still applies the policy after the nil-shape guard ─
// The guard must not break the normal path (companion to R46.2b).
type healthyOnceEtcdClient struct {
	value []byte
}

func (s *healthyOnceEtcdClient) Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	return &clientv3.GetResponse{
		Kvs: []*mvccpb.KeyValue{{Key: []byte(key), Value: s.value}},
	}, nil
}

func (s *healthyOnceEtcdClient) Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan {
	return nil
}

func (s *healthyOnceEtcdClient) Close() error { return nil }

func TestAttack_LoadCurrentHealthyStillApplies(t *testing.T) {
	client := &healthyOnceEtcdClient{value: []byte("package l3_firewall")}
	s := &Syncer{
		client:  client,
		key:     "/l3-firewall/policy",
		timeout: 200 * time.Millisecond,
		onUpdate: func(policy string) error {
			if policy != "package l3_firewall" {
				t.Errorf("onUpdate got %q, want %q", policy, "package l3_firewall")
			}
			return nil
		},
		stopCh: make(chan struct{}),
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
