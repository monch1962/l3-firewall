package syncer

import (
	"context"
	"testing"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// ── R51.2: malformed watch event (nil Kv / nil Event) panics the watch
// goroutine → whole-process crash ──────────────────────────────────────────
//
// The watch loop dereferences ev.Kv.Value without a nil check. etcd
// clientv3 casts wire protobuf events straight into *mvccpb.Event pointers
// without filtering, so a malicious or compromised etcd server (or a MITM
// on the plaintext etcd connection — syncer.Config wires no TLS) can send
// {"events":[{"kv":null}]} or {"events":[null]} and the syncer's watch
// goroutine panics. The panic is NOT recovered (only the onUpdate callback
// is wrapped in safeOnUpdate), so the whole process crashes: a remote DoS
// against the firewall's control-plane dependency.
//
// R13 hardened the watch path's maxPolicySize check and R9 the callback,
// but the event-shape itself was never validated.

// maliciousEtcdClient returns a watch channel that emits a single watch
// response whose event carries a nil Kv (the shape a malformed wire
// response produces after clientv3's cast).
type maliciousEtcdClient struct{}

func (m *maliciousEtcdClient) Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	return &clientv3.GetResponse{}, nil
}

func (m *maliciousEtcdClient) Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan {
	ch := make(chan clientv3.WatchResponse, 1)
	// Event is present but its Kv field is nil — ev.Kv.Value panics.
	ch <- clientv3.WatchResponse{
		Events: []*clientv3.Event{{Type: mvccpb.DELETE, Kv: nil}},
	}
	close(ch)
	return ch
}

func (m *maliciousEtcdClient) Close() error { return nil }

func TestAttack_WatchEventNilKvNoPanic(t *testing.T) {
	s := &Syncer{
		client:  &maliciousEtcdClient{},
		key:     "/test/key",
		timeout: time.Second,
		stopCh:  make(chan struct{}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run watch() in a goroutine with a recover so an unrecovered panic
	// in production (whole-process crash) surfaces here as a panic we can
	// observe without killing the test binary. The loop ends via stopCh:
	// since R65 the loop survives channel closes (it reconnects — the
	// stub replays the same malformed events, which are skipped again),
	// so the test stops it explicitly after the first cycle.
	panicked := make(chan bool, 1)
	go func() {
		defer func() {
			panicked <- recover() != nil
		}()
		s.watch(ctx)
	}()

	time.Sleep(300 * time.Millisecond) // deliver the malformed response + a reconnect cycle
	close(s.stopCh)
	if p := <-panicked; p {
		t.Error("watch goroutine panicked on nil-Kv event: a malformed etcd watch response crashes the firewall")
	}
}

// The nil-Event variant: the events array itself contains a nil pointer
// ({"events":[null]}), which makes ev.Kv panic on a nil dereference of ev.
type nilEventEtcdClient struct{}

func (n *nilEventEtcdClient) Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	return &clientv3.GetResponse{}, nil
}

func (n *nilEventEtcdClient) Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan {
	ch := make(chan clientv3.WatchResponse, 1)
	ch <- clientv3.WatchResponse{
		Events: []*clientv3.Event{nil},
	}
	close(ch)
	return ch
}

func (n *nilEventEtcdClient) Close() error { return nil }

func TestAttack_WatchEventNilEventNoPanic(t *testing.T) {
	s := &Syncer{
		client:  &nilEventEtcdClient{},
		key:     "/test/key",
		timeout: time.Second,
		stopCh:  make(chan struct{}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The loop ends via stopCh (R65: the loop survives channel closes —
	// it reconnects, and the stub replays the same nil-event batch, which
	// is skipped again).
	panicked := make(chan bool, 1)
	go func() {
		defer func() {
			panicked <- recover() != nil
		}()
		s.watch(ctx)
	}()

	time.Sleep(300 * time.Millisecond) // deliver the malformed response + a reconnect cycle
	close(s.stopCh)
	if p := <-panicked; p {
		t.Error("watch goroutine panicked on nil event: a malformed etcd watch response crashes the firewall")
	}
}

// Positive regression: a normal PUT event still flows through the callback.
type putEventEtcdClient struct{}

func (p *putEventEtcdClient) Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	return &clientv3.GetResponse{}, nil
}

func (p *putEventEtcdClient) Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan {
	ch := make(chan clientv3.WatchResponse, 1)
	ch <- clientv3.WatchResponse{
		Events: []*clientv3.Event{{
			Type: mvccpb.PUT,
			Kv:   &mvccpb.KeyValue{Key: []byte("/test/key"), Value: []byte("package l3_firewall")},
		}},
	}
	close(ch)
	return ch
}

func (p *putEventEtcdClient) Close() error { return nil }

func TestAttack_WatchEventNormalPutStillApplies(t *testing.T) {
	got := make(chan string, 1)
	s := &Syncer{
		client:  &putEventEtcdClient{},
		key:     "/test/key",
		timeout: time.Second,
		stopCh:  make(chan struct{}),
		onUpdate: func(policy string) error {
			got <- policy
			return nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.watch(ctx)
	}()

	select {
	case p := <-got:
		if p != "package l3_firewall" {
			t.Errorf("unexpected policy %q", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("onUpdate not called for normal PUT event")
	}
	// The loop ends via stopCh (R65: the loop survives channel closes —
	// it reconnects, and the stub replays the same PUT event, which the
	// content dedupe skips). Stop it after the event is delivered.
	time.Sleep(300 * time.Millisecond)
	close(s.stopCh)
	<-done
}
