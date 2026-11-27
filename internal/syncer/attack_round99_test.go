// Red-team security hardening Round 99 — the etcd policy plane's per-EVENT log
// surface (the R98 class not propagated inside watch()).
//
// R98 hardened the log surface of the policy plane: the supersession warning,
// the failed-reload error, the panic value, the reconnect warnings and the
// resync trace were all bounded and throttled by a CONSTANT site key. It swept
// the *terminating* and *reload* paths — and stopped there. The event loop in
// watch() still logs three PER-EVENT drop paths with no throttle at all, plus
// one PER-RESPONSE path:
//
//	event with a nil KeyValue      → "watch event missing key/value, skipping"
//	DELETE event                   → "policy key deleted, keeping last applied policy"
//	event over maxPolicySize       → "policy update exceeds max size, skipping"
//	response over 10 000 events    → "watch response carries excessive events…"
//
// The event COUNT is bounded (maxWatchEventsPerResponse = 10 000) but every
// event still writes one log line, so ONE wire response within clientv3's
// receive limit writes 10 000 lines — and the attacker who controls the policy
// channel (the R51/R52 threat model: a malicious/compromised etcd, or a MITM
// on the plaintext channel) paces the responses. That is the R96.3 shape
// ("per-event logging IS the DoS") on the goroutine that must keep applying
// policy: 10 000 × ~3 µs of handler time per response (~30 ms), plus disk/log
// shipper volume — the R98 fix's own rationale, in the same function.
package syncer

import (
	"context"
	"testing"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// floodClient serves a fixed sequence of pre-built WatchResponses, one per
// reconnect, then blocks — the phaseEtcdClient pattern without per-test
// plumbing.
func floodSyncer(t *testing.T, phases ...clientv3.WatchChan) *Syncer {
	t.Helper()
	client := &phaseEtcdClient{
		phases: phases,
		getFn: func(context.Context, string, ...clientv3.OpOption) (*clientv3.GetResponse, error) {
			// Resync reads a stable policy unrelated to the flood.
			return getResponse("/test/key", "package l3_firewall -- stable"), nil
		},
	}
	s := &Syncer{
		client:         client,
		key:            "/test/key",
		timeout:        time.Second,
		stopCh:         make(chan struct{}),
		reconnectDelay: time.Millisecond,
		onUpdate:       func(string) error { return nil },
	}
	go s.watch(context.Background())
	t.Cleanup(func() { close(s.stopCh) })
	return s
}

const floodEvents = 10000 // exactly maxWatchEventsPerResponse: no collapse, every event processed

// ── R99.1: a DELETE-event flood must not write one log line per event ──────
// One watch response carrying `floodEvents` DELETE events (DELETE carries no
// value, so R61 skips it — with a warning, per event). Pre-fix: 10 000 lines
// per response, attacker-paced.
func TestAttack_WatchDeleteEventFloodMustBeThrottled(t *testing.T) {
	sink := installR97Sink(t)
	events := make([]*clientv3.Event, floodEvents)
	for i := range events {
		events[i] = &clientv3.Event{Type: mvccpb.DELETE, Kv: &mvccpb.KeyValue{Key: []byte("/test/key")}}
	}
	floodSyncer(t, closedWatchChan(clientv3.WatchResponse{Events: events}), make(chan clientv3.WatchResponse))

	if !poll(3*time.Second, func() bool { return sink.count("policy key deleted") > 0 }) {
		t.Fatalf("the delete path never logged at all (log: %v)", sink.all())
	}
	// Let the (fast) loop finish consuming the batch.
	time.Sleep(100 * time.Millisecond)

	if got := sink.count("policy key deleted"); got > 3 {
		t.Errorf("one %d-event DELETE response wrote %d log lines — the delete path must be throttled by a CONSTANT site key (first occurrence immediate, repeats once per window); a hostile etcd paces these responses, so per-event logging is a log/disk DoS (the R96.3/R98 posture)", floodEvents, got)
	}
}

// ── R99.2: a nil-KeyValue event flood must not write one line per event ────
// clientv3 casts wire events into *Event without filtering, so a malformed or
// malicious response can carry any number of events whose Kv is nil (R51's
// nil-shape guard). The guard is correct; logging it once per event is not.
func TestAttack_WatchNilKvEventFloodMustBeThrottled(t *testing.T) {
	sink := installR97Sink(t)
	events := make([]*clientv3.Event, floodEvents)
	for i := range events {
		events[i] = &clientv3.Event{Type: mvccpb.PUT} // Kv == nil
	}
	floodSyncer(t, closedWatchChan(clientv3.WatchResponse{Events: events}), make(chan clientv3.WatchResponse))

	if !poll(3*time.Second, func() bool { return sink.count("missing key/value") > 0 }) {
		t.Fatalf("the nil-Kv guard never logged (log: %v)", sink.all())
	}
	time.Sleep(100 * time.Millisecond)

	if got := sink.count("missing key/value"); got > 3 {
		t.Errorf("one %d-event nil-Kv response wrote %d log lines — the malformed-event guard must be throttled by a constant site key, or a hostile etcd turns the guard into a log flood", floodEvents, got)
	}
}

// ── R99.3: an oversize-value event flood must not write one line per event ──
// Each event over maxPolicySize is skipped (correct: check-before-allocate,
// R42/R54) but logged. The `size` attribute is attacker-chosen, so the text
// is not even stable — the R98 rule is to throttle by the CONSTANT site key
// and keep the value inside the (bounded) line.
func TestAttack_WatchOversizeEventFloodMustBeThrottled(t *testing.T) {
	sink := installR97Sink(t)
	const n = 4
	big := make([]byte, maxPolicySize+1)
	events := make([]*clientv3.Event, n)
	for i := range events {
		events[i] = &clientv3.Event{Type: mvccpb.PUT, Kv: &mvccpb.KeyValue{Key: []byte("/test/key"), Value: big}}
	}
	floodSyncer(t, closedWatchChan(clientv3.WatchResponse{Events: events}), make(chan clientv3.WatchResponse))

	if !poll(3*time.Second, func() bool { return sink.count("exceeds max size") > 0 }) {
		t.Fatalf("the oversize guard never logged (log: %v)", sink.all())
	}
	time.Sleep(100 * time.Millisecond)

	if got := sink.count("exceeds max size"); got > 1 {
		t.Errorf("%d oversize events wrote %d log lines — the skip must be reported once per window, not once per event (the attacker paces the events)", n, got)
	}
}

// ── R99.4: the excessive-event-count warning must not fire per response ────
// The count bound collapses an oversized response to its last event (R61) —
// but the collapse warning itself is per RESPONSE. A hostile etcd sends
// oversized responses continuously, so this is the same per-event shape one
// level up. Reported by a constant site key so a *change* (normal → oversized)
// is still immediate while a sustained stream is one line per window.
func TestAttack_WatchExcessiveEventCountWarningMustBeThrottled(t *testing.T) {
	sink := installR97Sink(t)
	// One shared event pointer: the loop only reads it.
	put := putEvent("/test/key", "package l3_firewall -- flood")
	oversized := make([]*clientv3.Event, maxWatchEventsPerResponse+1)
	for i := range oversized {
		oversized[i] = put
	}
	const responses = 5
	phases := make([]clientv3.WatchChan, 0, responses+1)
	for i := 0; i < responses; i++ {
		phases = append(phases, closedWatchChan(clientv3.WatchResponse{Events: oversized}))
	}
	phases = append(phases, make(chan clientv3.WatchResponse)) // park the loop
	floodSyncer(t, phases...)

	if !poll(3*time.Second, func() bool { return sink.count("excessive events") > 0 }) {
		t.Fatalf("the oversized-response warning never fired (log: %v)", sink.all())
	}
	time.Sleep(150 * time.Millisecond)

	if got := sink.count("excessive events"); got > 2 {
		t.Errorf("%d oversized responses wrote %d warnings — a hostile etcd streams these, so the warning must be throttled by its constant site key", responses, got)
	}
	// The operator must still be told how bad the response was (the collapse
	// hides real state, so the count attribute has to survive).
	if got := sink.count("count=10001"); got == 0 {
		t.Errorf("the throttled warning lost the event count (an operator cannot tell a 10 001-event response from a 400 000-event one): %v", sink.all())
	}
}
