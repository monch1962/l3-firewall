// Red-team security hardening Round 98 — the etcd policy plane's log surface.
//
// Two independent paths let an attacker who controls the policy channel (the
// R51/R52 threat model: a malicious/compromised etcd, or a MITM on a
// plaintext channel) turn the firewall's own logging into the attack:
//
//  1. R98.3 — the reconnect path logs the FULL policy content. When the
//     R65 resync reads a policy that differs from the R63 queued pending
//     policy, the R66 supersession warning prints BOTH strings verbatim.
//     Each can be maxPolicySize (10 MB), so one reconnect cycle writes a
//     ~20 MB log line — and the attacker paces the cycles (a watch cancel
//     every watchReconnectDelay, 100 ms).
//
//  2. R98.4 — the failed-reload path logs an UNBOUNDED error. opa.Load's
//     compile error echoes the offending source line (2–3× the policy), and
//     the watch loop logs err.Error() after every distinct policy that fails
//     to compile. 10 MB in → 20–30 MB out, once per minReloadInterval.
//
// Both are the R96.3 posture ("the first distinct text immediately, the same
// text once per window, a changed text immediately") applied to the loops that
// still log per event — connect() already had it, watch() did not.
package syncer

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/monch1962/l3-firewall/internal/opa"
)

// totalBytes is the size of everything this sink captured — the quantity an
// operator's disk and log shipper actually pay.
func (h *r97Sink) totalBytes() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, l := range h.lines {
		n += len(l)
	}
	return n
}

func (h *r97Sink) find(substr string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, l := range h.lines {
		if strings.Contains(l, substr) {
			out = append(out, l)
		}
	}
	return out
}

func (h *r97Sink) count(substr string) int { return len(h.find(substr)) }

const logPayloadRun = 256 // a 256-byte run of the pad byte is unmistakable

// ── R98.3: supersession must report SIZES, not the policy content ────────
//
// Attack: queue a 1 MiB policy inside the R63 reload window, kill the watch
// stream, let the resync read a different 1 MiB policy. The R66 warning then
// prints both policies. The DETECTION must survive (the operator still needs
// to know a stale pending policy was dropped, and how large the two states
// were) — only the bytes must go.
func TestAttack_ResyncSupersessionMustNotLogPolicyContent(t *testing.T) {
	sink := installR97Sink(t)
	const key = "/test/key"
	const pad = 1 << 20
	queued := "package l3_firewall -- queued\n# " + strings.Repeat("Q", pad)
	current := "package l3_firewall -- current\n# " + strings.Repeat("C", pad)
	const warmup = "package l3_firewall -- warmup" // applied first, arms the rate window

	client := &phaseEtcdClient{
		phases: []clientv3.WatchChan{
			closedWatchChan(
				clientv3.WatchResponse{Events: []*clientv3.Event{putEvent(key, warmup)}},
				clientv3.WatchResponse{Events: []*clientv3.Event{putEvent(key, queued)}},
			), // warmup applied; queued parked in the pending slot; stream dies
			make(chan clientv3.WatchResponse), // blocked: one reconnect, then quiet
		},
		getFn: func(context.Context, string, ...clientv3.OpOption) (*clientv3.GetResponse, error) {
			return getResponse(key, current), nil
		},
	}
	s := &Syncer{
		client:         client,
		key:            key,
		timeout:        time.Second,
		stopCh:         make(chan struct{}),
		reconnectDelay: time.Millisecond,
		onUpdate:       func(string) error { return nil },
	}
	go s.watch(context.Background())
	defer close(s.stopCh)

	if !poll(3*time.Second, func() bool { return sink.count("resync superseded") > 0 }) {
		t.Fatalf("the R66 supersession path never ran (log: %v)", sink.all())
	}

	// The attack: policy bytes reproduced in the log stream.
	if got := sink.totalBytes(); got > 64*1024 {
		t.Errorf("one supersession cycle wrote %d bytes of log for two %d-byte policies — the warning must report SIZES, not content (a hostile etcd paces one cycle per watchReconnectDelay)", got, pad+32)
	}
	for _, marker := range []struct{ name, run string }{
		{"queued", strings.Repeat("Q", logPayloadRun)},
		{"current", strings.Repeat("C", logPayloadRun)},
	} {
		for _, line := range sink.find(marker.run) {
			t.Errorf("the %s policy's content reached the log stream (%d-byte line): %q…", marker.name, len(line), truncateForTest(line, 120))
		}
	}
	// The detection must remain: the warning still fires and still explains
	// what happened. (Asserted structurally: the message text and a size
	// attribute — not prose.)
	if n := sink.count("resync superseded"); n != 1 {
		t.Errorf("supersession warning fired %d times, want exactly 1 (the operator must still be told the stale pending policy was dropped)", n)
	}
}

// ── R98.4: a failed reload must not log the policy source ───────────────
//
// The production wiring (cmd/server) passes opa.Load as the onUpdate
// callback, so this test uses the real evaluator: a policy that fails to
// compile makes OPA echo the offending line and the watch loop log the whole
// error text.
func TestAttack_FailedReloadLogMustBeBounded(t *testing.T) {
	sink := installR97Sink(t)
	evaluator, err := opa.NewEmbedded(opa.EmbedConfig{Policy: "package l3_firewall\n\nallow := true\n"})
	if err != nil {
		t.Fatalf("building the evaluator: %v", err)
	}
	const key = "/test/key"
	bad := "package l3_firewall\n\nallow := true\n\nbad := \"" + strings.Repeat("X", 1<<20) + "\n"

	client := &phaseEtcdClient{
		phases: []clientv3.WatchChan{
			closedWatchChan(clientv3.WatchResponse{Events: []*clientv3.Event{putEvent(key, bad)}}),
			make(chan clientv3.WatchResponse),
		},
	}
	s := &Syncer{
		client:         client,
		key:            key,
		timeout:        time.Second,
		stopCh:         make(chan struct{}),
		reconnectDelay: time.Millisecond,
		onUpdate:       evaluator.Load, // the production callback
	}
	go s.watch(context.Background())
	defer close(s.stopCh)

	if !poll(3*time.Second, func() bool { return sink.count("failed to apply policy update") > 0 }) {
		t.Fatalf("the failed-reload path never logged (log: %v)", sink.all())
	}
	assertReloadFailureLogBounded(t, sink)
}

// The startup path (loadCurrent) logs the same error text and runs
// synchronously in Start(), before the firewall filters anything.
func TestAttack_InitialPolicyLoadFailureLogMustBeBounded(t *testing.T) {
	sink := installR97Sink(t)
	evaluator, err := opa.NewEmbedded(opa.EmbedConfig{Policy: "package l3_firewall\n\nallow := true\n"})
	if err != nil {
		t.Fatalf("building the evaluator: %v", err)
	}
	const key = "/test/key"
	bad := "package l3_firewall\n\nallow := true\n\nbad := \"" + strings.Repeat("X", 1<<20) + "\n"
	client := &phaseEtcdClient{
		getFn: func(context.Context, string, ...clientv3.OpOption) (*clientv3.GetResponse, error) {
			return getResponse(key, bad), nil
		},
	}
	s := &Syncer{
		client:   client,
		key:      key,
		timeout:  time.Second,
		stopCh:   make(chan struct{}),
		onUpdate: evaluator.Load,
	}
	s.loadCurrent(context.Background())

	if sink.count("failed to load initial policy") == 0 {
		t.Fatalf("the initial-load failure never logged (log: %v)", sink.all())
	}
	assertReloadFailureLogBounded(t, sink)
}

func assertReloadFailureLogBounded(t *testing.T, sink *r97Sink) {
	t.Helper()
	if got := sink.totalBytes(); got > 64*1024 {
		t.Errorf("a failed policy reload wrote %d bytes of log (max 64 KiB) — the compile error echoes the policy source, so a 10 MB policy becomes a 20–30 MB log line once per minReloadInterval", got)
	}
	for _, line := range sink.find(strings.Repeat("X", logPayloadRun)) {
		t.Errorf("the rejected policy's content reached the log stream (%d-byte line)", len(line))
	}
	if n := sink.count("rego_parse_error"); n == 0 {
		t.Errorf("the bounded log lost the actionable part — the OPA message (rego_parse_error, file:line) must survive: %v", sink.all())
	}
}

// ── R98.5: the reconnect warning must not fire once per reconnect ───────
//
// connect() already suppresses repeats of the same failure text (R96.3);
// watch() did not. A hostile or over-loaded etcd that cancels EVERY watch
// therefore produced one identical warning per watchReconnectDelay (100 ms) —
// ~10 lines/second, forever, from a stream the firewall has no control over.
type cancelLoopEtcdClient struct {
	mu    sync.Mutex
	watch int
}

func (c *cancelLoopEtcdClient) Get(context.Context, string, ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	return getResponse("/test/key", "package l3_firewall -- stable"), nil
}

func (c *cancelLoopEtcdClient) Watch(context.Context, string, ...clientv3.OpOption) clientv3.WatchChan {
	c.mu.Lock()
	c.watch++
	c.mu.Unlock()
	// clientv3's termination signal: a Canceled response, then a closed channel.
	return closedWatchChan(clientv3.WatchResponse{Canceled: true})
}

func (c *cancelLoopEtcdClient) Close() error { return nil }

func (c *cancelLoopEtcdClient) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.watch
}

func TestAttack_WatchReconnectWarningMustBeThrottled(t *testing.T) {
	sink := installR97Sink(t)
	client := &cancelLoopEtcdClient{}
	s := &Syncer{
		client:         client,
		key:            "/test/key",
		timeout:        time.Second,
		stopCh:         make(chan struct{}),
		reconnectDelay: time.Millisecond,
		onUpdate:       func(string) error { return nil },
	}
	go s.watch(context.Background())
	defer close(s.stopCh)

	// Let a meaningful number of reconnects happen, then look at the cost.
	time.Sleep(300 * time.Millisecond)
	reconnects := client.calls()
	if reconnects < 20 {
		t.Fatalf("only %d watch reconnects in 300 ms — the test cannot judge the log rate", reconnects)
	}
	lines := sink.count("reconnecting")
	if lines == 0 {
		t.Errorf("no reconnect warning at all — the loop must still say it is reconnecting (log: %v)", sink.all())
	}
	if lines > 5 {
		t.Errorf("%d reconnect warnings for %d reconnects — a hostile etcd that cancels every watch turns the warning into a per-event log flood (want <= 5: first, then once per window)", lines, reconnects)
	}
	if got := sink.totalBytes(); got > 8*1024 {
		t.Errorf("reconnect logging wrote %d bytes in 300 ms (max 8 KiB)", got)
	}
}

func getResponse(key, val string) *clientv3.GetResponse {
	return &clientv3.GetResponse{Kvs: []*mvccpb.KeyValue{{Key: []byte(key), Value: []byte(val)}}}
}

func truncateForTest(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ── R98.7: a panic value must not become an unbounded log attribute ─────
//
// safeOnUpdate is the panic guard for an arbitrary onUpdate callback. A
// callback that panics with the policy it was handed — or with any large
// value — otherwise put that value into the log verbatim, once per policy
// event (up to ten times a second at minReloadInterval). The recovered
// panic is a genuine operator signal and must stay visible; only its size
// is bounded.
func TestAttack_PanicValueLogMustBeBounded(t *testing.T) {
	sink := installR97Sink(t)
	big := strings.Repeat("P", 1<<20)
	err := safeOnUpdate(func(string) error { panic(big) }, "policy")
	if err == nil {
		t.Fatal("expected the panic to be recovered and returned as an error")
	}
	if got := sink.totalBytes(); got > 64*1024 {
		t.Errorf("a panicking onUpdate wrote %d bytes of log (max 64 KiB)", got)
	}
	if n := sink.count("recovered panic"); n != 1 {
		t.Errorf("the panic was reported %d times, want exactly 1", n)
	}
	// The operator must still be able to tell how big the value was, even
	// though the bytes are gone (the Truncate marker carries the size).
	if n := sink.count("[1048576 bytes]"); n != 1 {
		t.Errorf("the bounded panic attribute does not carry the original size (got %d such lines): %v", n, sink.all())
	}
}
