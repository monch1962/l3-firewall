// Red-team security hardening Round 49 — NFQUEUE verdict delivery
// integration boundary (engine ↔ go-nfqueue v1.3.2) + nil-payload
// fail-open sibling of the R40 parse-error fix.
//
// The go-nfqueue library contract (v1.3.2, verified in its own
// integration tests and ExampleNfqueue_RegisterWithErrorFunc): the hook
// function MUST call nf.SetVerdict(*attr.PacketID, verdict) itself, and
// its return value is RECEIVE-LOOP CONTROL, not a verdict —
//
//	if ret := fn(m); ret != 0 { return }
//
// non-zero STOPS the socketCallback loop.
//
// The engine's Run() hook was `return e.packetHandler(attr)` — the 0/1
// return was assumed to be NF_ACCEPT/NF_DROP (the R10/R16/R40 named-return
// fail-closed machinery is built on that assumption) but the kernel never
// received any verdict. Consequences in production:
//  1. no packet is ever verdicted — every queued packet stays queued until
//     MaxQueueLen (1024) fills and the kernel drops all new traffic
//     (accidental total outage; the deny-override allow-by-default model
//     can never allow anything);
//  2. the FIRST blocked packet (ret=1) terminates the receive loop
//     permanently — the firewall goes deaf to the queue while
//     eng.running still reports true.
package engine

import (
	"net"
	"sync"
	"testing"

	"github.com/florianl/go-nfqueue"
	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
)

// verdictCall records one SetVerdict delivery to the (fake) kernel queue.
type verdictCall struct {
	id      uint32
	verdict int
}

// fakeVerdictSender records SetVerdict calls instead of talking to the
// kernel, proving what the hook delivers.
type fakeVerdictSender struct {
	mu       sync.Mutex
	verdicts []verdictCall
}

func (f *fakeVerdictSender) SetVerdict(id uint32, verdict int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verdicts = append(f.verdicts, verdictCall{id: id, verdict: verdict})
	return nil
}

func (f *fakeVerdictSender) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.verdicts)
}

// blockedEngine returns an engine configured to block every packet
// deterministically: nil evaluator + fail-closed mode.
func blockedEngine() *Engine {
	return New(nil, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(0, 0),
		true, false, nil, nil, nil, nil, nil, "", nil)
}

// ── R49.1: NFQUEUE verdict never sent to the kernel ───────────────
// The kernel never receives NF_ACCEPT/NF_DROP for any packet: the hook
// return value is treated by go-nfqueue as receive-loop control
// (non-zero stops the loop), so (a) queued packets are never verdicted
// and the queue fills until the kernel drops all traffic, and (b) the
// first blocked packet (ret=1) kills the receive loop entirely. A
// security device whose verdicts never reach the kernel enforces
// nothing — the deny-override model silently becomes total outage.
func TestAttack_NFQUEUEVerdictNeverSent(t *testing.T) {
	eng := blockedEngine()
	fake := &fakeVerdictSender{}

	payload := buildTestTCPPacket(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 12345, 22, true, false, false, false)
	id := uint32(42)
	attr := nfqueue.Attribute{Payload: &payload, PacketID: &id}

	ret := eng.handleQueuePacket(fake, attr)

	if got := fake.count(); got != 1 {
		t.Fatalf("verdict never sent to kernel: %d SetVerdict call(s), want 1 — the firewall decides but the kernel is never told; queued packets saturate the queue and all traffic is dropped", got)
	}
	if fake.verdicts[0].id != id {
		t.Errorf("verdict id = %d, want %d", fake.verdicts[0].id, id)
	}
	if fake.verdicts[0].verdict != nfqueue.NfDrop {
		t.Errorf("verdict = %d, want NfDrop (%d) for a blocked packet", fake.verdicts[0].verdict, nfqueue.NfDrop)
	}
	if ret != 0 {
		t.Errorf("hook return = %d, want 0 — go-nfqueue treats non-zero as 'stop the receive loop'; the first blocked packet kills the whole packet path", ret)
	}
}

// ── R49.2: blocked verdict must be NfDrop; allowed must be NfAccept ─
func TestAttack_NFQUEUEVerdictAcceptAllowed(t *testing.T) {
	// fail-closed engine still allows nothing; use an audit-only engine
	// (blocks are logged but allowed) to produce an NF_ACCEPT decision.
	eng := New(nil, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(0, 0),
		false, true, nil, nil, nil, nil, nil, "", nil)
	fake := &fakeVerdictSender{}

	payload := buildTestTCPPacket(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 12345, 22, true, false, false, false)
	id := uint32(7)
	attr := nfqueue.Attribute{Payload: &payload, PacketID: &id}

	ret := eng.handleQueuePacket(fake, attr)

	if got := fake.count(); got != 1 {
		t.Fatalf("verdict never sent to kernel: %d SetVerdict call(s), want 1", got)
	}
	if fake.verdicts[0].verdict != nfqueue.NfAccept {
		t.Errorf("verdict = %d, want NfAccept (%d) for an allowed packet", fake.verdicts[0].verdict, nfqueue.NfAccept)
	}
	if ret != 0 {
		t.Errorf("hook return = %d, want 0 (keep the receive loop alive)", ret)
	}
}

// ── R49.3: nil payload is accepted (fail-open sibling of R40) ─────
// R40 made unparseable packets DROP (fail-closed), but the guard above
// it still ACCEPTS a packet with no payload at all — the most
// uninspectable case of all. For a security device, a nil payload must
// mean DROP like any other unparseable packet.
func TestAttack_NilPayloadFailOpen(t *testing.T) {
	eng := blockedEngine()
	attr := nfqueue.Attribute{} // Payload nil, PacketID nil
	if ret := eng.packetHandler(attr); ret != 1 {
		t.Errorf("nil-payload verdict = %d (want 1 = DROP); an uninspectable packet is accepted, bypassing every policy layer", ret)
	}
}
