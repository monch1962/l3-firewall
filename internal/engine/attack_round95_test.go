// Red-team security hardening Round 95 — control-plane truthfulness:
// the firewall's SELF-REPORT is not the firewall's state.
//
// `/admin/health` (documented as the liveness/readiness probe) reports
// `{"status":"ok","engine_running":<Running()>}`, and `Running()` is the
// engine's only statement about whether packets are being inspected. But
// `running` is set once in Run() after the NFQUEUE registration succeeds and
// cleared only after <-ctx.Done() — i.e. only on a deliberate shutdown. The
// receive loop itself lives in a separate goroutine inside go-nfqueue:
//
//	for { ... if ret := errfn(err); ret != 0 { return }
//	          for _, msg := range replys { ... if ret := fn(m); ret != 0 { return } } }
//
// THREE production-reachable conditions make that goroutine return:
//
//  1. the verdict hook returns non-zero — `handleQueuePacket` does this when
//     `nf.SetVerdict` FAILS (ENOBUFS on the netlink socket under memory
//     pressure, or a packet id the kernel no longer honours);
//  2. the verdict hook returns non-zero because the attribute carries no
//     PacketID (a hostile/buggy kernel frame — R49);
//  3. the error function returns non-zero for a non-transient netlink error
//     (socket closed, kernel module unloaded, a flood of ENOBUFS).
//
// In every one of those cases the library's deferred unbind removes the queue
// handler, so netfilter has NO listener: queued packets are dropped (R83
// measured exactly this shape) — the firewall becomes a total outage — while
// `running` stays true and `/admin/health` keeps answering "ok". Nothing the
// engine exposes can be used to detect it, so a supervisor never restarts the
// process and the outage is permanent and silent.
package engine

import (
	"errors"
	"os"
	"testing"

	"github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"
)

// ── R95.1: a failed verdict delivery stops the receive loop, and the engine
// still reports itself Running. `SetVerdict` failure is attacker-reachable: a
// packet flood under memory pressure yields ENOBUFS on the verdict socket, and
// one such failure ends the loop for the life of the process.
func TestAttack_VerdictFailureLeavesEngineReportingRunning(t *testing.T) {
	eng := blockedEngine()
	eng.running.Store(true) // the engine has registered and is serving the queue

	id := uint32(7)
	attr := nfqueue.Attribute{PacketID: &id} // nil payload → DROP decision → NfDrop verdict
	nf := &fakeVerdictSender{err: errors.New("send: no buffer space available")}

	if stop := eng.handleQueuePacket(nf, attr); stop == 0 {
		t.Fatalf("setup: expected the hook to stop the receive loop when the verdict cannot be delivered, got 0")
	}
	if eng.Running() {
		t.Errorf("engine reports Running()==true after the NFQUEUE verdict failed and the receive loop stopped: " +
			"the library has unbound the queue, netfilter drops every queued packet (total outage) and " +
			"/admin/health keeps answering {\"status\":\"ok\"} — a firewall that is not filtering must not " +
			"report that it is")
	}
}

// ── R95.2: a frame with no PacketID also stops the loop (R49 contract) and
// likewise leaves the engine reporting itself Running.
func TestAttack_MissingPacketIDLeavesEngineReportingRunning(t *testing.T) {
	eng := blockedEngine()
	eng.running.Store(true)

	if stop := eng.handleQueuePacket(&fakeVerdictSender{}, nfqueue.Attribute{}); stop == 0 {
		t.Fatalf("setup: expected the hook to stop the receive loop when PacketID is missing, got 0")
	}
	if eng.Running() {
		t.Errorf("engine reports Running()==true after the receive loop stopped on a PacketID-less frame")
	}
}

// ── R95.3: the receive-error decision must distinguish the transient case
// (continue processing) from the stop case, and the stop case must be visible
// in Running().
func TestAttack_ReceiveErrorStopIsVisibleInRunningState(t *testing.T) {
	// Stop decision: a non-transient netlink error.
	eng := blockedEngine()
	eng.running.Store(true)
	if stop := eng.handleReceiveError(errors.New("netlink: socket closed")); stop != 1 {
		t.Fatalf("non-transient receive error: errfn returned %d, want 1 (stop the loop)", stop)
	}
	if eng.Running() {
		t.Errorf("engine still reports Running()==true after the receive loop stopped on a non-transient error: " +
			"no listener remains on the queue, so every packet is dropped, while self-report says healthy")
	}

	// Transient decision: a read timeout must keep processing AND keep running.
	eng2 := blockedEngine()
	eng2.running.Store(true)
	transient := &netlink.OpError{Op: "receive", Err: os.ErrDeadlineExceeded}
	if stop := eng2.handleReceiveError(transient); stop != 0 {
		t.Fatalf("transient receive timeout: errfn returned %d, want 0 (keep the loop alive)", stop)
	}
	if !eng2.Running() {
		t.Errorf("transient receive timeout cleared Running(): a timeout is not a stopped receive loop")
	}
}

// ── R95.4: regression guard — a delivered verdict keeps the loop alive and the
// engine running, so the fix cannot degrade into "any packet stops the loop".
func TestAttack_SuccessfulVerdictKeepsEngineRunning(t *testing.T) {
	eng := blockedEngine()
	eng.running.Store(true)

	id := uint32(9)
	attr := nfqueue.Attribute{PacketID: &id}
	if stop := eng.handleQueuePacket(&fakeVerdictSender{}, attr); stop != 0 {
		t.Fatalf("hook return = %d, want 0 (keep the receive loop alive)", stop)
	}
	if !eng.Running() {
		t.Errorf("engine stopped reporting Running() after a successfully delivered verdict")
	}
}
