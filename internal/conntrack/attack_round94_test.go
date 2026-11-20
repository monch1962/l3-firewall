package conntrack

import "testing"

// ── R94: the policy-facing connection facts must be the facts the packet is
// judged ON, and "established" must mean a handshake was observed ───────────
//
// Two defects, both in the same producer (conntrack.UpdateTCPState → the
// engine's OPA input):
//
//  1. The engine read flow.Established / flow.TCPState AFTER the state machine
//     had already applied the CURRENT packet's flags. For a RST the transition
//     clears Established, so every RST was judged as `established: false` and
//     the shipped policy's RULE 8 ("RST to non-existent flow") denied EVEN the
//     teardown of a fully established connection. l3_test.rego's
//     test_state_violation_rst_established_ok pins the intended contract; no
//     Go producer could ever satisfy it (the R76/R77 dead-control class).
//  2. The FSM fabricated the fact in the other direction: a flow first seen
//     with a bare ACK was marked Established by the `case ack` arm (its default
//     state is SYN_SENT), so ONE handshake-less packet produced
//     `established: true` — while a REAL SYN→SYN-ACK handshake never did,
//     because the SYN arm demoted the new flow to SYN_RECEIVED and the SYN-ACK
//     arm only promotes from SYN_SENT.

// r94Handshake establishes a flow the way the current FSM can (a SYN-ACK seen
// on a fresh 5-tuple) so the arrival-snapshot assertion below is isolated from
// the FSM defect covered by R94.3.
func r94EstablishedFlow(t *testing.T, ct *Table) {
	t.Helper()
	f, _ := ct.UpdateTCPState("10.0.1.100", "10.0.2.50", "TCP", 44001, 443, true, true, false, false)
	if !f.Established {
		t.Fatalf("setup: SYN+ACK on a fresh flow did not establish it (state %s)", f.TCPState)
	}
}

// ── R94.1: the arrival snapshot is taken BEFORE the packet's transition ──────
// Attacker view: the firewall drops every TCP reset, so a peer can never be
// told a connection is gone; from the operator's side the stateful control is
// a blanket RST block wearing the label "RST to non-existent flow".
func TestAttack_ArrivalStateIsPreTransition(t *testing.T) {
	ct := NewTable(DefaultConfig())
	r94EstablishedFlow(t, ct)

	// The teardown RST. Applying it closes the flow — but the packet must be
	// JUDGED with the state it arrived in.
	f, arrival := ct.UpdateTCPState("10.0.1.100", "10.0.2.50", "TCP", 44001, 443, false, false, true, false)

	if !arrival.Established {
		t.Errorf("RST arrival reported established=false: the engine hands this to OPA, so RULE 8 " +
			"deny_state_violation denies the legitimate teardown of an ESTABLISHED connection")
	}
	if arrival.TCPState != TCPEstablished {
		t.Errorf("RST arrival reported tcp_state=%s, want ESTABLISHED (the state it arrived in)", arrival.TCPState)
	}
	// Regression: the flow's CURRENT state must still reflect the close.
	if f.TCPState != TCPClosed || f.Established {
		t.Errorf("after RST the flow is %s (established=%v), want CLOSED/false", f.TCPState, f.Established)
	}
}

// ── R94.2: a handshake-less packet must not fabricate "established" ─────────
// A policy that trusts input.connection.established (the natural "let
// established flows through" rule) would be bypassed by ONE ACK packet.
func TestAttack_BareACKDoesNotEstablishFlow(t *testing.T) {
	ct := NewTable(DefaultConfig())

	f, arrival := ct.UpdateTCPState("10.0.1.100", "10.0.2.50", "TCP", 44001, 443, false, true, false, false)
	if f.Established || arrival.Established {
		t.Errorf("a bare ACK with no handshake reported established=true (current=%v arrival=%v): "+
			"one spoofed ACK fabricates an established flow for any policy keyed on the fact",
			f.Established, arrival.Established)
	}
	if arrival.New != true {
		t.Errorf("arrival.New = %v, want true (this packet created the flow)", arrival.New)
	}
	// A second bare ACK must not "confirm" it either.
	f2, _ := ct.UpdateTCPState("10.0.1.100", "10.0.2.50", "TCP", 44001, 443, false, true, false, false)
	if f2.Established {
		t.Error("a second bare ACK established the flow")
	}
}

// ── R94.3: a real handshake must establish the flow ────────────────────────
// The client-initiated path (SYN → SYN-ACK → ACK) never reached ESTABLISHED:
// the SYN arm demoted the fresh flow to SYN_RECEIVED, and the SYN-ACK arm only
// promotes from SYN_SENT. The fact was therefore unreachable on the only path
// a real connection takes.
func TestAttack_RealHandshakeEstablishesFlow(t *testing.T) {
	ct := NewTable(DefaultConfig())

	ct.UpdateTCPState("10.0.1.100", "10.0.2.50", "TCP", 44001, 443, true, false, false, false) // SYN
	f, arrival := ct.UpdateTCPState("10.0.1.100", "10.0.2.50", "TCP", 44001, 443, true, true, false, false)

	if arrival.Established {
		t.Error("the SYN+ACK that COMPLETES the handshake reported established=true on arrival: " +
			"the connection was not established until this packet was applied")
	}
	if !f.Established {
		t.Errorf("after SYN→SYN-ACK the flow is %s (established=false): a completed three-way "+
			"handshake never establishes the flow, so no policy can ever see the truth", f.TCPState)
	}

	// The next packet IS judged on an established flow.
	_, arrival2 := ct.UpdateTCPState("10.0.1.100", "10.0.2.50", "TCP", 44001, 443, false, true, false, false)
	if !arrival2.Established {
		t.Error("the ACK after SYN→SYN-ACK arrived on a flow that is not established")
	}
}

// ── R94.4: the blind-RST control still fires ───────────────────────────────
// Regression guard for the fix: a RST on a 5-tuple the firewall has never seen
// must still arrive as established=false (the attack RULE 8 exists for).
func TestAttack_BlindRSTArrivesUnestablished(t *testing.T) {
	ct := NewTable(DefaultConfig())
	_, arrival := ct.UpdateTCPState("10.0.9.9", "10.0.2.50", "TCP", 50000, 443, false, false, true, false)
	if arrival.Established {
		t.Error("a RST on an unseen 5-tuple reported established=true")
	}
	if !arrival.New {
		t.Error("a RST on an unseen 5-tuple did not report that it created the flow")
	}
}
