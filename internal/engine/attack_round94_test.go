package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/packet"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
)

// ── R94 (engine integration): the connection facts the SHIPPED policy judges
// are produced by conntrack.UpdateTCPState. See
// internal/conntrack/attack_round94_test.go for the unit-level finding.
//
// These tests drive the real production path — Engine.evaluatePacket → the
// shipped opa-policies/l3.rego — so a packet stopped by an unrelated rule
// cannot pass as "not allowed" and mask the defect.

// r94Step paces packets so the engine's OWN rate signals stay below the shipped
// policy's thresholds: RULE 3 blocks a SYN above 100 pps and RULE 14 blocks
// above 500 pps to one destination port, and the EWMA's first samples are
// instantaneous rates. 20ms spacing converges well under both (≈50 pps).
func r94Step() { time.Sleep(20 * time.Millisecond) }

func r94pi(flags packet.TCPFlags) *packet.PacketInfo {
	return &packet.PacketInfo{
		SrcIP: "10.0.1.100", DstIP: "10.0.2.50", Protocol: "TCP",
		SrcPort: 44001, DstPort: 443, PacketSize: 64, TCPFlags: flags,
	}
}

// ── R94.1: a legitimate TCP teardown is blocked by the shipped policy ──────
// deny_state_violation ("RST to non-existent flow") fires for EVERY RST: the
// engine reads flow.Established AFTER UpdateTCPState already applied the RST
// transition, which clears it. Measured pre-fix: the RST that closes a fully
// established connection is dropped, so a peer is never told the connection is
// gone (it waits out the 300s TCP idle timeout), "connection refused" never
// reaches a client, and every half-closed flow occupies a conntrack slot for
// the full timeout — the stateful control is a blanket RST block that logs a
// reason it cannot possibly have determined.
func TestAttack_LegitRSTTeardownIsNotBlocked(t *testing.T) {
	eng := newPolicyEngine(t)

	if res := eng.evaluatePacket(r94pi(packet.TCPFlags{SYN: true}), 64); !res.Allowed {
		t.Fatalf("setup: SYN blocked (%q)", res.Reason)
	}
	r94Step()
	if res := eng.evaluatePacket(r94pi(packet.TCPFlags{SYN: true, ACK: true}), 64); !res.Allowed {
		t.Fatalf("setup: SYN+ACK blocked (%q)", res.Reason)
	}
	r94Step()
	if res := eng.evaluatePacket(r94pi(packet.TCPFlags{ACK: true}), 64); !res.Allowed {
		t.Fatalf("setup: ACK blocked (%q)", res.Reason)
	}
	r94Step()

	res := eng.evaluatePacket(r94pi(packet.TCPFlags{RST: true}), 64)
	if !res.Allowed {
		t.Errorf("the RST closing an ESTABLISHED connection was blocked (%q): the flow is judged "+
			"after its own transition has cleared Established, so RULE 8 denies every TCP reset — "+
			"legitimate teardowns never reach the peer and half-closed flows hold conntrack slots "+
			"for the full idle timeout", res.Reason)
	}
}

// ── R94.2: the blind-RST control RULE 8 exists for must still fire ─────────
// Regression guard for the R94.1 fix: a RST on a 5-tuple the firewall has never
// seen is the unsolicited-teardown attack, and it must stay blocked.
func TestAttack_BlindRSTIsStillBlocked(t *testing.T) {
	eng := newPolicyEngine(t)
	res := eng.evaluatePacket(r94pi(packet.TCPFlags{RST: true}), 64)
	if res.Allowed {
		t.Fatalf("a RST on an unseen 5-tuple was ALLOWED: the stateful RST control is gone")
	}
	if !strings.Contains(res.Reason, "connection state violation") {
		t.Errorf("blind RST blocked for %q, want the connection state violation reason", res.Reason)
	}
}

// ── R94.3: one ACK packet must not fabricate "established" ─────────────────
// Any policy keyed on input.connection.established (the natural "trust
// established flows" rule) is bypassed by a single handshake-less ACK today.
func TestAttack_MidStreamACKCannotFabricateEstablished(t *testing.T) {
	probe := &scanProbeEval{}
	eng := New(probe, conntrack.NewTable(conntrack.DefaultConfig()), ratelimit.NewLimiter(0, 0),
		false, false, nil, nil, nil, nil, nil, "", nil)

	eng.evaluatePacket(r94pi(packet.TCPFlags{ACK: true}), 64)

	if probe.lastInput == nil {
		t.Fatal("the evaluator was never called")
	}
	if probe.lastInput.Connection.Established {
		t.Errorf("a bare ACK with no observed handshake produced connection.established=true "+
			"(tcp_state=%q): one spoofed packet fabricates an established flow, so any policy "+
			"trusting the fact is bypassed", probe.lastInput.Connection.TCPState)
	}
}

// ── R94.4: a completed handshake must reach the policy as established ──────
// The mirror image of R94.3: the fact must be true when it IS true, otherwise
// the stateful policy plane (and every operator rule built on it) is inert.
func TestAttack_RealHandshakeReachesPolicyAsEstablished(t *testing.T) {
	probe := &scanProbeEval{}
	eng := New(probe, conntrack.NewTable(conntrack.DefaultConfig()), ratelimit.NewLimiter(0, 0),
		false, false, nil, nil, nil, nil, nil, "", nil)

	eng.evaluatePacket(r94pi(packet.TCPFlags{SYN: true}), 64)
	eng.evaluatePacket(r94pi(packet.TCPFlags{SYN: true, ACK: true}), 64)
	// The next packet is the first one that can be judged on the completed
	// handshake.
	eng.evaluatePacket(r94pi(packet.TCPFlags{ACK: true}), 64)

	if probe.lastInput == nil {
		t.Fatal("the evaluator was never called")
	}
	if !probe.lastInput.Connection.Established {
		t.Errorf("after SYN→SYN-ACK→ACK the policy input reports connection.established=false "+
			"(tcp_state=%q): a real three-way handshake never establishes the flow, so no stateful "+
			"rule can ever trust it", probe.lastInput.Connection.TCPState)
	}
	if probe.lastInput.Connection.TCPState != "ESTABLISHED" {
		t.Errorf("after a completed handshake tcp_state=%q, want ESTABLISHED",
			probe.lastInput.Connection.TCPState)
	}
}
