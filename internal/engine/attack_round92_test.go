package engine

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/packet"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
)

// ── R92.1 (engine integration): end-to-end proof of the AH bypass ───────────
// See internal/packet/attack_round92_test.go for the parser-layer finding.
// This test drives the REAL production path — packet.ParsePacket →
// Engine.evaluatePacket → the shipped opa-policies/l3.rego — and asserts on the
// DENY REASON, so a packet that is stopped by an unrelated rule cannot pass as
// "not allowed" and mask the bypass.

func r92eTCP(dstPort uint16) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:2], 40000)
	binary.BigEndian.PutUint16(h[2:4], dstPort)
	h[12] = 0x50
	h[13] = 0x02 // SYN
	return h
}

func r92eUDP(dstPort uint16) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:2], 40000)
	binary.BigEndian.PutUint16(h[2:4], dstPort)
	binary.BigEndian.PutUint16(h[4:6], 8)
	return h
}

// r92eAH returns an AH header of (payloadLen+2)*4 bytes.
func r92eAH(next, payloadLen byte) []byte {
	h := make([]byte, (int(payloadLen)+2)*4)
	h[0] = next
	h[1] = payloadLen
	binary.BigEndian.PutUint32(h[4:8], 0x1000)
	binary.BigEndian.PutUint32(h[8:12], 1)
	return h
}

func r92eIPv6(next byte, payload []byte) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(payload)))
	pkt[6] = next
	pkt[7] = 64
	copy(pkt[8:24], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(pkt[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	return append(pkt, payload...)
}

func r92eIPv4(proto byte, payload []byte) []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(20+len(payload)))
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:16], []byte{203, 0, 113, 9})
	copy(pkt[16:20], []byte{198, 51, 100, 7})
	return append(pkt, payload...)
}

func r92eCat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// TestAttack_AuthHeaderWrappedBlockedPortIsDenied proves the bypass end to end
// with the SHIPPED policy: a TCP SYN or UDP datagram to a blocked port, wrapped
// in an IPsec AH header, must be denied BY THE PORT RULE — the same reason the
// unwrapped packet gets.
func TestAttack_AuthHeaderWrappedBlockedPortIsDenied(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{"ipv6_ah_tcp_22", r92eIPv6(51, r92eCat(r92eAH(6, 1), r92eTCP(22))), "blocked port 22 (TCP)"},
		{"ipv6_ah_tcp_3389", r92eIPv6(51, r92eCat(r92eAH(6, 1), r92eTCP(3389))), "blocked port 3389 (TCP)"},
		{"ipv6_ah_udp_3389", r92eIPv6(51, r92eCat(r92eAH(17, 1), r92eUDP(3389))), "blocked port 3389 (UDP)"},
		{"ipv4_ah_tcp_23", r92eIPv4(51, r92eCat(r92eAH(6, 1), r92eTCP(23))), "blocked port 23 (TCP)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := newPolicyEngine(t)
			pi, err := packet.ParsePacket(tc.raw)
			if err != nil {
				t.Fatalf("ParsePacket: %v", err)
			}
			res := eng.evaluatePacket(pi, len(tc.raw))
			if res.Allowed {
				t.Errorf("AH-wrapped packet to a blocked port was ALLOWED (reason %q, parser protocol %q): "+
					"the AH hides the L4 header from the parser, so no L4-keyed rule can fire while a "+
					"destination holding the AH SA strips the header and delivers the unchanged segment",
					res.Reason, pi.Protocol)
				return
			}
			if !contains(res.Reason, tc.want) {
				t.Errorf("blocked for the WRONG reason: %q, want it to contain %q", res.Reason, tc.want)
			}
		})
	}
}

// TestAttack_AuthHeaderWrappedBenignPortStillAllowed is the control: the fix
// must not start blocking legitimate traffic that happens to be AH-protected.
func TestAttack_AuthHeaderWrappedBenignPortStillAllowed(t *testing.T) {
	eng := newPolicyEngine(t)
	raw := r92eIPv6(51, r92eCat(r92eAH(6, 1), r92eTCP(443)))
	pi, err := packet.ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if res := eng.evaluatePacket(pi, len(raw)); !res.Allowed {
		t.Errorf("AH-wrapped TCP to port 443 DENIED (reason %q) — legitimate AH-protected "+
			"traffic to an unblocked port must still pass", res.Reason)
	}
}

// ── R92.2: the OPA input document reports FICTIONAL connection facts ────────
//
// opa.BuildInput hardcodes Connection.PacketsInFlow to 1 and never sets
// Connection.AgeMs (always 0), although ConnectionInfo documents both as
// connection-tracking state and the policy's own input contract (l3.rego line
// 9) advertises them. conntrack.Flow has the real values — Packets (incremented
// by touch()) and AgeMs() — and the engine holds the flow at BuildInput time.
// R76 noted the two fields as dead inputs but never fixed them: a policy rule
// keyed on either ("block flows with packets_in_flow > N", "block flows older
// than age_ms") is silently wrong — never fires, or fires on the wrong packet
// — which is the R76/R77 silently-dead-control class.
func TestAttack_OPAInputReportsRealFlowFacts(t *testing.T) {
	probe := &scanProbeEval{}
	ct := conntrack.NewTable(conntrack.DefaultConfig())
	eng := New(probe, ct, ratelimit.NewLimiter(0, 0), false, false, nil, nil, nil, nil, nil, "", nil)

	raw := r92eIPv4(6, r92eTCP(443)) // TCP SYN, unblocked port
	pi, err := packet.ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}

	// First packet of the flow: the real count IS 1, so the pre-fix constant
	// is indistinguishable here — that is exactly why the lie survived.
	eng.evaluatePacket(pi, len(raw))
	if probe.lastInput == nil {
		t.Fatal("evaluator was never called")
	}
	if got := probe.lastInput.Connection.PacketsInFlow; got != 1 {
		t.Errorf("first-packet packets_in_flow = %d, want 1", got)
	}

	// Second packet of the SAME 5-tuple: the real count is 2.
	time.Sleep(3 * time.Millisecond)
	eng.evaluatePacket(pi, len(raw))
	if got := probe.lastInput.Connection.PacketsInFlow; got != 2 {
		t.Errorf("packets_in_flow = %d on the second packet of the flow, want 2 — the engine "+
			"hardcodes 1, so any policy rule keyed on this documented field is silently dead", got)
	}
	if got := probe.lastInput.Connection.AgeMs; got <= 0 {
		t.Errorf("age_ms = %d on the second packet of the flow, want > 0 — the field is never "+
			"populated, so a policy rule keyed on flow age is silently dead", got)
	}
}

// contains is a thin alias so the table assertions read cleanly.
func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }
