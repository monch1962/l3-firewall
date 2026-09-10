package engine

import (
	"errors"
	"os"
	"testing"

	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/opa"
	"github.com/monch1962/l3-firewall/internal/packet"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
)

// errEval is an evaluator that fails the decision — the shape the shipped
// policy produces for a packet that matches two deny rules (R78.1).
type errEval struct{ err error }

func (e *errEval) Evaluate(*opa.Input) (*opa.Result, error) { return nil, e.err }

// shippedPolicyEval loads the actual shipped deny-override policy the
// production binary embeds (--opa-embed default ./opa-policies/l3.rego).
func shippedPolicyEval(t *testing.T) *opa.EmbeddedEvaluator {
	t.Helper()
	data, err := os.ReadFile("../../opa-policies/l3.rego")
	if err != nil {
		t.Fatalf("reading shipped policy: %v", err)
	}
	ev, err := opa.NewEmbedded(opa.EmbedConfig{Policy: string(data)})
	if err != nil {
		t.Fatalf("NewEmbedded(shipped policy): %v", err)
	}
	return ev
}

func newPolicyEngine(t *testing.T) *Engine {
	t.Helper()
	return New(shippedPolicyEval(t), conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(0, 0),
		false /* failClosed — the production default */, false, nil, nil, nil, nil, nil, "", nil)
}

// ── R78.1: a packet matching TWO deny rules produces an OPA eval error, and
// the engine's default (non-fail-closed) error path ALLOWS it ────────────────
// The shipped policy (opa-policies/l3.rego) defines `deny_reason` as 21
// COMPLETE rules with different values, one per deny condition:
//
//	deny_reason := "port scan detected"   if { deny_port_scan }
//	deny_reason := "SYN flood detected"   if { deny_syn_flood }
//	…
//
// Rego forbids a complete rule from producing multiple outputs: when two of
// those bodies are true for the same packet, evaluation fails with
//
//	eval_conflict_error: complete rules must not produce multiple outputs.
//
// The evaluator queries the WHOLE document (`data.l3_firewall`), and that
// document includes `reason`, which references `deny_reason` — so the conflict
// aborts the ENTIRE decision. Engine.evaluatePacket then takes its
// `err != nil && !failClosed` branch and returns Allowed=true.
// Net effect: any packet that trips two deny rules BYPASSES every deny rule.
// Every one of these combinations is attacker-craftable, so this is a direct
// fail-open bypass of the shipped default policy.
func TestAttack_DenyReasonConflictBypassesShippedPolicy(t *testing.T) {
	t.Run("blocked_port_with_invalid_tcp_flags", func(t *testing.T) {
		// One packet: destination port 22 (blocked_ports) AND the invalid
		// SYN+RST flag combination (deny_protocol_anomaly). A textbook
		// stealth scan shape, and a two-rule match.
		eng := newPolicyEngine(t)
		pi := &packet.PacketInfo{
			SrcIP: "10.0.0.9", DstIP: "8.8.8.8", Protocol: "TCP",
			SrcPort: 40000, DstPort: 22, PacketSize: 64,
			TCPFlags: packet.TCPFlags{SYN: true, RST: true},
		}
		res := eng.evaluatePacket(pi, 64)
		if res.Allowed {
			t.Errorf("TCP SYN+RST to blocked port 22 was ALLOWED (reason %q): it matches both "+
				"deny_blocked_port and deny_protocol_anomaly, the two deny_reason values conflict, "+
				"OPA returns eval_conflict_error for the whole data.l3_firewall document, and the "+
				"engine's non-fail-closed error path converts it to an allow — a two-rule packet "+
				"bypasses every deny rule in the shipped policy", res.Reason)
		}
	})

	t.Run("blocked_port_and_source_port", func(t *testing.T) {
		// Source port 22 and destination port 22: deny_source_port and
		// deny_blocked_port both fire (distinct deny_reason strings).
		eng := newPolicyEngine(t)
		pi := &packet.PacketInfo{
			SrcIP: "10.0.0.9", DstIP: "8.8.8.8", Protocol: "TCP",
			SrcPort: 22, DstPort: 22, PacketSize: 64,
			TCPFlags: packet.TCPFlags{SYN: true},
		}
		if res := eng.evaluatePacket(pi, 64); res.Allowed {
			t.Errorf("TCP src_port=22 -> dst_port=22 was ALLOWED (reason %q): two deny rules match", res.Reason)
		}
	})

	t.Run("icmp_echo_flood", func(t *testing.T) {
		// deny_icmp (type 8 echo request) fires on the first packet. Once the
		// source's measured packet rate passes icmp_rate_per_second (10), deny_icmp_flood
		// fires TOO — the second deny_reason value conflicts and the flood is
		// ALLOWED from that moment on. The rule that exists to stop the flood
		// disables the block exactly when the flood gets fast enough.
		eng := newPolicyEngine(t)
		icmpType := uint8(8)
		icmpCode := uint8(0)
		var lastAllowed bool
		var lastReason string
		for i := 0; i < 30; i++ {
			pi := &packet.PacketInfo{
				SrcIP: "10.0.0.9", DstIP: "8.8.8.8", Protocol: "ICMP",
				ICMPType: &icmpType, ICMPCode: &icmpCode, PacketSize: 64,
			}
			res := eng.evaluatePacket(pi, 64)
			lastAllowed, lastReason = res.Allowed, res.Reason
		}
		if lastAllowed {
			t.Errorf("ICMP echo flood: packet 30 was ALLOWED (reason %q) — deny_icmp and "+
				"deny_icmp_flood both match once the rate passes 10 pps, their deny_reason values "+
				"conflict, and the resulting eval error is converted to an allow: the "+
				"flood-protection rule turns OFF the block under exactly the load it targets", lastReason)
		}
	})

	t.Run("port_scan_via_syn_flood", func(t *testing.T) {
		// A fast SYN scan to distinct ports: by probe 20 the source has >= 20
		// recorded destination ports (deny_port_scan) and its measured pps is
		// far past syn_rate_per_second (deny_syn_flood) — two deny rules at
		// once, so the scan is ALLOWED from probe 20 onward.
		eng := newPolicyEngine(t)
		lastAllowed := true
		lastReason := ""
		blocked := 0
		for dstPort := uint16(1); dstPort <= 25; dstPort++ {
			pi := &packet.PacketInfo{
				SrcIP: "10.0.0.9", DstIP: "8.8.8.8", Protocol: "TCP",
				SrcPort: 40000, DstPort: dstPort, PacketSize: 64,
				TCPFlags: packet.TCPFlags{SYN: true},
			}
			res := eng.evaluatePacket(pi, 64)
			if !res.Allowed {
				blocked++
			}
			lastAllowed, lastReason = res.Allowed, res.Reason
		}
		if lastAllowed {
			t.Errorf("port scan (25 SYN probes to distinct ports) ended with probe 25 ALLOWED "+
				"(reason %q, blocked=%d of 25): probe 20 trips BOTH deny_port_scan and deny_syn_flood, "+
				"the conflicting deny_reason values raise eval_conflict_error, and the engine's "+
				"non-fail-closed error path allows every probe from then on — a fast scan escapes "+
				"the scan detector precisely when the detector engages", lastReason, blocked)
		}
	})
}

// ── R78.2: the engine converts an OPA evaluation error into an allow ─────────
// Engine.evaluatePacket inspects `if e.failClosed` on the Evaluate error path
// and otherwise returns Allowed=true. `--opa-fail-closed` is documented as
// "Block when OPA is unreachable", but a policy EVALUATION error is not
// unreachability — it is a decision the policy failed to produce for THIS
// input, and its inputs are attacker-controlled (R78.1 is one way to force
// one). One crafted packet must not be able to switch the firewall to
// allow-all, so an undecidable packet has to fail closed the same way
// unparseable (R40.3) and nil-payload (R49) packets do.
func TestAttack_OPAEvalErrorIsFailOpen(t *testing.T) {
	eng := New(&errEval{err: errors.New("eval_conflict_error: complete rules must not produce multiple outputs")},
		conntrack.NewTable(conntrack.DefaultConfig()), ratelimit.NewLimiter(0, 0),
		false /* failClosed — production default */, false, nil, nil, nil, nil, nil, "", nil)

	pi := &packet.PacketInfo{
		SrcIP: "10.0.0.9", DstIP: "8.8.8.8", Protocol: "TCP",
		SrcPort: 40000, DstPort: 22, PacketSize: 64,
		TCPFlags: packet.TCPFlags{SYN: true, RST: true},
	}
	res := eng.evaluatePacket(pi, 64)
	if res.Allowed {
		t.Errorf("a packet whose OPA evaluation FAILED was ALLOWED (reason %q): a policy "+
			"evaluation error is attacker-reachable (R78.1 forces one with a single crafted "+
			"packet) and must fail closed like every other undecidable packet (R40.3 parse "+
			"errors, R49 nil payload) — otherwise --opa-fail-closed=false (the default) turns "+
			"any policy defect into a universal bypass", res.Reason)
	}
}
