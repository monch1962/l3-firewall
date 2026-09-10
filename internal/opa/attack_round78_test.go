package opa

import (
	"os"
	"testing"

	"github.com/monch1962/l3-firewall/internal/packet"
)

// ── R78: the shipped policy's `deny_reason` is a multi-valued COMPLETE rule,
// so a two-rule packet makes the whole decision document unevaluable ─────────
// opa-policies/l3.rego defines deny_reason 21 times, once per deny condition,
// each a complete rule with a different value. Rego rejects a complete rule
// that produces more than one output (eval_conflict_error), so when two deny
// bodies are true for the same packet the `reason`/`deny_reason` part of the
// document cannot be evaluated. Because decisionQuery is the whole package
// (data.l3_firewall), the evaluator surfaces that as an error for the entire
// decision rather than a deny — and Engine.evaluatePacket's error path allows
// the packet when --opa-fail-closed is left at its default (false). The policy
// must therefore be conflict-free for every input: a multi-rule packet has to
// yield a well-defined deny, not an error.
func TestAttack_ShippedPolicyTwoDenyRulesIsNotEvalError(t *testing.T) {
	data, err := os.ReadFile("../../opa-policies/l3.rego")
	if err != nil {
		t.Fatalf("reading shipped policy: %v", err)
	}
	ev, err := NewEmbedded(EmbedConfig{Policy: string(data)})
	if err != nil {
		t.Fatalf("NewEmbedded(shipped policy): %v", err)
	}

	// TCP SYN+RST to blocked port 22: deny_blocked_port AND
	// deny_protocol_anomaly both match.
	input := &Input{
		Packet: PacketInfo{
			SrcIP: "10.0.0.9", DstIP: "8.8.8.8", Protocol: "TCP",
			SrcPort: 40000, DstPort: 22, PacketSize: 64,
			TCPFlags: packet.TCPFlags{SYN: true, RST: true},
		},
		Connection: ConnectionInfo{Established: false, PacketsInFlow: 1},
		Time:       TimeInfo{UtcHour: 12, UtcDay: 3},
	}

	res, err := ev.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate(two-deny packet) returned error %v — the shipped policy's deny_reason "+
			"complete rules conflict (eval_conflict_error: complete rules must not produce multiple "+
			"outputs), which aborts the WHOLE data.l3_firewall decision; the engine converts that "+
			"error to an allow by default, so a two-rule packet bypasses every deny rule (R78)", err)
	}
	if res == nil || res.Allowed {
		t.Errorf("two-deny packet evaluated to Allowed=%v (want a deny): deny_blocked_port and "+
			"deny_protocol_anomaly both match and the policy must deny it, not allow it", res)
	}
}
