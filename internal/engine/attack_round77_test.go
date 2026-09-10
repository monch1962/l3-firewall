package engine

import (
	"testing"
	"time"

	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/packet"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
)

// ── R77.1: main()-wired engine feeds a saturated/global new_conns_per_sec to
// OPA — deny_new_conn_rate can never fire, and fires on the wrong source ─────
// The shipped deny-override policy (l3.rego RULE 13) denies when
// input.rate.new_conns_per_sec > 1000 (max_new_connections_per_second := 1000,
// "Per-IP new connection rate limit"). The producer chain is:
//
//	engine.evaluatePacket → conntrack.NewConnectionRate → opa.BuildInput.
//
// Pre-R77 conntrack.NewConnectionRate() summed a TABLE-GLOBAL timestamp slice
// capped at 10000 entries over a 10s window — the maximum reportable value was
// exactly 10000/10 = 1000.0, and the rule's strict `> 1000` could never be
// satisfied at any flood rate (the cap aliases the measurement at the policy
// threshold). Every packet from EVERY source also carried the aggregate rate
// (the field is documented "New connections/sec from this source").
// This test drives evaluatePacket exactly as the NFQUEUE callback would and
// asserts the INPUT the policy consumes carries the flood evidence per source.
func TestAttack_NewConnRateEvidenceNeverReachesOPAInput(t *testing.T) {
	// Engine wiring mirrors cmd/server/main.go (production conntrack Config
	// shape; audit-only/fail-closed off; no optional components).
	ct := conntrack.NewTable(conntrack.Config{
		MaxEntries:       65536,
		MaxFlowsPerSrcIP: 0,
		IdleTimeout:      5 * time.Minute,
		UDPTimeout:       30 * time.Second,
		ICMPTimeout:      5 * time.Second,
	})
	probe := &scanProbeEval{}
	eng := New(probe, ct, ratelimit.NewLimiter(0, 0),
		false, false, nil, nil, nil, nil, nil, "", nil)

	flooder := "10.0.0.9"
	// Attacker: 15000 fresh TCP connections from one source (distinct dst
	// IP:port 5-tuples — each is a new flow, like a real connection flood).
	for i := 0; i < 15000; i++ {
		pi := &packet.PacketInfo{
			SrcIP: flooder, DstIP: sprintfDst(i), Protocol: "TCP",
			SrcPort: uint16(i%60000 + 1), DstPort: 443, PacketSize: 64,
			TCPFlags: packet.TCPFlags{SYN: true},
		}
		if res := eng.evaluatePacket(pi, 64); !res.Allowed {
			t.Fatalf("packet %d unexpectedly blocked", i)
		}
	}

	if probe.lastInput == nil {
		t.Fatal("evaluator never called")
	}
	// The flooder's OWN last packet must carry its per-source rate above the
	// policy threshold — otherwise deny_new_conn_rate (default-on, > 1000)
	// is dead code in the production binary.
	if r := probe.lastInput.Rate.NewConnsPerSec; r <= 1000 {
		t.Errorf("OPA input rate.new_conns_per_sec = %.1f after 15000-conn flood (want > 1000): the per-source producer saturates at the policy threshold, so deny_new_conn_rate can never fire — sustained new-conn floods are silently allowed", r)
	}
}

// ── R77.2: an innocent source must not inherit the flooder's rate ───────────
// Pre-R77 the rate was table-global: after a 15000-conn flood from 10.0.0.9, a
// single packet from an innocent 10.1.1.1 carried the same aggregate rate in
// its OPA input, so deny_new_conn_rate (evaluated per packet) would deny the
// INNOCENT source's traffic. Post-fix the rate is attributed per source.
func TestAttack_NewConnRateAttributedToSource(t *testing.T) {
	ct := conntrack.NewTable(conntrack.Config{
		MaxEntries:       65536,
		MaxFlowsPerSrcIP: 0,
		IdleTimeout:      5 * time.Minute,
		UDPTimeout:       30 * time.Second,
		ICMPTimeout:      5 * time.Second,
	})
	probe := &scanProbeEval{}
	eng := New(probe, ct, ratelimit.NewLimiter(0, 0),
		false, false, nil, nil, nil, nil, nil, "", nil)

	flooder := "10.0.0.9"
	for i := 0; i < 15000; i++ {
		pi := &packet.PacketInfo{
			SrcIP: flooder, DstIP: sprintfDst(i), Protocol: "TCP",
			SrcPort: uint16(i%60000 + 1), DstPort: 443, PacketSize: 64,
			TCPFlags: packet.TCPFlags{SYN: true},
		}
		eng.evaluatePacket(pi, 64)
	}

	// Innocent source sends ONE packet after the flood.
	pi := &packet.PacketInfo{
		SrcIP: "10.1.1.1", DstIP: "8.8.8.8", Protocol: "TCP",
		SrcPort: 40000, DstPort: 443, PacketSize: 64,
		TCPFlags: packet.TCPFlags{SYN: true},
	}
	if res := eng.evaluatePacket(pi, 64); !res.Allowed {
		t.Fatalf("innocent packet unexpectedly blocked")
	}
	if probe.lastInput == nil {
		t.Fatal("evaluator never called")
	}
	if r := probe.lastInput.Rate.NewConnsPerSec; r >= 1000 {
		t.Errorf("innocent source 10.1.1.1 (1 conn) reports new_conns_per_sec = %.1f — inherited the flooder's table-global rate; deny_new_conn_rate would deny the WRONG source's traffic", r)
	}
}

// sprintfDst yields distinct destination IPs across a 3-octet space so 15000
// distinct 5-tuples never collide (R58 RED-test construction lesson).
func sprintfDst(i int) string {
	high, low := i/250, i%250
	b := make([]byte, 0, 16)
	b = append(b, "203.0."...)
	b = appendUint(b, high)
	b = append(b, '.')
	b = appendUint(b, low)
	return string(b)
}

func appendUint(b []byte, n int) []byte {
	if n == 0 {
		return append(b, '0')
	}
	var tmp [3]byte
	i := len(tmp)
	for n > 0 {
		i--
		tmp[i] = byte('0' + n%10)
		n /= 10
	}
	return append(b, tmp[i:]...)
}
