package engine

import (
	"testing"
	"time"

	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/opa"
	"github.com/monch1962/l3-firewall/internal/packet"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
)

// scanProbeEval captures the last OPA input the engine produced so a test can
// assert on the exact document the Rego policy evaluates (R76).
type scanProbeEval struct {
	lastInput *opa.Input
}

func (s *scanProbeEval) Evaluate(input *opa.Input) (*opa.Result, error) {
	s.lastInput = input
	return &opa.Result{Allowed: true}, nil
}

// ── R76.3: main()-wired engine never feeds recent_ports to OPA ─────────
// The production binary builds its conntrack table with only MaxEntries and
// the idle timeouts (cmd/server/main.go ctConfig). Because NewTable does not
// default PortScanMaxPorts (asymmetric with capture/l2filter/syncer
// constructors, which default every field), RecordDestPort no-ops and the
// engine's per-packet GetRecentDestPorts always returns nil — so the OPA
// input document the engine hands to the evaluator carries an empty
// connection.recent_ports on every packet. The shipped deny-override policy
// (l3.rego: enable_port_scan := true; deny_port_scan if SYN-only packet AND
// count(recent_ports) >= 20 → allow := false) therefore can never deny a
// port scan in the production binary: a moderate-rate scan below the
// syn-flood (100 pps) and traffic-rate (10000 pps) rules is allowed through,
// silently — the deny rule the operator's default policy enables is inert.
// This test drives evaluatePacket exactly as the NFQUEUE callback would and
// asserts the INPUT the policy consumes carries the scan evidence.
func TestAttack_PortScanEvidenceNeverReachesOPAInput(t *testing.T) {
	// Engine wiring mirrors cmd/server/main.go (ctConfig shape; no scan
	// fields; no other optional components; audit-only/fail-closed off).
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

	// Attacker: 25 SYN-only probes from 10.0.0.9 to 25 distinct destination
	// ports (each probe is a fresh 5-tuple = fresh flow, like a real scan).
	for dstPort := uint16(1); dstPort <= 25; dstPort++ {
		pi := &packet.PacketInfo{
			SrcIP: "10.0.0.9", DstIP: "8.8.8.8", Protocol: "TCP",
			SrcPort: 40000, DstPort: dstPort, PacketSize: 64,
			TCPFlags: packet.TCPFlags{SYN: true}, // SYN-only (ACK/RST/FIN false)
		}
		if res := eng.evaluatePacket(pi, 64); !res.Allowed {
			t.Fatalf("packet to port %d unexpectedly blocked", dstPort)
		}
	}

	if probe.lastInput == nil {
		t.Fatal("evaluator never called")
	}
	if n := len(probe.lastInput.Connection.RecentPorts); n < 20 {
		t.Errorf("OPA input connection.recent_ports has %d entries after 25-probe scan (want >= 20): "+
			"the shipped deny_port_scan rule (threshold 20) can never fire in the "+
			"production binary — moderate scans are silently allowed", n)
	}
}
