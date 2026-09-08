package conntrack

import (
	"testing"
	"time"
)

// ── R76.1: production-shaped conntrack Config never records scan ports ──
// cmd/server/main.go constructs conntrack.Config with ONLY MaxEntries and the
// three idle timeouts (no PortScanMaxPorts/PortScanWindow — there are no CLI
// flags for them). NewTable defaults MaxEntries/timeouts on <=0 but NOT
// PortScanMaxPorts, so RecordDestPort's cap check `len(ports) >=
// t.cfg.PortScanMaxPorts` evaluates `0 >= 0` and returns early FOREVER:
// srcPorts never fills, GetRecentDestPorts returns nil, and the OPA input
// field connection.recent_ports is always empty. The SHIPPED deny-override
// policy (opa-policies/l3.rego) enables port-scan blocking by default
// (`enable_port_scan := true`, deny_port_scan on SYN-only packets when
// count(recent_ports) >= 20 → allow := false), so that rule can never fire
// in the production binary: a moderate-rate scan (below the 100 pps
// syn-flood / 10000 pps traffic-rate rules) is silently ALLOWED — the
// R40.4-class "silently dropped security control", where the drop is the
// ABSENCE of the field in main()'s config rather than a dead flag. Every
// conntrack test to date set PortScanMaxPorts explicitly (100), so the
// production Config shape was never exercised (R39's srcPorts-bounding fix
// and R39's doc finding covered only the never-read PortScanWindow field).
//
// The Config below mirrors cmd/server/main.go EXACTLY (main.go ctConfig).
func TestAttack_ProductionConfigNeverRecordsScanPorts(t *testing.T) {
	cfg := Config{
		MaxEntries:       65536,
		MaxFlowsPerSrcIP: 0,
		IdleTimeout:      5 * time.Minute,
		UDPTimeout:       30 * time.Second,
		ICMPTimeout:      5 * time.Second,
		// PortScanMaxPorts / PortScanWindow deliberately omitted — main()
		// does not set them and NewTable must apply its defaults.
	}
	tbl := NewTable(cfg)

	// Attacker: one source IP probing 25 distinct destination ports (a
	// moderate scan — 25 SYN probes well below every flood threshold).
	for port := uint16(1); port <= 25; port++ {
		tbl.RecordDestPort("10.0.0.9", port)
	}

	got := tbl.GetRecentDestPorts("10.0.0.9")
	if len(got) < 20 {
		t.Errorf("production-shaped config recorded %d scan ports (want >= 20): "+
			"PortScanMaxPorts is 0 so RecordDestPort short-circuits forever — "+
			"OPA input connection.recent_ports stays empty and the shipped "+
			"deny_port_scan rule (threshold 20) can never fire", len(got))
	}
}

// ── R76.2 (regression): scan tracking works under the fixed defaults, and
// the R39 bound (prune when the source's last flow dies) still holds ──
// After NewTable defaults PortScanMaxPorts, a production-shaped config must
// record distinct ports (deduplicated) while the source has flows, and the
// R39 prune must still clear the source's history when its LAST flow dies —
// defaulting must not resurrect the unbounded-growth class.
func TestAttack_ProductionConfigScanTrackingRegression(t *testing.T) {
	cfg := Config{
		MaxEntries:  65536,
		IdleTimeout: 5 * time.Minute,
		UDPTimeout:  30 * time.Second,
		ICMPTimeout: 5 * time.Second,
	}
	tbl := NewTable(cfg)

	// The scanner also has a live flow (a real scan opens connections).
	tbl.LookupOrCreate("10.0.0.9", "8.8.8.8", "TCP", 40000, 80)

	for port := uint16(1); port <= 25; port++ {
		tbl.RecordDestPort("10.0.0.9", port)
	}
	// Re-send one duplicate — must not double-count.
	tbl.RecordDestPort("10.0.0.9", 5)

	if got := tbl.GetRecentDestPorts("10.0.0.9"); len(got) != 25 {
		t.Fatalf("defaulted config recorded %d distinct ports (want 25: 25 unique, duplicate deduped)", len(got))
	}

	// R39 contract under the new default: when the source's last flow dies,
	// its port-scan history is pruned — no unbounded per-source growth.
	tbl.Delete("10.0.0.9", "8.8.8.8", "TCP", 40000, 80)
	if got := tbl.GetRecentDestPorts("10.0.0.9"); len(got) != 0 {
		t.Errorf("scan history not pruned after last flow died: got %d ports (want 0 — R39 bound)", len(got))
	}
}
