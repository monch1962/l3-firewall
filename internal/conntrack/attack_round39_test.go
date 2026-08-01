package conntrack

import (
	"fmt"
	"testing"
	"time"
)

// ── R39: Unbounded srcPorts growth via spoofed source IPs ──────────────
// Attacker sends one packet per spoofed source IP (L3 — spoofing is
// trivial, the firewall cannot attribute packets). Every TCP/UDP packet
// calls RecordDestPort, which appends to srcPorts[srcIP]. Entries are
// NEVER evicted — flow expiry/eviction cleans flows and srcFlowCount but
// leaves srcPorts entries behind forever.
//
// Result: unbounded memory growth over the lifetime of the firewall
// (R2/R8 class — rate limiter map was capped at 100k, but conntrack's
// port-scan map has no cap at all).
func TestAttack_SrcPortsUnboundedGrowth(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PortScanMaxPorts = 100
	cfg.IdleTimeout = time.Nanosecond // flows expire on the next Expire() call
	tbl := NewTable(cfg)

	// Attacker cycles unique spoofed srcIPs, one TCP packet each.
	// Each creates a flow (which then expires), and each RecordDestPort
	// leaves a permanent srcPorts entry.
	const attackerPackets = 20000
	for i := 0; i < attackerPackets; i++ {
		src := fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff)
		tbl.RecordDestPort(src, uint16(i%65535))
		f := tbl.LookupOrCreate(src, "203.0.113.1", "TCP", 40000+uint16(i%1000), uint16(i%65535))
		_ = f
	}
	tbl.Expire()

	// After expiry, flows are gone...
	if got := tbl.Len(); got != 0 {
		t.Fatalf("expected all flows expired, got %d", got)
	}
	// ...and srcPorts must be bounded too (attack should NOT accumulate
	// an entry per spoofed srcIP forever).
	if got := len(tbl.srcPorts); got > 1000 {
		t.Errorf("srcPorts grew unbounded under spoofed srcIP flood: %d entries (attack should be bounded)", got)
	}
}

// ── R39: srcPorts must be pruned when a source's last flow dies ────────
// The port-scan history for a srcIP is only meaningful while that srcIP
// has active flows. When the last flow for a srcIP expires/evicts/deletes,
// its srcPorts entry must be removed too — otherwise the map grows with
// every unique srcIP the firewall ever sees.
func TestAttack_SrcPortsPrunedOnFlowExpiry(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PortScanMaxPorts = 100
	cfg.IdleTimeout = time.Nanosecond // flows expire on the next Expire() call
	tbl := NewTable(cfg)

	src := "192.0.2.55"
	tbl.LookupOrCreate(src, "203.0.113.1", "TCP", 40000, 443)
	tbl.RecordDestPort(src, 443)
	tbl.RecordDestPort(src, 8443)

	if got := len(tbl.srcPorts[src]); got != 2 {
		t.Fatalf("expected 2 ports recorded, got %d", got)
	}

	// Flow expires (simulate idle timeout)
	tbl.Expire()
	if got := tbl.Len(); got != 0 {
		t.Fatalf("expected flow expired, got %d", got)
	}
	if _, ok := tbl.srcPorts[src]; ok {
		t.Errorf("srcPorts entry for %s survived flow expiry — port-scan map leaks forever", src)
	}
}

// ── R39: Port-scan detection still works while flows are active ────────
// The srcPorts prune must NOT remove port history while the source has
// active flows — otherwise the fix would break port-scan detection.
func TestAttack_SrcPortsKeptWhileFlowsActive(t *testing.T) {
	cfg := DefaultConfig()
	cfg.IdleTimeout = time.Nanosecond
	tbl := NewTable(cfg)

	src := "203.0.113.77"
	f := tbl.LookupOrCreate(src, "198.51.100.1", "TCP", 50000, 22)
	if f == nil {
		t.Fatal("expected flow created")
	}
	tbl.RecordDestPort(src, 22)
	tbl.RecordDestPort(src, 23)

	// While the flow is active, port history must be visible to the
	// scan-detection logic in the engine (GetRecentDestPorts feeds OPA).
	ports := tbl.GetRecentDestPorts(src)
	if len(ports) != 2 {
		t.Fatalf("expected 2 recorded ports while flow active, got %v", ports)
	}

	// After expiry the history is pruned — bounded, no leak.
	tbl.Expire()
	if _, ok := tbl.srcPorts[src]; ok {
		t.Errorf("srcPorts entry survived expiry — leak")
	}
}

// ── R39: Delete must also prune srcPorts ───────────────────────────────
// Delete removes a flow and decrements the per-source count; when the
// last flow for a srcIP is deleted, its port history must go too.
func TestAttack_SrcPortsPrunedOnDelete(t *testing.T) {
	cfg := DefaultConfig()
	tbl := NewTable(cfg)

	src := "198.51.100.7"
	tbl.LookupOrCreate(src, "203.0.113.1", "UDP", 40000, 53)
	tbl.RecordDestPort(src, 53)

	tbl.Delete(src, "203.0.113.1", "UDP", 40000, 53)
	if _, ok := tbl.srcPorts[src]; ok {
		t.Errorf("srcPorts entry for %s survived Delete — port-scan map leaks", src)
	}
}
