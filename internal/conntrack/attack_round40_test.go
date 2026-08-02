package conntrack

import (
	"fmt"
	"testing"
	"time"
)

// ── R40.5: IPv4-mapped IPv6 aliases split the flow key space ───────
// flowKey, srcFlowCount and srcPorts are all keyed by raw IP strings, so
// "10.0.0.1" and "::ffff:10.0.0.1" (same logical source) create separate
// flows. The per-source flow limit and connection limit are keyed by the
// same strings — an attacker using both representations doubles their
// budget under every per-source limit (R10 class).
func TestAttack_IPv4MappedAlias_SplitsFlowKey(t *testing.T) {
	tbl := NewTable(DefaultConfig())

	if f := tbl.LookupOrCreate("10.0.0.1", "8.8.8.8", "UDP", 1000, 53); f == nil {
		t.Fatal("flow 1 nil")
	}
	if f := tbl.LookupOrCreate("::ffff:10.0.0.1", "8.8.8.8", "UDP", 1000, 53); f == nil {
		t.Fatal("flow 2 nil")
	}

	if n := tbl.Len(); n != 1 {
		t.Errorf("IPv4-mapped alias created %d flows for one source; want 1", n)
	}
	if c := tbl.GetSrcFlowCount("10.0.0.1"); c != 1 {
		t.Errorf("srcFlowCount(10.0.0.1) = %d, want 1", c)
	}
}

// ── R40.5: srcPorts companion and Delete must use the same keys ─────
// Port-scan history and deletion via the alias must resolve to the same
// logical source, or the R39 prune invariant breaks (entries that can
// never be deleted) and scan detection splits.
func TestAttack_IPv4MappedAlias_SrcPortsAndDelete(t *testing.T) {
	tbl := NewTable(DefaultConfig())

	tbl.LookupOrCreate("10.0.0.1", "8.8.8.8", "UDP", 1000, 53)
	tbl.RecordDestPort("10.0.0.1", 80)
	tbl.RecordDestPort("::ffff:10.0.0.1", 443)

	ports := tbl.GetRecentDestPorts("::ffff:10.0.0.1")
	if len(ports) != 2 {
		t.Errorf("GetRecentDestPorts(alias) = %v — port-scan history split across alias keys", ports)
	}

	// Deleting via the alias must remove the flow and prune srcPorts (R39).
	tbl.Delete("::ffff:10.0.0.1", "8.8.8.8", "UDP", 1000, 53)
	if n := tbl.Len(); n != 0 {
		t.Errorf("Delete via alias left %d flows — flow can never be removed via the other key form", n)
	}
	if p := tbl.GetRecentDestPorts("10.0.0.1"); len(p) != 0 {
		t.Errorf("srcPorts not pruned after delete: %v", p)
	}
}

// ── R40.6: O(n) flow eviction scan amplifies CPU (same class as the
// rate-limiter eviction) ─────────────────────────────────────────────
// evictOneLocked scans the ENTIRE flow map under the write lock when a new
// flow arrives at capacity. Spoofed 5-tuples at the cap force a full-map
// scan per packet in the NFQUEUE hot path.
func TestAttack_EvictionScan_CPUAmplification(t *testing.T) {
	const capacity = 40000
	const churnKeys = 5000

	cfg := DefaultConfig()
	cfg.MaxEntries = capacity
	tbl := NewTable(cfg)
	for i := 0; i < capacity; i++ {
		tbl.LookupOrCreate(fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff),
			"8.8.8.8", "UDP", uint16(1000+(i%500)), 53)
	}

	empty := NewTable(DefaultConfig())
	t0 := time.Now()
	for k := 0; k < churnKeys; k++ {
		empty.LookupOrCreate(fmt.Sprintf("192.168.%d.%d", k>>8, k&0xff),
			"8.8.8.8", "UDP", uint16(20000+k), 53)
	}
	baseline := time.Since(t0)
	if baseline <= 0 {
		baseline = time.Nanosecond
	}

	t1 := time.Now()
	for k := 0; k < churnKeys; k++ {
		tbl.LookupOrCreate(fmt.Sprintf("192.168.%d.%d", k>>8, k&0xff),
			"8.8.8.8", "UDP", uint16(20000+k), 53)
	}
	churn := time.Since(t1)

	ratio := float64(churn) / float64(baseline)
	t.Logf("baseline=%v churn=%v ratio=%.1f (capacity=%d)", baseline, churn, ratio, capacity)
	if ratio > 500 {
		t.Errorf("flow-insert-at-capacity cost %.0fx an empty-table insert — O(n) eviction scan under write lock in hot path", ratio)
	}
}
