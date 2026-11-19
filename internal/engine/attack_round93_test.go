package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monch1962/l3-firewall/internal/packet"
)

// ── R93.3: attacker-varied reasons exhaust the block-stats cap ─────────────
//
// /admin/block-stats and the packets_blocked_total{reason} metric are two views
// of the same event (R86). The metric surface bounds label cardinality by
// FOLDING digit runs and overflowing anything still variable (metrics/labelGuard),
// so an attacker cannot blind it. The admin surface instead keys a raw map on
// the exact reason string and — once maxBlockStatsReasons (256) entries exist —
// silently stops counting every NEW reason.
//
// Several deny reasons embed attacker-controlled numbers. The per-IP rate-limit
// reason prints the measured pps/bps, which the attacker controls by pacing
// their traffic, so 256 distinct reasons are trivially generated. After that the
// operator's per-reason view of what the firewall is blocking is frozen: the
// threat-intel and OPA deny reasons that matter during an incident are never
// counted, with no warning anywhere.
func TestAttack_BlockStatsValueFloodHidesRealReason(t *testing.T) {
	eng := newAttackTestEngine(t)

	pi := &packet.PacketInfo{
		SrcIP: "10.0.1.100", DstIP: "10.0.2.50", Protocol: "TCP",
		SrcPort: 44001, DstPort: 443,
	}
	// The exact production shape (engine.evaluatePacket's rate-limit branch).
	for i := 0; i < maxBlockStatsReasons+64; i++ {
		eng.recordBlock(pi, fmt.Sprintf("per-IP rate limit exceeded: %d pps / %d bps", 1000+i, 500000+i*7), "")
	}
	const real = "source IP in threat intelligence blocklist"
	eng.recordBlock(pi, real, "")

	stats := eng.BlockStats()
	if stats[real] != 1 {
		t.Errorf("a real deny reason was not counted after an attacker emitted %d distinct reasons: %s=%d (map holds %d keys)",
			maxBlockStatsReasons+64, real, stats[real], len(stats))
	}
	if len(stats) > maxBlockStatsReasons {
		t.Errorf("block stats exceeded the memory cap: %d > %d", len(stats), maxBlockStatsReasons)
	}
}

// The folding must be what keeps the card small: numeric variance collapses to
// a single key per reason shape, and distinct STATIC reasons stay distinct.
func TestAttack_BlockStatsFoldsPerPacketValues(t *testing.T) {
	eng := newAttackTestEngine(t)
	pi := &packet.PacketInfo{SrcIP: "10.0.1.100", DstIP: "10.0.2.50", Protocol: "TCP", SrcPort: 44001, DstPort: 22}

	eng.recordBlock(pi, "per-IP rate limit exceeded: 10 pps / 500 bps", "")
	eng.recordBlock(pi, "per-IP rate limit exceeded: 900 pps / 70000 bps", "")
	eng.recordBlock(pi, "blocked port 22 (TCP)", "")
	eng.recordBlock(pi, "blocked port 22 (TCP)", "")

	stats := eng.BlockStats()
	if len(stats) != 2 {
		t.Fatalf("want 2 folded keys (one rate-limit shape + one static reason), got %d: %v", len(stats), keysOf(stats))
	}
	var rateKey string
	for k := range stats {
		if strings.HasPrefix(k, "per-IP rate limit exceeded:") {
			rateKey = k
		}
	}
	if rateKey == "" {
		t.Fatalf("rate-limit reason missing from block stats: %v", keysOf(stats))
	}
	if stats[rateKey] != 2 {
		t.Errorf("%q counted %d times, want 2 (folded)", rateKey, stats[rateKey])
	}
	if stats["blocked port # (TCP)"] != 2 {
		t.Errorf("static reason not folded/counted as %q: %v", "blocked port # (TCP)", keysOf(stats))
	}
	// Forensics keep the exact string: only the aggregate key is folded.
	recent := eng.RecentBlocks()
	if len(recent) == 0 || recent[len(recent)-1].Reason != "blocked port 22 (TCP)" {
		t.Errorf("recent block log must keep the exact reason, got %q", recent[len(recent)-1].Reason)
	}
}

// Restored state is the second input to the same map: keys written by an older
// build (or by an attacker-influenced file that still parses) must be folded
// too, otherwise a restored map arrives already full and every new reason is
// dropped from the first packet after startup.
func TestAttack_RestoreStateFoldsKeys(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	many := map[string]int64{}
	for i := 0; i < maxBlockStatsReasons+16; i++ {
		many[fmt.Sprintf("per-IP rate limit exceeded: %d pps / %d bps", 1000+i, 500000+i)] = 1
	}
	many["blocked SSH"] = 7
	payload, err := json.Marshal(map[string]any{"block_stats": many})
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(statePath, payload, 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	eng := newAttackTestEngine(t)
	eng.statePath = statePath
	eng.restoreState()

	stats := eng.BlockStats()
	if len(stats) > 4 {
		t.Errorf("restored keys were not folded: %d keys: %v", len(stats), keysOf(stats))
	}
	if stats["blocked SSH"] != 7 {
		t.Errorf("static restored reason lost: %v", keysOf(stats))
	}
}

func keysOf(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
