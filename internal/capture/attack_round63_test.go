// Red-team security hardening Round 63 — capture rotation cleanup:
// unbounded directory scan on the NFQUEUE hot path.
//
// cleanupLocked() runs on EVERY rotation (rotateLocked, called from
// WriteBlock on the packet hot path — every MaxPackets blocked
// packets). The R60 ReadDir fix removed glob-metachar expansion but
// left the scan dimension unbounded: os.ReadDir reads the ENTIRE
// directory into memory, and the removal loop deletes every
// blocked_*.pcap beyond MaxFiles. An attacker with write access to
// --pcap-dir (the standing R42/R45/R55 threat model) plants a large
// number of files — matching OR not — and every rotation pays an O(N)
// allocation + syscall burst on the hot path; with non-matching names
// the files persist, so the cost recurs on every rotation forever
// (memory spike + receive-loop stall → queue overflow → ALL traffic
// dropped, R55's documented impact chain).
//
// R63 FIX (two mechanisms):
//  1. Direct indexed removal — after creating rotation file N, index
//     (N - MaxFiles) is obsolete; the firewall knows the exact names it
//     creates (blocked_%05d.pcap), so its own retention cap is enforced
//     in O(1) with no directory read.
//  2. A BOUNDED directory scan (maxCleanupEntries via Readdirnames) for
//     stale files the index cannot see (prior-run files with
//     non-sequential names, e.g. old non-padded formats) — memory and
//     syscalls per rotation are O(1) regardless of directory contents;
//     leftover matches are pruned on subsequent rotations.
package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// plantAttackerFiles creates n matching attacker files (blocked_%05d.pcap
// at HIGH indices — above the test's own rotation window) plus n/2
// non-matching junk files in dir. The pre-R63 cleanup deletes every
// matching file beyond MaxFiles in one O(N) scan; the R63 bounded scan
// examines at most maxCleanupEntries names per rotation.
func plantAttackerFiles(t *testing.T, dir string, n int) {
	t.Helper()
	base := 20000 // well above the test's own rotation window (1..~10)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("blocked_%05d.pcap", base+i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte("attacker"), 0644); err != nil {
			t.Fatalf("planting %s: %v", name, err)
		}
	}
	for i := 0; i < n/2; i++ {
		name := fmt.Sprintf("junk_%05d.txt", i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte("attacker"), 0644); err != nil {
			t.Fatalf("planting %s: %v", name, err)
		}
	}
}

// ── R63.1: cleanup must not do unbounded work per rotation ─────────────
// RED (pre-fix): one rotation with N attacker-planted matching files
// deletes all but MaxFiles of them — O(N) removals from an O(N)
// directory read on the hot path. GREEN (post-fix): at most
// maxCleanupEntries entries are examined per rotation, so the number of
// removals (and the memory) is bounded regardless of how many files the
// attacker planted.
func TestAttack_CleanupScanBoundedPerRotation(t *testing.T) {
	dir := t.TempDir()

	// 8000 planted matching files — more than maxCleanupEntries (4096):
	// the pre-R63 code removes ~7995 of them in a single rotation.
	plantAttackerFiles(t, dir, 8000)

	w, err := NewWriter(Config{Dir: dir, MaxFiles: 5, MaxPackets: 1})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	// One rotation (each rotation runs cleanupLocked on the hot path).
	if err := w.WriteBlock([]byte("packet-bytes")); err != nil {
		t.Fatalf("WriteBlock: %v", err)
	}

	// Count how many planted files the rotation removed.
	removed := 0
	for i := 0; i < 8000; i++ {
		if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("blocked_%05d.pcap", 20000+i))); err != nil {
			removed++
		}
	}
	if removed > 4096 {
		t.Errorf("R63 RED: one rotation removed %d attacker-planted files — cleanup scanned/deleted unbounded directory contents on the hot path; per-rotation work must be bounded", removed)
	}
}

// ── R63.2: the firewall's own retention cap is still enforced ──────────
// Regression guard: cleanup must preserve the MaxFiles rotation cap
// (R11.9/R60.2 contract) — including the indexed removal of the
// firewall's own rotation files.
func TestAttack_CleanupOwnFilesStillCapped(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir, MaxFiles: 3, MaxPackets: 1})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	for i := 0; i < 10; i++ {
		if err := w.WriteBlock([]byte("packet-bytes")); err != nil {
			t.Fatalf("WriteBlock %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	own := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "blocked_") && strings.HasSuffix(e.Name(), ".pcap") {
			own++
		}
	}
	if own > w.cfg.MaxFiles {
		t.Errorf("expected at most %d own files after cleanup, got %d", w.cfg.MaxFiles, own)
	}
}
