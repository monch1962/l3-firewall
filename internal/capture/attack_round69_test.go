// Red-team security hardening Round 69 — capture rotation cleanup:
// unsorted Readdirnames removal deletes the CURRENT open rotation file
// (silent evidence loss) and inverts retention (newest deleted, oldest kept).
//
// The R63 mechanism-2 comment claims "Names come back in sorted order, so
// the matches found are the oldest — exactly what the removal loop
// targets." That is false: os.File.Readdirnames returns DIRECTORY order,
// not sorted order. On this host's tmpfs /tmp it returns REVERSE-creation
// order (verified empirically: files created 1..15 then 10000..10002
// listed as [10002 10001 10000 00015 ... 00001]); on ext4 it is hash
// order. In every case the first match in the slice is NOT the oldest.
//
// cleanupLocked mechanism 2 removes matches[:len(matches)-MaxFiles] — the
// FRONT of that unsorted slice. Consequences under the standing R42/R45/
// R55/R63 threat model (attacker with write access to --pcap-dir plants
// blocked_*.pcap files):
//  1. The firewall's own CURRENT rotation file — the file this rotation
//     just opened and is actively writing blocked-packet evidence into —
//     is unlinked by its own rotation's cleanup. On Linux the unlink
//     succeeds (fd stays valid), so every packet written until the next
//     rotation lands in an orphaned inode and VANISHES on close: the
//     most recent forensic captures are silently destroyed.
//  2. Retention is INVERTED: newer captures are deleted while the
//     OLDEST stale planted files survive — the opposite of the
//     documented "remove oldest" contract. The newest evidence (which an
//     incident responder needs) is exactly what is destroyed.
//
// R69 FIX: (a) sort the matches so removal deterministically targets the
// oldest first, and (b) never remove the file this rotation just opened
// (blocked_%05d.pcap at index curFileN) — it is definitionally not
// stale. Mechanism 1 (indexed removal) already enforces the own-file
// retention cap by index; mechanism 2 exists to prune stale prior-run
// files the index cannot see.
package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// ── R69: cleanup must never unlink the current open rotation file ──────
// The R63 bounded-scan tests count HOW MANY files are examined/removed;
// they never check WHICH files are removed. On a directory whose readdir
// order is not sorted (all real filesystems), mechanism 2 removes
// matches[:len-MaxFiles] — the front of the unsorted slice. The file just
// created by THIS rotation (blocked_%05d.pcap with the highest index) is
// the most recently created entry, so on tmpfs it is the FIRST match and
// is deleted by its own rotation's cleanup.
func TestAttack_CleanupUnsortedRemovalDeletesCurrentRotationFile(t *testing.T) {
	dir := t.TempDir()

	// Attacker plants stale blocked_*.pcap files BEFORE the firewall's
	// rotations start, so the cleanup removal loop has more matches than
	// MaxFiles (the condition that activates mechanism 2).
	for _, idx := range []int{100, 101, 102} {
		name := fmt.Sprintf("blocked_%05d.pcap", idx)
		if err := os.WriteFile(filepath.Join(dir, name), []byte("attacker"), 0644); err != nil {
			t.Fatalf("planting %s: %v", name, err)
		}
	}

	w, err := NewWriter(Config{Dir: dir, MaxFiles: 2, MaxPackets: 1})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	// Each WriteBlock rotates (MaxPackets=1) and runs cleanupLocked on the
	// hot path. The current rotation file must survive its own rotation's
	// cleanup: it is open and receiving the forensic evidence.
	for i := 0; i < 6; i++ {
		if err := w.WriteBlock([]byte("packet-bytes")); err != nil {
			t.Fatalf("WriteBlock %d: %v", i, err)
		}
		cur := fmt.Sprintf("blocked_%05d.pcap", i+1)
		if _, err := os.Stat(filepath.Join(dir, cur)); err != nil {
			t.Errorf("R69 RED: rotation file %s (current, open, receiving writes) was deleted by its own rotation's cleanup — Readdirnames returns directory order, not sorted; mechanism 2 removed the newest files instead of the oldest (silent capture-evidence loss)", cur)
		}
	}
}

// ── R69: retention must not be inverted (newest deleted, oldest kept) ──
// Mechanism 2's removal must target the OLDEST matches: the planted stale
// file (blocked_00000.pcap — sorts before every own file) must be
// pruned, and the current + newest own captures must survive. Pre-fix,
// on tmpfs's reverse-creation Readdirnames order the matches slice is
// [00006 00005 ... 00000] and the removal loop deletes the FRONT — the
// NEWEST files — leaving exactly the oldest ones behind: retention
// fully inverted.
func TestAttack_CleanupUnsortedRemovalKeepsNewestCaptures(t *testing.T) {
	dir := t.TempDir()

	// Plant a stale file that SORTS BEFORE the firewall's own names
	// (blocked_00000.pcap < blocked_00001.pcap lexicographically) — the
	// true "oldest" and the removal loop's intended first target.
	if err := os.WriteFile(filepath.Join(dir, "blocked_00000.pcap"), []byte("attacker"), 0644); err != nil {
		t.Fatalf("planting stale file: %v", err)
	}

	w, err := NewWriter(Config{Dir: dir, MaxFiles: 2, MaxPackets: 1})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	for i := 0; i < 6; i++ {
		if err := w.WriteBlock([]byte("packet-bytes")); err != nil {
			t.Fatalf("WriteBlock %d: %v", i, err)
		}
	}

	// The planted OLDEST file must be pruned (it is the stale target).
	if _, err := os.Stat(filepath.Join(dir, "blocked_00000.pcap")); err == nil {
		t.Errorf("R69 RED: planted stale file blocked_00000.pcap survived cleanup while newer captures were removed — retention inverted (mechanism 2 deleted the front of an unsorted Readdirnames slice)")
	}
	// The CURRENT rotation file (blocked_00006.pcap, open) and the newest
	// retained own capture (blocked_00005.pcap) must survive.
	for _, idx := range []int{5, 6} {
		name := fmt.Sprintf("blocked_%05d.pcap", idx)
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("R69 RED: newest capture %s missing after cleanup — retention inverted (newest deleted, oldest kept) because mechanism 2 removed the front of an unsorted Readdirnames slice", name)
		}
	}
}
