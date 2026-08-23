// Red-team security hardening Round 60 — glob metacharacter injection into
// capture's rotation-file cleanup pattern.
//
// cleanupLocked() builds its match pattern from the operator/attacker-
// influenced --pcap-dir: pattern := filepath.Join(cfg.Dir, "blocked_*.pcap").
// filepath.Glob interprets glob metacharacters (*, ?, [) IN the directory
// component of the pattern — a dir like /base/pcaps[1] expands to match
// /base/pcaps1/blocked_*.pcap (the literal SIBLING directory), so:
//
//	(1) os.Remove deletes blocked_*.pcap files in sibling directories the
//	    firewall never wrote to (arbitrary deletion as the firewall's UID,
//	    which for nfqueue is typically root), and
//	(2) the firewall's OWN rotation files in the literal /base/pcaps[1]
//	    directory never match the pattern, so cleanup silently never runs
//	    and the MaxFiles cap is defeated — unbounded disk growth (the
//	    R13/R57/R59 path guards reject ".." and symlink components but
//	    never considered glob metacharacters in the path).
//
// R60 FIX: list the configured directory with os.ReadDir and filter by
// filename prefix/suffix instead of globbing — ReadDir has no pattern
// interpretation, so the match set is exactly the files in the configured
// directory and nothing else.
package capture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── R60.1: cleanup must NOT delete sibling-directory files via glob metachars ──
// RED (pre-fix): cfg.Dir = /base/pcaps[1] makes the glob pattern
// /base/pcaps[1]/blocked_*.pcap match /base/pcaps1/blocked_*.pcap; when the
// sibling dir holds more files than MaxFiles, cleanupLocked os.Removes the
// oldest of THEM — deleting files the firewall never created. GREEN
// (post-fix): ReadDir on the literal dir finds nothing in pcaps1; victims
// survive.
func TestAttack_CleanupGlobMetacharNoSiblingDeletion(t *testing.T) {
	base := t.TempDir()
	cfgDir := filepath.Join(base, "pcaps[1]") // literal dir with glob metachars
	siblingDir := filepath.Join(base, "pcaps1")
	if err := os.MkdirAll(cfgDir, 0755); err != nil {
		t.Fatalf("mkdir cfgDir: %v", err)
	}
	if err := os.MkdirAll(siblingDir, 0755); err != nil {
		t.Fatalf("mkdir siblingDir: %v", err)
	}

	// Victim files in the SIBLING directory (never created by the writer).
	// Three victims with MaxFiles=1: the vulnerable glob matches all three
	// and deletes the two lexicographically oldest.
	victims := []string{"blocked_00001.pcap", "blocked_00002.pcap", "blocked_00003.pcap"}
	for _, v := range victims {
		if err := os.WriteFile(filepath.Join(siblingDir, v), []byte("victim"), 0644); err != nil {
			t.Fatalf("write victim: %v", err)
		}
	}

	w, err := NewWriter(Config{Dir: cfgDir, MaxFiles: 1, MaxPackets: 1})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	// Write enough packets to trigger several rotations (each rotation runs
	// cleanupLocked).
	for i := 0; i < 6; i++ {
		if err := w.WriteBlock([]byte("packet-bytes")); err != nil {
			t.Fatalf("WriteBlock %d: %v", i, err)
		}
	}

	// Assertion 1: no sibling victim may be deleted.
	for _, v := range victims {
		if _, err := os.Stat(filepath.Join(siblingDir, v)); err != nil {
			t.Errorf("R60 RED: sibling victim %s was deleted by glob metachar expansion (%v)", v, err)
		}
	}

	// Assertion 2: the writer's own files in the literal dir must be capped
	// at MaxFiles — a glob that never matches them defeats the cap. List
	// with os.ReadDir (never Glob — the path contains metacharacters).
	entries, err := os.ReadDir(cfgDir)
	if err != nil {
		t.Fatalf("read own dir: %v", err)
	}
	own := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "blocked_") && strings.HasSuffix(e.Name(), ".pcap") {
			own++
		}
	}
	if own > w.cfg.MaxFiles {
		t.Errorf("R60 RED: %d own files in literal dir exceed MaxFiles=%d — cleanup never matches them", own, w.cfg.MaxFiles)
	}
}

// ── R60.2: cleanup must still enforce MaxFiles on a normal directory ──
// Regression guard: the ReadDir fix must preserve the rotation-cap behavior
// that the glob provided for ordinary paths (the R11.9 contract).
func TestAttack_CleanupGlobMetacharNormalDirStillCapped(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir, MaxFiles: 2, MaxPackets: 1})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	for i := 0; i < 8; i++ {
		if err := w.WriteBlock([]byte("packet-bytes")); err != nil {
			t.Fatalf("WriteBlock %d: %v", i, err)
		}
	}

	files, _ := filepath.Glob(filepath.Join(dir, "blocked_*.pcap"))
	if len(files) > w.cfg.MaxFiles {
		t.Errorf("expected at most %d files after cleanup, got %d", w.cfg.MaxFiles, len(files))
	}
}
