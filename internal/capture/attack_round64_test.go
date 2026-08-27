package capture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── R64.1: rotation-time directory symlink swap (capture) ───────────
// R45's securepath walk runs ONCE at NewWriter; every rotation re-opens
// paths derived from cfg.Dir FRESH (the blocked_%05d.pcap create in
// rotateLocked and the cleanup directory scan). An attacker with write
// access to the PARENT of --pcap-dir (rename + symlink creation — a
// strictly weaker requirement than the documented R42/R45/R55 model of
// write access to the directory itself; e.g. any local user can rename
// anything under the world-writable /tmp) can, at ANY time during the
// firewall's run, rename the real directory away and plant a symlink to
// an arbitrary directory the firewall's UID (typically root) can write.
// The next rotation then creates/truncates blocked_%05d.pcap and
// deletes blocked_*.pcap in the attacker-chosen directory as the
// firewall's UID — the R45 write-through class, previously only closed
// for directories that were ALREADY symlinks at construction time.
func TestAttack_RotateDirectorySymlinkSwapNoWriteThrough(t *testing.T) {
	parentDir := t.TempDir()
	dir := filepath.Join(parentDir, "pcaps")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir pcap dir: %v", err)
	}
	victimDir := t.TempDir()

	w, err := NewWriter(Config{Dir: dir, MaxPackets: 2, MaxFiles: 5})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	// Rotation 1 into the real directory (2 packets per file).
	if err := w.WriteBlock([]byte("packet-1")); err != nil {
		t.Fatalf("WriteBlock 1: %v", err)
	}
	if err := w.WriteBlock([]byte("packet-2")); err != nil {
		t.Fatalf("WriteBlock 2: %v", err)
	}

	// Attacker swaps the configured directory for a symlink to the victim
	// directory (rename + symlink in the PARENT, which the attacker owns
	// or which is world-writable).
	orig := dir + ".orig"
	if err := os.Rename(dir, orig); err != nil {
		t.Fatalf("rename pcap dir: %v", err)
	}
	if err := os.Symlink(victimDir, dir); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}

	// Rotation 2: the next blocked packets must NOT be captured through
	// the swapped-in symlink into the victim directory.
	_ = w.WriteBlock([]byte("packet-3"))
	_ = w.WriteBlock([]byte("packet-4"))

	entries, err := os.ReadDir(victimDir)
	if err != nil {
		t.Fatalf("reading victim dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "blocked_") {
			t.Errorf("pcap file written into victim directory through swapped-in dir symlink: %s", e.Name())
		}
	}
}

// ── R64.2: regression — real directories still rotate after the check ─
// The R64 fix must not break normal rotation on genuine directories.
func TestAttack_RotateRealDirectoryStillWorks(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir, MaxPackets: 2, MaxFiles: 5})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for i := 0; i < 6; i++ {
		if err := w.WriteBlock([]byte("packet")); err != nil {
			t.Fatalf("WriteBlock %d: %v", i, err)
		}
	}
	matches, err := filepath.Glob(filepath.Join(dir, "blocked_*.pcap"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) != 3 {
		t.Errorf("expected 3 rotation files for 6 packets/2-per-file, got %d", len(matches))
	}
}
