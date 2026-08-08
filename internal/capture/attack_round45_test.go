package capture

import (
	"os"
	"path/filepath"
	"testing"
)

// ── R45.6: NewWriter pcap directory symlink write-through ───────────
// R42 hardened the rotation FILE open with O_NOFOLLOW, but a symlink at
// the DIRECTORY path (--pcap-dir) is followed: os.MkdirAll on a symlink
// "succeeds" (the path exists as a dir through the link) and every
// blocked_%05d.pcap rotation file lands in the attacker-chosen target
// directory as the firewall's UID. O_NOFOLLOW only protects the final
// component; intermediate directory symlinks are resolved by the kernel.
func TestAttack_NewWriterDirectorySymlinkWriteThrough(t *testing.T) {
	victimDir := t.TempDir()

	parentDir := t.TempDir()
	pcapDir := filepath.Join(parentDir, "pcap")
	if err := os.Symlink(victimDir, pcapDir); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	w, err := NewWriter(Config{Dir: pcapDir})
	if err == nil && w != nil {
		// If NewWriter accepted the symlinked dir, force a rotation and
		// check where the file landed
		if werr := w.WriteBlock([]byte("attack")); werr == nil {
			matches, _ := filepath.Glob(filepath.Join(victimDir, "blocked_*.pcap"))
			if len(matches) > 0 {
				t.Errorf("pcap file written into victim directory through symlink: %v", matches)
			}
		}
		t.Errorf("NewWriter accepted a symlinked pcap directory — expected rejection")
	}
}

// ── R45.7: NewWriter still works on a genuine directory ─────────────
func TestAttack_NewWriterRealDirectoryStillWorks(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir})
	if err != nil {
		t.Fatalf("NewWriter on a real directory failed: %v", err)
	}
	if w == nil {
		t.Fatal("NewWriter returned nil on a real directory")
	}
	if err := w.WriteBlock([]byte("hello")); err != nil {
		t.Fatalf("WriteBlock on real dir failed: %v", err)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "blocked_*.pcap"))
	if len(matches) != 1 {
		t.Errorf("expected 1 pcap file in real dir, got %d", len(matches))
	}
}
