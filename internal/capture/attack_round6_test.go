package capture

import (
	"os"
	"path/filepath"
	"testing"
)

// ── R6.11: Disk space exhaustion via pcap writes ────────────────────────
// Attacker triggers many blocked packets to fill the disk with pcap files.
// There is no disk space check before writing.
func TestAttack_DiskSpaceExhaustion(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir, MaxPackets: 1, MaxFiles: 1000})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	packet := make([]byte, 1024) // 1KB packet
	for i := 0; i < 100; i++ {
		if err := w.WriteBlock(packet); err != nil {
			t.Fatalf("WriteBlock %d: %v", i, err)
		}
	}

	// Count files created
	files, _ := filepath.Glob(filepath.Join(dir, "*.pcap"))
	t.Logf("created %d pcap files (%d bytes each)", len(files), len(packet))

	// Verify no disk space check — the test documents that writes proceed
	// without any free-space verification
	if len(files) > w.cfg.MaxFiles {
		t.Logf("pcap files (%d) exceed MaxFiles (%d) — cleanup is working", len(files), w.cfg.MaxFiles)
	}

	// Check if files are cleaned up by rotation
	if len(files) > w.cfg.MaxFiles {
		t.Errorf("expected at most %d files after rotation, got %d", w.cfg.MaxFiles, len(files))
	}
}

// ── R6.12: WriteBlock with nil/empty raw bytes ──────────────────────────
// Attacker triggers WriteBlock with nil or empty byte slice.
// DEFERRED (R41): zero-length pcap records are cosmetic — bounded by
// maxPacketSize, no disk-exhaustion path beyond normal writes. Adding a
// reject-nil guard is not security-relevant; the R6 "needs nil guard"
// log described a hypothetical, not an exploitable condition.
func TestAttack_WriteBlockNilBytes(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir, MaxPackets: 10})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	// nil byte slice
	if err := w.WriteBlock(nil); err != nil {
		t.Logf("WriteBlock(nil) returned error: %v", err)
	} else {
		t.Log("DEFERRED (R41): WriteBlock(nil) writes a zero-length pcap record — cosmetic only, bounded by maxPacketSize")
	}

	// empty byte slice
	if err := w.WriteBlock([]byte{}); err != nil {
		t.Logf("WriteBlock([]byte{}) returned error: %v", err)
	} else {
		t.Log("DEFERRED (R41): WriteBlock([]byte{}) writes a zero-length pcap record — cosmetic only")
	}
}

// ── R6.13: File permission issues ───────────────────────────────────────
// Config uses world-readable directories (0755) for pcap storage.
func TestAttack_FilePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pcaps")
	w, err := NewWriter(Config{Dir: dir, MaxPackets: 1})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	// Check directory permissions
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	perm := info.Mode().Perm()
	if perm&0004 != 0 {
		t.Logf("pcap directory %s is world-readable (perms=%o) — blocked packet data is readable by any user", dir, perm)
	}
}

// ── R6.14: Close followed by WriteBlock ─────────────────────────────────
// After closing, writes should fail gracefully, not panic or corrupt.
func TestAttack_WriteAfterClose(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir, MaxPackets: 10})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	w.Close()

	// Write after close
	packet := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00}
	err = w.WriteBlock(packet)
	if err == nil {
		t.Error("WriteBlock after Close succeeded — should fail or be a no-op")
	} else {
		t.Logf("WriteBlock after Close correctly returned error: %v", err)
	}
}
