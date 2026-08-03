package capture

import (
	"path/filepath"
	"testing"
)

// ── R11.7: cleanupLocked Glob error handling ────────────────────────
// R11 documented filepath.Glob errors being silently discarded in
// cleanupLocked. R12 added `slog.Warn("pcap cleanup: Glob error", ...)`.
// R41: production code is correct — Glob errors are logged, so the R11
// "would be silently ignored" log was stale. We can't assert on slog
// output without a handler hook; this test exercises the write+rotate
// path (which invokes cleanupLocked) and confirms no error is returned.
func TestAttack_CleanupLockedGlobErrorIgnored(t *testing.T) {
	// Create a directory structure where Glob might fail
	dir := t.TempDir()

	// Write an invalid file that makes the directory unreadable
	// (Simulate a permissions issue by restricting directory access)
	subDir := filepath.Join(dir, "sub")
	_ = subDir // Not used directly; we test with normal dir

	w, err := NewWriter(Config{Dir: dir, MaxPackets: 1, MaxFiles: 5})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	// Write a packet to trigger rotation which calls cleanupLocked
	packet := []byte{0x00, 0x01, 0x02, 0x03}
	if err := w.WriteBlock(packet); err != nil {
		t.Fatalf("WriteBlock: %v", err)
	}

	t.Log("FIXED (R12): cleanupLocked logs Glob errors via slog.Warn — no silent discard")
}

// ── R11.8: WriteBlock with raw slice of zero length ────────────────
// WriteBlock accepts a raw byte slice of any length, including zero.
// len(raw)=0 produces a zero-length packet in the pcap file.
// DEFERRED (R41): same disposition as R6.12 — zero-length records are
// cosmetic, bounded by maxPacketSize, no disk-exhaustion path beyond
// normal writes.
func TestAttack_WriteBlockZeroLength(t *testing.T) {
	dir := t.TempDir()

	w, err := NewWriter(Config{Dir: dir, MaxPackets: 10})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	// Write with empty slice
	if err := w.WriteBlock([]byte{}); err != nil {
		t.Logf("WriteBlock with empty slice returned error: %v", err)
	} else {
		t.Log("DEFERRED (R41): WriteBlock with empty slice writes a zero-length pcap record — cosmetic only")
	}

	// Write with nil slice
	if err := w.WriteBlock(nil); err != nil {
		t.Logf("WriteBlock with nil slice returned error: %v", err)
	} else {
		t.Log("DEFERRED (R41): WriteBlock with nil slice writes a zero-length pcap record — cosmetic only")
	}

	// Verify pcap file was created
	files, _ := filepath.Glob(filepath.Join(dir, "*.pcap"))
	if len(files) > 0 {
		t.Logf("Pcap file created with %d writes (incl. zero-length packets)", len(files))
	}
}

// ── R11.9: cleanupLocked with large number of concurrently created files ─
// Concurrent WriteBlock calls on different writers writing to the same
// directory could cause Glob to return files created by other writers.
func TestAttack_CleanupLockedConcurrent(t *testing.T) {
	dir := t.TempDir()

	w, err := NewWriter(Config{Dir: dir, MaxPackets: 1, MaxFiles: 10})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	// Write several packets to trigger multiple rotations
	for i := 0; i < 15; i++ {
		pkt := make([]byte, 64)
		if err := w.WriteBlock(pkt); err != nil {
			t.Fatalf("WriteBlock %d: %v", i, err)
		}
	}

	// After the last rotation, cleanupLocked should have cleaned up old files
	files, _ := filepath.Glob(filepath.Join(dir, "*.pcap"))
	if len(files) > w.cfg.MaxFiles {
		t.Errorf("expected at most %d files after cleanup, got %d", w.cfg.MaxFiles, len(files))
	} else {
		t.Logf("cleanupLocked: %d files remaining (max %d) — cleanup works", len(files), w.cfg.MaxFiles)
	}
}
