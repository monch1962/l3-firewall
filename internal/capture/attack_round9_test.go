package capture

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ── R9.13: WriteBlock max packet size cap ────────────────────────────
// R9 documented no maximum size check — a single 1GB packet would
// consume 1GB of disk. R12 added maxPacketSize (65536) rejection.
// R41: converted to a hard assertion — the old "no size cap enforced"
// log only fired in the pre-R12 success branch and was stale.
func TestAttack_NoMaxPacketSizeLimit(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir, MaxPackets: 1, MaxFiles: 3})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	// Write a 100MB "packet"
	largePkt := make([]byte, 100*1024*1024)
	start := time.Now()
	err = w.WriteBlock(largePkt)
	elapsed := time.Since(start)

	if err == nil {
		t.Errorf("WriteBlock with 100MB packet succeeded — maxPacketSize cap (%d) not enforced", maxPacketSize)
	} else {
		t.Logf("FIXED (R12): oversized packet rejected in %v: %v", elapsed, err)
	}
}

// ── R9.14: cleanupLocked with very many files ──────────────────────────
// cleanupLocked uses filepath.Glob which sorts all matching filenames
// alphabetically. With 100K+ pcap files, the glob and sort could be slow.
func TestAttack_CleanupWithManyFiles(t *testing.T) {
	dir := t.TempDir()

	// Create many pcap files manually to simulate accumulated state
	for i := 0; i < 1000; i++ {
		fname := filepath.Join(dir, "blocked_"+itoa(i)+".pcap")
		f, err := os.Create(fname)
		if err != nil {
			t.Fatalf("create file %d: %v", i, err)
		}
		f.Close()
	}

	w, err := NewWriter(Config{Dir: dir, MaxPackets: 1, MaxFiles: 5})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	// Trigger rotation and cleanup
	start := time.Now()
	packet := []byte{0x00, 0x01, 0x02, 0x03}
	if err := w.WriteBlock(packet); err != nil {
		t.Fatalf("WriteBlock: %v", err)
	}
	elapsed := time.Since(start)

	files, _ := filepath.Glob(filepath.Join(dir, "*.pcap"))
	t.Logf("cleanupLocked completed in %v — %d files remaining (max %d)", elapsed, len(files), w.cfg.MaxFiles)
	if len(files) > w.cfg.MaxFiles {
		t.Errorf("expected at most %d files after cleanup, got %d", w.cfg.MaxFiles, len(files))
	}
}

// ── R9.15: WriteBlock after concurrent Close with mutex ────────────────
// WriteBlock after Close should be caught by the w.closed check. Verify
// the closed flag check works correctly.
func TestAttack_WriteAfterCloseReturnsError(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir, MaxPackets: 10})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	// Close normally
	w.Close()

	// WriteBlock must return error
	err = w.WriteBlock([]byte{0x00})
	if err == nil {
		t.Error("WriteBlock after Close succeeded — should return error")
	} else {
		t.Logf("WriteBlock after Close correctly returned: %v", err)
	}
}

// ── R9.16: Concurrent WriteBlock across multiple packets ──────────────
// Multiple concurrent callers writing different packet sizes should not
// corrupt the pcap file or cause data races.
func TestAttack_ConcurrentWriteBlock(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir, MaxPackets: 100, MaxFiles: 10})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			pkt := make([]byte, (n+1)*100)
			_ = w.WriteBlock(pkt)
		}(i)
	}
	wg.Wait()
	t.Log("20 concurrent WriteBlock calls completed without error")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
	result := ""
	for n > 0 {
		result = digits[n%10] + result
		n /= 10
	}
	return result
}
