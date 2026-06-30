package capture

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// ── R8.9: Config.Dir path traversal ───────────────────────────────────
// Config.Dir is used directly in filepath.Join to create pcap files.
// A malicious or misconfigured Dir could write files outside the
// intended capture directory.
func TestAttack_DirPathTraversal(t *testing.T) {
	baseDir := t.TempDir()
	traversalDir := filepath.Join(baseDir, "..", "..", "pcap_escape")

	w, err := NewWriter(Config{Dir: traversalDir, MaxPackets: 1, MaxFiles: 3})
	if err != nil {
		t.Fatalf("NewWriter with traversal dir: %v", err)
	}
	defer w.Close()

	packet := []byte{0x00, 0x01, 0x02, 0x03}
	if err := w.WriteBlock(packet); err != nil {
		t.Fatalf("WriteBlock: %v", err)
	}

	// File should exist at the traversal path, not inside baseDir
	outsidePath := filepath.Join(baseDir, "..", "..", "pcap_escape")
	if _, err := os.Stat(outsidePath); err == nil {
		t.Log("pcap files created outside intended directory via path traversal")
	} else {
		t.Logf("Traversal path not found: %v", err)
	}
}

// ── R8.10: RotateLocked with extreme file number handling ─────────────
// After many rotations, curFileN could theoretically overflow int.
// While impractical to overflow, we verify the behavior at boundaries.
func TestAttack_RotateExtremeFileNumber(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir, MaxPackets: 1, MaxFiles: 100})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	// Simulate a high curFileN by setting it directly
	w.mu.Lock()
	w.curFileN = 99999
	w.mu.Unlock()

	packet := []byte{0x00, 0x01, 0x02, 0x03}
	if err := w.WriteBlock(packet); err != nil {
		t.Fatalf("WriteBlock with high file number: %v", err)
	}

	w.mu.Lock()
	t.Logf("curFileN after rotation at high boundary: %d", w.curFileN)
	files, _ := filepath.Glob(filepath.Join(dir, "blocked_*.pcap"))
	w.mu.Unlock()

	if len(files) == 0 {
		t.Error("expected at least one pcap file after rotation")
	}
}

// ── R8.11: Concurrent Close and WriteBlock ────────────────────────────
// Calling Close() while WriteBlock is in progress should not cause a
// data race. The mutex should protect both operations.
func TestAttack_ConcurrentCloseAndWrite(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir, MaxPackets: 100, MaxFiles: 10})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	packet := make([]byte, 100)
	var wg sync.WaitGroup

	// Writer goroutines
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = w.WriteBlock(packet)
			}
		}(i)
	}

	// Close goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = w.Close()
	}()

	wg.Wait()

	t.Log("Concurrent Close and WriteBlock completed without data race")
	// Verify post-close behavior
	err = w.WriteBlock(packet)
	if err == nil {
		t.Log("WriteBlock after concurrent Close succeeded (possibly before Close completed)")
	} else {
		t.Logf("WriteBlock after concurrent Close correctly returned: %v", err)
	}
}

// ── R8.12: Large packet write ─────────────────────────────────────────
// An unusually large raw packet (multi-MB) should not cause issues.
func TestAttack_LargePacketWrite(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir, MaxPackets: 5, MaxFiles: 3})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	// 10MB "packet"
	largePkt := make([]byte, 10*1024*1024)
	if err := w.WriteBlock(largePkt); err != nil {
		t.Logf("WriteBlock with 10MB packet returned error: %v", err)
	} else {
		t.Log("WriteBlock with 10MB packet succeeded")
	}

	files, _ := filepath.Glob(filepath.Join(dir, "*.pcap"))
	if len(files) > 0 {
		info, _ := os.Stat(files[0])
		if info != nil {
			t.Logf("Pcap file size: %d MB", info.Size()/(1024*1024))
		}
	}
}
