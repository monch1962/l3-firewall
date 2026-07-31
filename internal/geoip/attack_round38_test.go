// Red-team security hardening Round 38 — FIFO startup DoS + oversized DB in geoip.NewReader
//
// R14/R15 fixed persist.LoadState blocking on FIFO paths. geoip.NewReader
// calls maxminddb.Open(path) which os.Open()s the path internally — a FIFO
// at the --geoip-db path blocks startup indefinitely (same DoS class).
// Additionally, maxminddb.Open mmaps/reads the whole file with no size cap
// (R8 class: memory exhaustion from an oversized attacker-influenced file).
//
// geoip package had zero attack-test coverage prior to this round.
package geoip

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func mkfifo(path string) error {
	return syscall.Mkfifo(path, 0644)
}

// ── R38.1: NewReader must not block on a FIFO at the DB path ─────────
func TestAttack_NewReaderMustNotBlockOnFIFO(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "geo.mmdb")

	if err := mkfifo(fifoPath); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}

	done := make(chan struct{})
	go func() {
		_, _ = NewReader(fifoPath)
		close(done)
	}()

	select {
	case <-done:
		t.Log("NewReader returned on FIFO path — no startup hang")
	case <-time.After(2 * time.Second):
		t.Error("NewReader blocked on FIFO for 2s — startup DoS (R14/R15 class)")
	}
}

// ── R38.2: NewReader must reject a FIFO (non-regular) DB path ────────
func TestAttack_NewReaderRejectsFIFOPath(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "geo.fifo")

	if err := mkfifo(fifoPath); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}

	done := make(chan struct{})
	var readerErr error
	go func() {
		_, readerErr = NewReader(fifoPath)
		close(done)
	}()

	select {
	case <-done:
		if readerErr == nil {
			t.Error("NewReader opened FIFO without error — should reject non-regular file")
		} else {
			t.Logf("NewReader correctly rejected FIFO: %v", readerErr)
		}
	case <-time.After(2 * time.Second):
		t.Error("NewReader blocked on FIFO for 2s — still hanging")
	}
}

// ── R38.3: NewReader must reject oversized DB files (R8 memory class) ─
// A file larger than maxGeoIPFileSize must be rejected before being
// mmap'd/read into memory, preventing memory exhaustion from an
// attacker-influenced --geoip-db path.
func TestAttack_NewReaderRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.mmdb")

	// Create a sparse file just over the size cap — no real disk usage,
	// but os.Stat reports the full logical size.
	big := int64(maxGeoIPFileSize) + 1024
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.Truncate(big); err != nil {
		f.Close()
		t.Fatalf("truncate to %d: %v", big, err)
	}
	f.Close()

	_, err = NewReader(path)
	if err == nil {
		t.Errorf("NewReader accepted %d-byte file (cap %d) — memory exhaustion vector (R8 class)", big, maxGeoIPFileSize)
	} else {
		t.Logf("NewReader correctly rejected oversized file: %v", err)
	}
}

// ── R38.4: NewReader still works for small/bad regular files ─────────
// Regression: empty path → nil, nil; bad file → error (not hang).
func TestAttack_NewReaderRegularFileStillWorks(t *testing.T) {
	// Empty path disabled
	r, err := NewReader("")
	if err != nil {
		t.Fatalf("NewReader(\"\") returned error: %v", err)
	}
	if r != nil {
		t.Error("NewReader(\"\") should return nil reader")
	}

	// Random (invalid mmdb) regular file → error, not hang
	dir := t.TempDir()
	path := filepath.Join(dir, "bogus.mmdb")
	if err := os.WriteFile(path, []byte("this is not a maxmind db"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	done := make(chan struct{})
	go func() {
		_, _ = NewReader(path)
		close(done)
	}()
	select {
	case <-done:
		t.Log("NewReader returned promptly on invalid regular file")
	case <-time.After(2 * time.Second):
		t.Error("NewReader blocked on regular file — unexpected")
	}
}
