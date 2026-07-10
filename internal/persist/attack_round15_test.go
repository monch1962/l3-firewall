// Red-team security hardening Round 15 — TOCTOU in LoadState between os.Stat and os.Open
//
// The R14 fix uses os.Stat before os.Open to reject non-regular files (FIFOs).
// This is vulnerable to a TOCTOU (time-of-check-time-of-use) race: an attacker
// with write access to the state directory can replace the regular file with a
// FIFO between the Stat and Open calls.
//
// R15 FIX: Use os.OpenFile with syscall.O_NONBLOCK to open first (never blocks
// on FIFO), then f.Stat() on the already-opened fd to check the file type.
// On Linux, O_NONBLOCK has no effect on regular file reads, so subsequent
// JSON decoding works normally.
package persist

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// ── R15.1: os.Open blocks on FIFO (the root mechanism behind the DoS) ──
// Proving that os.Open on a FIFO without the Stat guard blocks indefinitely.
// This is the root cause that both R14 (Stat then Open) and R15 (O_NONBLOCK
// then f.Stat) fix. R15's approach eliminates the TOCTOU between the Stat
// and Open calls by checking the file type on the already-opened fd.
func TestAttack_OSOpenBlocksOnFIFO(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "direct.fifo")

	if err := syscall.Mkfifo(fifoPath, 0644); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}

	// Direct os.Open on a FIFO — must NOT block (showing the root cause)
	// This test demonstrates why the Stat check is needed AND why the
	// Stat-then-Open pattern has a TOCTOU race: if the file is replaced
	// between Stat and Open, os.Open blocks here.
	done := make(chan struct{})
	var openErr error
	go func() {
		_, openErr = os.Open(fifoPath)
		close(done)
	}()

	select {
	case <-done:
		t.Logf("os.Open on FIFO returned unexpectedly: %v (may indicate O_NONBLOCK or other mechanism)", openErr)
	case <-time.After(500 * time.Millisecond):
		t.Log("os.Open blocks on FIFO — root cause confirmed: the Stat guard prevents this,")
		t.Log("but the TOCTOU race between Stat and Open means a file replaced after Stat")
		t.Log("still causes blocking. R15 fixes this with O_NONBLOCK+fstat.")
	}
}

// ── R15.2: O_NONBLOCK does NOT block on FIFO ───────────────────────────
// Proving that os.OpenFile with syscall.O_NONBLOCK opens a FIFO immediately,
// eliminating the blocking that os.Open would cause.
func TestAttack_ONonBlockDoesNotBlockOnFIFO(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "nonblock.fifo")

	if err := syscall.Mkfifo(fifoPath, 0644); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}

	// Open with O_NONBLOCK — must NOT block
	done := make(chan struct{})
	go func() {
		f, err := os.OpenFile(fifoPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Errorf("OpenFile O_NONBLOCK on FIFO failed: %v", err)
		} else {
			f.Close()
		}
		close(done)
	}()

	select {
	case <-done:
		t.Log("O_NONBLOCK opened FIFO immediately — no blocking, TOCTOU-safe")
	case <-time.After(2 * time.Second):
		t.Error("O_NONBLOCK blocked on FIFO for 2s — O_NONBLOCK not working!")
	}
}

// ── R15.3: LoadState with O_NONBLOCK on regular file works ──────────────
// When LoadState opens a regular file with O_NONBLOCK, the subsequent f.Stat()
// correctly returns IsRegular=true and JSON decoding works normally.
func TestAttack_LoadStateONonBlockRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	// Create a valid state file
	state := &EngineState{BlockStats: map[string]int64{"test": 99}}
	if err := SaveState(path, state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	// LoadState must still work normally (O_NONBLOCK has no effect on regular file reads)
	loaded, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState on regular file with O_NONBLOCK returned error: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadState returned nil state")
	}
	if loaded.BlockStats["test"] != 99 {
		t.Errorf("expected test=99, got test=%d", loaded.BlockStats["test"])
	}
	t.Log("LoadState with O_NONBLOCK on regular file works correctly — regression OK")
}

// ── R15.4: LoadState must handle FIFO with O_NONBLOCK instead of blocking ──
// The old approach (os.Stat then os.Open) blocks if the file is replaced with
// a FIFO between the Stat and Open. The new approach (os.OpenFile with
// O_NONBLOCK then f.Stat()) never blocks because O_NONBLOCK opens FIFOs
// immediately. The file type is checked on the opened fd, eliminating the
// TOCTOU race window.
func TestAttack_LoadStateONonBlockBlocksOnFIFO(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "state.fifo")

	// Create a named pipe (FIFO)
	if err := mkfifo(fifoPath); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}

	// Call LoadState on the FIFO path — must return an error immediately,
	// not block, because O_NONBLOCK opens FIFOs without waiting for a writer.
	done := make(chan struct{})
	var loadErr error
	go func() {
		_, loadErr = LoadState(fifoPath)
		close(done)
	}()

	select {
	case <-done:
		if loadErr == nil {
			t.Error("LoadState on FIFO returned nil error — should reject non-regular file")
		} else {
			t.Logf("LoadState correctly rejected FIFO via O_NONBLOCK+fstat: %v", loadErr)
		}
	case <-time.After(2 * time.Second):
		t.Error("LoadState blocked on FIFO for 2s — O_NONBLOCK should prevent blocking on FIFO")
	}
}

// ── R15.5: LoadState must reject directories via O_NONBLOCK ────────────
// Directories opened with O_RDONLY succeed on Linux, but json.Decode would
// fail (or block on some FS types). The O_NONBLOCK+fstat approach must
// also reject directories.
func TestAttack_LoadStateRejectsDirectory(t *testing.T) {
	dir := t.TempDir()

	// Call LoadState on the directory itself — must return an error
	done := make(chan struct{})
	var loadErr error
	go func() {
		_, loadErr = LoadState(dir)
		close(done)
	}()

	select {
	case <-done:
		if loadErr == nil {
			t.Error("LoadState on directory returned nil error — should reject non-regular file")
		} else {
			t.Logf("LoadState correctly rejected directory: %v", loadErr)
		}
	case <-time.After(2 * time.Second):
		t.Error("LoadState blocked on directory for 2s")
	}
}

// ── R15.4: O_NONBLOCK+fstat on FIFO returns correct file type ─────────
// Direct verification that os.OpenFile with syscall.O_NONBLOCK followed by
// f.Stat() identifies FIFOs correctly, and that O_NONBLOCK prevents
// blocking on FIFO open.
func TestAttack_ONonBlockFstatCatchesFIFO(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "test.fifo")

	if err := mkfifo(fifoPath); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}

	// Open with O_NONBLOCK — must NOT block
	done := make(chan struct{})
	var isRegular bool
	go func() {
		f, err := os.OpenFile(fifoPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Errorf("OpenFile with O_NONBLOCK on FIFO failed: %v", err)
			close(done)
			return
		}
		defer f.Close()

		fi, err := f.Stat()
		if err != nil {
			t.Errorf("f.Stat on FIFO fd failed: %v", err)
			close(done)
			return
		}
		isRegular = fi.Mode().IsRegular()
		close(done)
	}()

	select {
	case <-done:
		if isRegular {
			t.Error("O_NONBLOCK+fstat reported FIFO as regular file — file type detection broken")
		} else {
			t.Log("O_NONBLOCK opened FIFO immediately, fstat correctly identified non-regular")
		}
	case <-time.After(2 * time.Second):
		t.Error("OpenFile with O_NONBLOCK blocked on FIFO for 2s — O_NONBLOCK not working")
	}
}

// ── R15.5: O_NONBLOCK + regular file reads work normally ────────────────
// Verify that opening a regular file with O_NONBLOCK and then reading from
// it works identically to a normal open. O_NONBLOCK should not affect reads
// from regular files on Linux.
func TestAttack_ONonBlockRegularFileReadWorks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "readtest.json")
	content := `{"block_stats":{"key":1}}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Open with O_NONBLOCK and read
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("OpenFile with O_NONBLOCK: %v", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("f.Stat: %v", err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatal("fstat of regular file returned non-regular")
	}

	// Read the file content through the O_NONBLOCK fd
	buf := make([]byte, len(content))
	n, err := f.Read(buf)
	if err != nil {
		t.Fatalf("Read from O_NONBLOCK fd: %v", err)
	}
	if string(buf[:n]) != content {
		t.Errorf("Read content mismatch: got %q, want %q", string(buf[:n]), content)
	}
	t.Log("O_NONBLOCK + read on regular file works correctly")
}

// ── R15.6: Non-existent path still returns nil with O_NONBLOCK ─────────
// Regression: LoadState on a missing file must still return (nil, nil)
// with the O_NONBLOCK approach.
func TestAttack_LoadStateONonBlockMissingFile(t *testing.T) {
	dir := t.TempDir()
	nonExistent := filepath.Join(dir, "does_not_exist.json")

	state, err := LoadState(nonExistent)
	if err != nil {
		t.Fatalf("LoadState on missing file returned error: %v", err)
	}
	if state != nil {
		t.Error("LoadState on missing file should return nil state")
	}
	t.Log("LoadState with O_NONBLOCK on missing file returns (nil, nil) — regression OK")
}
