// Red-team security hardening Round 14 — FIFO/named pipe blocking in LoadState
// Attack: If the state file path points to a named pipe (FIFO), os.Open blocks
// indefinitely, causing the firewall engine to hang during startup in
// restoreState(). An attacker with config/CLI influence can set --state-file
// to a FIFO path, preventing the engine from processing any packets (DoS).
//
// FIX: Use os.Stat before os.Open to reject non-regular files (FIFOs,
// directories, device files, sockets).
package persist

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// ── R14.1: LoadState blocks on FIFO/named pipe (DoS) ────────────────
// os.Open on a named pipe blocks until the other end is opened for
// writing. This means LoadState would hang forever if the state file
// path is a FIFO, preventing the engine from starting.
func TestAttack_LoadStateBlocksOnFIFO(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "state.fifo")

	// Create a named pipe (FIFO)
	if err := mkfifo(fifoPath); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}

	// Call LoadState on the FIFO path — must return an error, not block
	done := make(chan struct{})
	var loadErr error
	go func() {
		_, loadErr = LoadState(fifoPath)
		close(done)
	}()

	select {
	case <-done:
		// LoadState returned — it must have returned an error
		if loadErr == nil {
			t.Error("LoadState on FIFO returned nil error — should reject non-regular file")
		} else {
			t.Logf("LoadState correctly rejected FIFO: %v", loadErr)
		}
	case <-time.After(2 * time.Second):
		t.Error("LoadState blocked on FIFO for 2s — os.Open hangs on named pipe, needs file type check before opening")
	}
}

// ── R14.2: LoadState must not block on symlink to FIFO ──────────────
// os.Stat follows symlinks and returns the target file's mode. A symlink
// to a FIFO should also be rejected.
func TestAttack_LoadStateSymlinkToFIFO(t *testing.T) {
	dir := t.TempDir()

	// Create a FIFO
	fifoPath := filepath.Join(dir, "target.fifo")
	if err := mkfifo(fifoPath); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}

	// Create a symlink to the FIFO
	symlinkPath := filepath.Join(dir, "link_to_fifo.json")
	if err := os.Symlink(fifoPath, symlinkPath); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	// Call LoadState on the symlink — must not block
	done := make(chan struct{})
	var loadErr error
	go func() {
		_, loadErr = LoadState(symlinkPath)
		close(done)
	}()

	select {
	case <-done:
		if loadErr == nil {
			t.Error("LoadState via symlink to FIFO returned nil error — should reject")
		} else {
			t.Logf("LoadState correctly rejected symlink to FIFO: %v", loadErr)
		}
	case <-time.After(2 * time.Second):
		t.Error("LoadState blocked on symlink-to-FIFO for 2s — needs os.Stat check before opening")
	}
}

// ── R14.3: LoadState must still work with regular files ─────────────
// Regression test: the fix must not break normal LoadState operation.
func TestAttack_LoadStateRegularFileStillWorks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	// Save a valid state file
	state := &EngineState{BlockStats: map[string]int64{"test": 42}}
	if err := SaveState(path, state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	// LoadState must work normally
	loaded, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState on regular file returned error: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadState returned nil state")
	}
	if loaded.BlockStats["test"] != 42 {
		t.Errorf("expected test=42, got test=%d", loaded.BlockStats["test"])
	}
	t.Log("LoadState with regular file works correctly — regression OK")
}

// ── R14.4: LoadState with non-existent path still returns nil ──────
// Regression: missing file on first run should still return (nil, nil).
func TestAttack_LoadStateMissingFileStillNil(t *testing.T) {
	dir := t.TempDir()
	nonExistent := filepath.Join(dir, "does_not_exist.json")

	state, err := LoadState(nonExistent)
	if err != nil {
		t.Fatalf("LoadState on missing file returned error: %v", err)
	}
	if state != nil {
		t.Error("LoadState on missing file should return nil state")
	}
	t.Log("LoadState with missing file returns (nil, nil) — regression OK")
}

// mkfifo creates a named pipe at the given path.
func mkfifo(path string) error {
	return syscall.Mkfifo(path, 0644)
}
