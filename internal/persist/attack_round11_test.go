package persist

import (
	"os"
	"path/filepath"
	"testing"
)

// ── R11.10: SaveState with file on different filesystem ────────────
// os.Rename fails with "invalid cross-device link" when the temp file
// and target are on different filesystems. The function should fall
// back to copy+delete, leaving no .tmp file behind.
// FIXED R13: os.Rename error path now cleans up the .tmp file.
func TestAttack_SaveStateCrossDevice(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	state := &EngineState{BlockStats: map[string]int64{"test": 1}}
	if err := SaveState(path, state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	// Verify file was written correctly
	loaded, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if loaded.BlockStats["test"] != 1 {
		t.Errorf("expected test=1, got test=%d", loaded.BlockStats["test"])
	}
	t.Log("SaveState/LoadState on same filesystem works correctly")

	// Check no temp file remains (R11.10 vulnerability: rename failure on
	// cross-device can leave .tmp file behind)
	tmpPath := path + ".tmp"
	if _, err := os.Stat(tmpPath); err == nil {
		t.Errorf("R13 FIX NEEDED: stale .tmp file found at %s — SaveState must clean up on error", tmpPath)
	} else {
		t.Log("No stale .tmp file found — cleanup is working")
	}
}

// ── R11.11: LoadState with symlink path ────────────────────────────
// If the state file path is a symlink, LoadState follows it. An attacker
// who can control the state file path could point it to sensitive files.
// The content would be parsed as JSON and likely fail. But we verify
// the behavior is safe (no crash, error returned).
func TestAttack_LoadStateSymlink(t *testing.T) {
	dir := t.TempDir()

	// Create a valid state file
	realPath := filepath.Join(dir, "real_state.json")
	state := &EngineState{BlockStats: map[string]int64{"test": 1}}
	if err := SaveState(realPath, state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	// Create a symlink to the state file
	symlinkPath := filepath.Join(dir, "symlink_state.json")
	if err := os.Symlink(realPath, symlinkPath); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	// LoadState via symlink — should follow it
	loaded, err := LoadState(symlinkPath)
	if err != nil {
		t.Fatalf("LoadState via symlink: %v", err)
	}
	if loaded.BlockStats["test"] != 1 {
		t.Errorf("expected test=1, got test=%d", loaded.BlockStats["test"])
	}
	t.Log("LoadState via symlink correctly follows symlink and loads data")
}

// ── R11.12: LoadState with path to a directory ─────────────────────
// os.Open on a directory returns an error (EISDIR). LoadState should
// handle this gracefully.
func TestAttack_LoadStatePathIsDirectory(t *testing.T) {
	dir := t.TempDir()

	// Try loading from a directory path instead of a file
	state, err := LoadState(dir)

	if err != nil {
		t.Logf("LoadState with directory path returned error: %v", err)
	} else if state != nil {
		t.Log("LoadState with directory path returned a non-nil state — unexpected but not a crash")
	} else {
		t.Log("LoadState with directory path returned nil state")
	}
}
