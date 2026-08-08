package persist

import (
	"os"
	"path/filepath"
	"testing"
)

// ── R45.4: SaveState directory symlink write-through ────────────────
// R42 hardened the .tmp FILE open with O_NOFOLLOW, but O_NOFOLLOW only
// protects the FINAL path component. If an attacker plants a symlink at
// the DIRECTORY path (e.g. --state-file /tmp/state/state.json where
// /tmp/state is a symlink to an attacker-chosen victim directory),
// os.MkdirAll succeeds (the symlink "exists" as a dir) and every write
// resolves THROUGH the symlink into the victim directory as the
// firewall's UID — an arbitrary file create/truncate primitive one level
// up from R42's file-level symlink.
func TestAttack_SaveStateDirectorySymlinkWriteThrough(t *testing.T) {
	victimDir := t.TempDir()

	// Plant a symlink at the intended state directory, pointing at the
	// victim directory
	parentDir := t.TempDir()
	stateDir := filepath.Join(parentDir, "state")
	if err := os.Symlink(victimDir, stateDir); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	statePath := filepath.Join(stateDir, "state.json")
	err := SaveState(statePath, &EngineState{BlockStats: map[string]int64{"10.0.0.1": 5}})

	if err == nil {
		t.Error("SaveState succeeded through a symlinked directory — expected rejection")
	}

	// The victim directory must not contain the state file
	if _, statErr := os.Stat(filepath.Join(victimDir, "state.json")); statErr == nil {
		t.Error("state.json was written into the victim directory through the symlink")
	}
	if _, statErr := os.Stat(filepath.Join(victimDir, "state.json.tmp")); statErr == nil {
		t.Error("state.json.tmp was written into the victim directory through the symlink")
	}
}

// ── R45.5: SaveState still works on a genuine (non-symlink) directory ─
// Regression guard: the symlink rejection must not break the normal
// save path.
func TestAttack_SaveStateRealDirectoryStillWorks(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	if err := SaveState(statePath, &EngineState{BlockStats: map[string]int64{"192.168.1.1": 3}}); err != nil {
		t.Fatalf("SaveState on a real directory failed: %v", err)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Errorf("state.json not written: %v", err)
	}
}
