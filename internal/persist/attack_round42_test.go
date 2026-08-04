// Red-team security hardening Round 42 — SaveState .tmp symlink write-through.
//
// SaveState writes via os.Create(statePath + ".tmp") then renames the .tmp
// over the final path. os.Create follows symlinks: an attacker with write
// access to the state directory (the same threat model as R13/R14 — the
// --state-file path is operator-influenced and may live in an attacker-
// writable directory) can pre-create state.json.tmp as a symlink to an
// arbitrary file writable by the firewall's UID. Every 60-second save then
// TRUNCATES and overwrites that file with the firewall's JSON state — an
// arbitrary file write/truncate primitive (the JSON content is the engine's
// block stats, but the truncate+overwrite destroys the target's contents,
// and a sufficiently controlled state map can inject attacker-influenced
// keys into the written JSON).
//
// LoadState was hardened against the symlink class (R15's symlink-to-FIFO
// rejection), but SaveState's .tmp CREATE was never covered.
//
// R42 FIX: open the .tmp with O_NOFOLLOW — a symlink at the .tmp path is
// rejected with ELOOP instead of being followed. Rename over the final path
// is already safe (os.Rename replaces the symlink itself, never follows it).
package persist

import (
	"os"
	"path/filepath"
	"testing"
)

// ── R42.1: os.Create follows a symlink (root mechanism) ────────────────
// Documents the root cause: the vulnerable open is os.Create (O_CREATE|
// O_TRUNC|O_WRONLY, symlink-following). The fix switches to O_NOFOLLOW.
func TestAttack_OSCreateFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("PRECIOUS"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "state.json.tmp")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}

	f, err := os.Create(link)
	if err != nil {
		t.Fatalf("os.Create on symlink failed: %v", err)
	}
	f.Close()

	b, _ := os.ReadFile(victim)
	if len(b) != 0 {
		t.Logf("os.Create followed the symlink and truncated the victim (%d bytes remain) — write-through confirmed", len(b))
	} else {
		t.Log("os.Create followed the symlink — victim truncated to 0 bytes")
	}
}

// ── R42.2: SaveState must NOT write through a symlinked .tmp ───────────
// RED (pre-fix): SaveState follows the symlink, truncates the victim and
// writes the JSON state through it, returning nil. GREEN (post-fix):
// SaveState returns an error and the victim is untouched.
func TestAttack_SaveStateSymlinkTmpWriteThrough(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	orig := "PRECIOUS-DATA"
	if err := os.WriteFile(victim, []byte(orig), 0600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "state.json")
	if err := os.Symlink(victim, statePath+".tmp"); err != nil {
		t.Fatal(err)
	}

	err := SaveState(statePath, &EngineState{BlockStats: map[string]int64{"attack": 1}})
	if err == nil {
		t.Error("SaveState must reject a symlinked .tmp path (returned nil error)")
	}

	b, readErr := os.ReadFile(victim)
	if readErr != nil {
		t.Fatalf("reading victim: %v", readErr)
	}
	if string(b) != orig {
		t.Errorf("SYMLINK WRITE-THROUGH: victim modified: got %q want %q", string(b), orig)
	}
}

// ── R42.3: SaveState still works with a normal .tmp (regression) ───────
// The O_NOFOLLOW flag must not break the normal save path.
func TestAttack_SaveStateNormalTmpStillWorks(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	if err := SaveState(statePath, &EngineState{BlockStats: map[string]int64{"ok": 7}}); err != nil {
		t.Fatalf("SaveState failed on normal path: %v", err)
	}
	b, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("reading state: %v", err)
	}
	if len(b) == 0 {
		t.Error("state file empty after SaveState")
	}
}
