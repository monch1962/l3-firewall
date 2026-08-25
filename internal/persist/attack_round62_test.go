package persist

import (
	"os"
	"path/filepath"
	"testing"
)

// ── R62: LoadState symlink-following (reader/writer guard asymmetry) ──
// SaveState — the WRITER of --state-file — rejects symlinks at every path
// component: O_NOFOLLOW on the .tmp create (R42) plus the securepath
// directory walk after MkdirAll (R45). LoadState — the sibling READER of
// the same path — followed symlinks at the final component AND at
// directory components; R11.11 even enshrined the follow behavior as a
// passing test. An attacker with write access to the state directory (the
// R42/R45/R55 threat model: operator-influenced --state-file in an
// attacker-writable dir) plants `state.json -> /crafted/state.json`; at
// startup engine.Run → restoreState → LoadState follows the link, and if
// the target parses as EngineState JSON its BlockStats are injected into
// engine state, served on the default-unauthenticated /admin/block-stats
// endpoint (R46) and re-persisted by the next 60-second saveState tick —
// self-amplifying attacker-controlled stats (R59's documented impact
// chain). The R59 fix rejected ".." components but never examined the
// symlink class for the reader; the R48/R53 "securepath walks 3/3"
// accounting covered only the writers. The fix mirrors the writer's
// posture: securepath walk on the directory + O_NOFOLLOW on the open.
func TestAttack_LoadStateSymlinkRejected(t *testing.T) {
	dir := t.TempDir()

	// The attacker's crafted state file — valid EngineState JSON. The
	// target must genuinely exist and parse so the RED failure proves
	// "symlink followed + content injected", not a vacuous ENOENT.
	crafted := filepath.Join(dir, "crafted.json")
	if err := os.WriteFile(crafted, []byte(`{"block_stats":{"evil_key":999}}`), 0644); err != nil {
		t.Fatalf("WriteFile crafted: %v", err)
	}

	// Symlink planted at the state path, pointing at the crafted file.
	link := filepath.Join(dir, "state.json")
	if err := os.Symlink(crafted, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	// The reader must REJECT the link — it must not follow it.
	state, err := LoadState(link)
	if err == nil {
		t.Fatalf("LoadState followed the symlink and returned state %+v — symlink must be rejected", state)
	}
	t.Logf("LoadState correctly rejected the symlink: %v", err)
}

// Directory-component variant: a symlink planted at the DIRECTORY path
// (state-dir -> /crafted-dir) is resolved by the kernel before the open —
// O_NOFOLLOW on the final component does not cover it. The R45 walk that
// SaveState runs must be mirrored on the reader.
func TestAttack_LoadStateSymlinkDirRejected(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.MkdirAll(realDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	crafted := filepath.Join(realDir, "state.json")
	if err := os.WriteFile(crafted, []byte(`{"block_stats":{"evil_key":999}}`), 0644); err != nil {
		t.Fatalf("WriteFile crafted: %v", err)
	}

	// Symlink at the directory component.
	linkDir := filepath.Join(root, "state-dir")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	state, err := LoadState(filepath.Join(linkDir, "state.json"))
	if err == nil {
		t.Fatalf("LoadState followed the directory symlink and returned state %+v — symlink must be rejected", state)
	}
	t.Logf("LoadState correctly rejected the directory symlink: %v", err)
}

// Positive regression: the fix must not break the legitimate first-run
// and regular-file paths (companion to R14.3/R14.4 — a missing state file
// on first run still returns (nil, nil), and a regular file still loads).
func TestAttack_LoadStateRegularAndMissingStillWork(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	// Missing file (first run) → (nil, nil), no error.
	state, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState on missing file: %v", err)
	}
	if state != nil {
		t.Fatalf("LoadState on missing file returned non-nil state %+v", state)
	}

	// Regular file round-trip via SaveState → LoadState still works.
	saved := &EngineState{BlockStats: map[string]int64{"test": 42}}
	if err := SaveState(path, saved); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	loaded, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState on regular file: %v", err)
	}
	if loaded == nil || loaded.BlockStats["test"] != 42 {
		t.Fatalf("LoadState on regular file returned %+v — expected test=42", loaded)
	}
}
