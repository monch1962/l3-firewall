// Red-team security hardening Round 59 — persist.LoadState path-traversal
// asymmetry (R13 sibling-path gap).
//
// R13 added a ".." rejection to SaveState: "Rejects paths with '..' to
// prevent path traversal attacks when --state-file is attacker-influenced."
// The guard exists because an operator-influenced path can come from an
// untrusted source (e.g. a config file an attacker can partially edit), and
// the state file is read AND written by the firewall at the same path.
//
// LoadState — the sibling reader on the SAME state file — has no such
// check. It opens the path verbatim (O_RDONLY|O_NONBLOCK) and JSON-decodes
// it. With an attacker-influenced --state-file, LoadState will happily read
// ANY readable file the firewall UID can open, and if that file happens to
// parse as EngineState JSON, its BlockStats entries are injected into the
// engine's blockStats map (engine.restoreState) and served on the admin
// API's /admin/block-stats endpoint — which is UNAUTHENTICATED by default
// (R46). The attacker-controlled "reason" strings then appear in admin
// output and are persisted by the next SaveState tick (self-amplifying:
// the poisoned stats re-write themselves to the state file).
//
// This is the R52 sibling-path rule applied to the R13 guard: a fix that
// bounds one path of a component must be mirrored on every sibling path
// consuming the same input.
package persist

import (
	"os"
	"path/filepath"
	"testing"
)

// ── R59.1: LoadState must reject a path containing ".." ──────────────
// RED (pre-fix): LoadState opens the traversal path verbatim and
// successfully decodes the state file it resolves to — the ".." is
// silently accepted, and the file's BlockStats are loaded (later injected
// into engine.blockStats and served on the unauthenticated admin API).
// GREEN (post-fix): LoadState returns a path-traversal error, mirroring
// SaveState's R13 guard.
func TestAttack_LoadStateRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	// Create a REAL state file the traversal path resolves to, so the
	// pre-fix behavior is "reads it successfully" rather than ENOENT.
	if err := SaveState(statePath, &EngineState{
		BlockStats: map[string]int64{"attacker-reason": 42},
	}); err != nil {
		t.Fatalf("SaveState setup: %v", err)
	}

	// Raw string concatenation preserves ".." in the path — filepath.Join
	// calls filepath.Clean internally and would resolve the ".." before
	// LoadState ever sees it, making the test pass vacuously. The ".."
	// must be preceded by a REAL directory component for the kernel to
	// resolve it back to dir: escape/../state.json → dir/state.json.
	escape := filepath.Join(dir, "escape")
	if err := os.Mkdir(escape, 0755); err != nil {
		t.Fatalf("setup: mkdir escape: %v", err)
	}
	traversalPath := escape + "/../state.json"

	// The resolved path must actually exist (the kernel resolves ".."), so
	// the RED assertion is about the missing REJECTION, not a missing file.
	if _, err := os.Stat(traversalPath); err != nil {
		t.Fatalf("setup: traversal path should resolve to a real file: %v", err)
	}

	_, err := LoadState(traversalPath)
	if err == nil {
		t.Fatalf("LoadState accepted traversal path %q — R13 guard missing on sibling reader", traversalPath)
	}
}
