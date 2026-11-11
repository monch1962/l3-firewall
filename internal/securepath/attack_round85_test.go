// Red-team security hardening Round 85 — guard test for the shared
// helper that closes the '..'-hides-a-symlink class at the ONLY sound
// ordering.
//
// The R57 fix rejected ".." inside RejectSymlinkComponents, but every
// file-reading consumer reached the helper through filepath.Dir(path),
// and filepath.Dir applies filepath.Clean — which consumes the ".."
// before the walk can see it. Two consumers (geoip --geoip-db,
// --opa-embed policy file) still had the live bypass in round 85.
//
// RejectUnsafePath is the idiom those readers must use. This test pins
// the contract so a future "simplification" back to
// RejectSymlinkComponents(filepath.Dir(path)) fails here as well as in
// the per-consumer round-85 tests.
package securepath

import (
	"os"
	"path/filepath"
	"testing"
)

// ── R85.3: RejectUnsafePath rejects '..' that filepath.Dir consumes ───
func TestAttack_RejectUnsafePathRejectsDotDotBeforeClean(t *testing.T) {
	escapeRoot := t.TempDir()
	victimDir := filepath.Join(escapeRoot, "victim")
	if err := os.MkdirAll(victimDir, 0755); err != nil {
		t.Fatalf("mkdir victim: %v", err)
	}
	// The file the kernel would reach: parent(victimDir)/db.mmdb.
	if err := os.WriteFile(filepath.Join(escapeRoot, "db.mmdb"), []byte("x"), 0644); err != nil {
		t.Fatalf("WriteFile escape target: %v", err)
	}

	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "evil"), 0755); err != nil {
		t.Fatalf("mkdir evil: %v", err)
	}
	if err := os.RemoveAll(filepath.Join(base, "evil")); err != nil {
		t.Fatalf("rmdir evil: %v", err)
	}
	if err := os.Symlink(victimDir, filepath.Join(base, "evil")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	// RAW concatenation — filepath.Join would resolve the '..'.
	raw := base + "/evil/../db.mmdb"

	// Pin the bug this helper exists for: the pre-R85 idiom PASSES,
	// because filepath.Dir(raw) is base (a real directory) and the ".."
	// is gone by the time the walk runs.
	if err := RejectSymlinkComponents(filepath.Dir(raw)); err != nil {
		t.Fatalf("precondition broken: the filepath.Dir idiom was expected to PASS (that is the bug), got %v", err)
	}

	// The sound idiom rejects it on the raw string, before any Clean.
	if err := RejectUnsafePath(raw); err == nil {
		t.Errorf("expected RejectUnsafePath to reject %q: '..' is consumed by filepath.Dir, so only the raw-path check can see it", raw)
	}
}

// ── R85.4: the helper must not reject legitimate paths ───────────────
func TestAttack_RejectUnsafePathAllowsLegitimatePaths(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "logs")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, p := range []string{
		filepath.Join(dir, "state.json"), // plain file, absent
		filepath.Join(sub, "audit.log"),  // nested, absent leaf
		dir + "/logs/..hidden",           // ".." as a PREFIX is a legal name
		dir + "/a..b/state.json",         // ".." inside a component is legal
	} {
		if err := RejectUnsafePath(p); err != nil {
			t.Errorf("RejectUnsafePath(%q) = %v, want nil (legitimate path)", p, err)
		}
	}
}
