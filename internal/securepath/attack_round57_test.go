// Red-team security hardening Round 57 — securepath, the shared
// directory-symlink guard (R45) and its '..' bypass:
//
//  1. RejectSymlinkComponents pre-Cleans the path with filepath.Clean,
//     which resolves ".." lexically BEFORE the walk. A path like
//     /base/evil/../state is therefore walked as /base/state while the
//     kernel resolves the raw path component-by-component: /base/evil
//     (symlink → /victim), then ".." (→ parent of /victim), then state.
//     MkdirAll and the subsequent file opens land in the
//     attacker-chosen directory while the walk — checking only the
//     cleaned path — passes.
//
//     persist.SaveState has its own strings.Contains("..") guard (R13),
//     but capture.NewWriter relies solely on this helper, so the bypass
//     is live for that consumer (audit's bypass is worse: filepath.Dir
//     strips ".." before the helper is even called — see the audit
//     attack_round57 test).
//
// R57 FIX: reject ".." path components outright, checked on the RAW
// input before Clean — after Clean they are already resolved and
// invisible to the walk. No legitimate firewall state/log/capture
// directory needs a ".." component.
package securepath

import (
	"os"
	"testing"
)

// ── R57.1: symlink before a '..' component escapes the walk ──────────
// RejectSymlinkComponents("/base/evil/../state") with /base/evil →
// /victim must FAIL: the kernel resolves evil, then ".." against the
// REAL directory structure (parent of /victim), then state — a
// different directory than the cleaned path the walk checks.
func TestAttack_DotDotBypass_SymlinkBeforeDotDot(t *testing.T) {
	victimDir := t.TempDir()
	parentDir := t.TempDir()
	if err := os.Symlink(victimDir, parentDir+"/evil"); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	// The cleaned path must exist as a real dir for the walk to pass
	// (callers run the check AFTER MkdirAll, so all components exist).
	if err := os.MkdirAll(parentDir+"/state", 0755); err != nil {
		t.Fatalf("MkdirAll state dir: %v", err)
	}

	// RAW concatenation — filepath.Join would Clean away the ".." and
	// defeat the test (filepath.Join resolves .. internally).
	dir := parentDir + "/evil/../state"

	// Simulate the caller's MkdirAll on the raw path: the kernel
	// resolves evil → victimDir, ".." → parent(victimDir), state →
	// created there, NOT at the cleaned parentDir/state the walk checks.
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll raw dir (kernel resolution): %v", err)
	}
	// The escape target: parent(victimDir)/state. os.Stat passes the raw
	// string to the kernel, which resolves ".." against the real tree.
	escapePath := victimDir + "/../state"
	if _, err := os.Stat(escapePath); err != nil {
		t.Fatalf("precondition broken: kernel did not create escape dir %s: %v", escapePath, err)
	}

	if err := RejectSymlinkComponents(dir); err == nil {
		t.Errorf("expected rejection of %q: '..' hides symlink component evil → %s; the walk checked %q (cleaned) but the kernel writes through to %s",
			dir, victimDir, parentDir+"/state", escapePath)
	}
}
