// Red-team security hardening Round 85 — companion finding to R85.1.
//
// readPolicyFile (R70/R71/R72/R73/R74 hardened) is the second consumer
// that hands `filepath.Dir(path)` to securepath.RejectSymlinkComponents
// and therefore never benefits from R57's raw-'..' rejection: filepath.Dir
// applies filepath.Clean, resolving '..' before the walk. The '..'
// survives only in the raw path that os.OpenFile receives, where the
// kernel resolves it against the real tree.
//
// Impact is the sharpest of the file readers: readPolicyFile's return
// value becomes the ENFORCED firewall policy (opa.NewEmbedded at
// startup, eval.Load on every 5-second hot-reload poll). With
// --opa-embed=/base/evil/../attacker.rego and /base/evil ->
// /escape/victim, the walk validates only /base and passes, while the
// open reads /escape/attacker.rego — attacker-chosen Rego loaded as the
// firewall's policy. A permissive Rego policy silently disables blocking
// (fail-open), which is precisely the outcome the R70 comment says the
// symlink guard exists to prevent.
package main

import (
	"os"
	"path/filepath"
	"testing"
)

// ── R85.2: '..' in --opa-embed hides a symlink and escapes the walk ──
func TestAttack_ReadPolicyFileRejectsDotDotHiddenSymlink(t *testing.T) {
	escapeRoot := t.TempDir()
	victimDir := filepath.Join(escapeRoot, "victim")
	if err := os.MkdirAll(victimDir, 0755); err != nil {
		t.Fatalf("mkdir victim: %v", err)
	}
	// The attacker's policy: deny-nothing (fail-open).
	attackerPolicy := "package l3\n\nimport rego.v1\n\ndefault allow := true\n\nallow if { true }\n"
	crafted := filepath.Join(escapeRoot, "attacker.rego")
	if err := os.WriteFile(crafted, []byte(attackerPolicy), 0644); err != nil {
		t.Fatalf("WriteFile crafted policy: %v", err)
	}

	base := t.TempDir()
	if err := os.Symlink(victimDir, filepath.Join(base, "evil")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	// RAW concatenation — filepath.Join would resolve the '..'.
	raw := base + "/evil/../attacker.rego"

	// Precondition: the kernel resolves the RAW string to the crafted
	// policy outside base; the cleaned path does not exist.
	if _, err := os.Stat(raw); err != nil {
		t.Fatalf("precondition broken: kernel does not resolve %q: %v", raw, err)
	}

	data, _, err := readPolicyFile(raw)
	if err == nil {
		t.Errorf("expected readPolicyFile to reject %q: '..' hides symlink evil -> %s, so the walk checked %s while the read landed on %s; returned %d bytes of attacker-chosen policy, which becomes the ENFORCED firewall policy (fail-open)",
			raw, victimDir, base, crafted, len(data))
	}
}
