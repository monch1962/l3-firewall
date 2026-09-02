// Red-team security hardening Round 70 — cmd/server readPolicyFile:
// reader-side symlink-following (the R62 class applied to the policy
// file reader).
//
// persist.LoadState — the sibling reader of --state-file — was hardened
// in R62 to reject symlinks at the final path component (O_NOFOLLOW) and
// at directory components (securepath walk). readPolicyFile — the reader
// of --opa-embed, whose content becomes the ENFORCED firewall policy via
// opa.NewEmbedded at startup and eval.Load on every 5-second hot-reload
// poll in watchPolicyFile — received only the R42 FIFO/O_NONBLOCK +
// fstat treatment and was never given the R62 reader-side symlink guard.
//
// Threat model (the standing R42/R45/R62 posture: attacker with write
// access to the policy file's directory — a partially-attacker-edited
// config dir, a mis-chmoded deploy dir, or a shared ops dir on a
// multi-tenant host): the attacker plants `l3.rego -> /attacker/evil.rego`
// (or a symlink to ANY file readable by the firewall's UID). R42's own
// test commentary established the model ("an attacker who can swap the
// policy file for a FIFO ... can also swap it for a symlink"), and
// watchPolicyFile's mtime check does not stop a symlink swap (replacing
// the directory entry updates the entry mtime). Because readPolicyFile's
// open follows the link:
//   - the firewall compiles + enforces attacker-chosen policy — a Rego
//     file with no deny rules means deny-override permits everything
//     (fail-open: blocking silently disabled), and
//   - a symlink to any regular file readable by the firewall's UID is
//     read + attempted as Rego every 5 seconds, with the compile error
//     logged at error level (read oracle on otherwise-unreadable files).
//
// The R68 fix-propagation grep accounted only for O_NOFOLLOW CREATE-opens
// (audit/capture/persist writers, 3/3) — the READER class on this path
// was missed.
package main

import (
	"os"
	"path/filepath"
	"testing"
)

// ── R70.1: readPolicyFile must REJECT a symlink planted at the policy ──
// path, even when the target is a perfectly valid regular Rego file.
// Pre-fix the open follows the link and the attacker's policy content is
// returned (and would be compiled + enforced); the RED failure proves
// the follow, not a vacuous error.
func TestAttack_ReadPolicyFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()

	// The attacker's crafted policy — valid Rego. The target must
	// genuinely exist and be readable so a rejection is the ONLY reason
	// the read fails (not ENOENT).
	crafted := filepath.Join(dir, "evil.rego")
	if err := os.WriteFile(crafted, []byte("package firewall\nallow := false\n"), 0644); err != nil {
		t.Fatalf("WriteFile crafted: %v", err)
	}

	// Symlink planted at the policy path, pointing at the crafted file.
	link := filepath.Join(dir, "l3.rego")
	if err := os.Symlink(crafted, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	data, err := readPolicyFile(link)
	if err == nil {
		t.Fatalf("readPolicyFile FOLLOWED the planted symlink and returned %d bytes of attacker policy (%q) — a symlink at the policy path must be rejected (R62 reader class)", len(data), string(data))
	}
	t.Logf("readPolicyFile correctly rejected the symlink: %v", err)
}

// ── R70.2: a symlink to a crafted fail-open policy must not become the ──
// enforced policy. This test drives the ACTUAL hot-reload decision: the
// watcher reloads when the entry mtime advances; the read must then fail
// (symlink rejected) instead of returning the attacker's allow-all Rego.
func TestAttack_ReadPolicyFileSymlinkDoesNotSupplyPolicy(t *testing.T) {
	dir := t.TempDir()

	// Attacker's crafted fail-open policy: deny-override with zero deny
	// rules — blocking silently disabled if enforced.
	crafted := filepath.Join(dir, "evil.rego")
	if err := os.WriteFile(crafted, []byte("package firewall\nallow := true\n"), 0644); err != nil {
		t.Fatalf("WriteFile crafted: %v", err)
	}

	link := filepath.Join(dir, "l3.rego")
	if err := os.Symlink(crafted, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	data, err := readPolicyFile(link)
	if err != nil {
		t.Logf("symlinked policy correctly rejected: %v", err)
		return
	}
	// RED path: the read succeeded through the link. If this content were
	// handed to opa.NewEmbedded / eval.Load the firewall would enforce it.
	t.Errorf("readPolicyFile returned content through the planted symlink (%d bytes) — attacker-supplied policy reaches the evaluator", len(data))
}

// ── R70.3: regular-file regression — O_NOFOLLOW must not break the ─────
// legitimate policy read (real regular file still loads unchanged), and
// after the planted symlink is removed the same path must read normally
// again (no poisoning of the path).
func TestAttack_ReadPolicyFileRegularFileStillReads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "l3.rego")
	content := "package firewall\nallow := true\n"

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	data, err := readPolicyFile(path)
	if err != nil {
		t.Fatalf("readPolicyFile failed on regular file: %v", err)
	}
	if string(data) != content {
		t.Errorf("readPolicyFile content mismatch: got %q want %q", string(data), content)
	}

	// Now plant a symlink over it, confirm rejection, remove it, and
	// confirm the path recovers to normal reads.
	crafted := filepath.Join(dir, "evil.rego")
	if err := os.WriteFile(crafted, []byte("package firewall\nallow := false\n"), 0644); err != nil {
		t.Fatalf("WriteFile crafted: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := os.Symlink(crafted, path); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if _, err := readPolicyFile(path); err == nil {
		t.Fatalf("readPolicyFile accepted the planted symlink phase")
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove link: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile restore: %v", err)
	}
	data, err = readPolicyFile(path)
	if err != nil {
		t.Fatalf("readPolicyFile failed after symlink removal (recovery broken): %v", err)
	}
	if string(data) != content {
		t.Errorf("readPolicyFile content mismatch after recovery: got %q want %q", string(data), content)
	}
}
