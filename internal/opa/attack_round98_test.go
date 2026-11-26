// Red-team security hardening Round 98 — the policy plane's LOG-VALUE surface.
//
// The etcd policy channel accepts up to maxPolicySize (10 MB) of
// attacker-controlled Rego (the R51/R52 threat model: a malicious or
// compromised etcd, or a MITM on a plaintext channel). Every reload is
// compiled by EmbeddedEvaluator.Load, and OPA's compile error ECHOES THE
// OFFENDING SOURCE LINE — twice for a parse error, three times for an
// unterminated string literal (measured below). Load returned that error
// verbatim and every caller logs err.Error():
//
//	syncer.loadCurrent  → "etcd: failed to get initial policy", "error", err
//	syncer.watch        → "etcd: failed to apply policy update", "error", err
//	cmd/server          → "failed to reload policy", ...
//
// One 10 MB policy carrying a syntax error therefore becomes a 20–30 MB
// single log line, issued on the etcd watch goroutine once per
// minReloadInterval (100 ms) — a sustained ~200–300 MB/s of log/disk writes
// driven by an attacker who controls the policy channel, at the exact moment
// the firewall is already failing to enforce their policy. This is the R96.3
// "per-event logging IS the DoS" class on the policy plane, with the payload
// supplied by the attacker.
//
// The fix belongs at the SOURCE: the component that owns the text bounds it
// (R85/R89 — centralise, don't patch each consumer), so every present and
// future caller is protected. The head of the error keeps the actionable part
// (file:line, the OPA message); only the echoed source is dropped.
package opa

import (
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
)

// policyEchoPad is the padding used to make the failing source line large
// enough that an echoed copy is unmistakable in the error text.
const policyEchoPad = 1 << 20

// unterminatedPolicy returns a valid package with an unterminated string
// literal whose content is pad bytes — OPA echoes that line in the error.
func unterminatedPolicy(pad int) string {
	return "package l3_firewall\n\nallow := true\n\nbad := \"" + strings.Repeat("X", pad) + "\n"
}

func assertErrorDoesNotEchoPolicy(t *testing.T, err error, policyLen int) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a compile error — the policy source is deliberately invalid")
	}
	text := err.Error()
	// The mechanism: the policy bytes must not be reproduced in the message.
	if strings.Contains(text, strings.Repeat("X", 256)) {
		t.Errorf("compile error reproduces the policy source: %d-byte message for a %d-byte policy (%d echoes the source)", len(text), policyLen, len(text)/policyLen)
	}
	// The contract: a log attribute derived from this error is bounded.
	const maxLogErr = 64 * 1024
	if len(text) > maxLogErr {
		t.Errorf("compile error text is %d bytes (max %d): a policy channel that delivers this line per reload is a log/disk DoS", len(text), maxLogErr)
	}
	// The actionable part must survive: where and what.
	if !strings.Contains(text, "policy.rego") || !strings.Contains(text, "rego_parse_error") {
		t.Errorf("bounded error lost the actionable part (want the file:line and the OPA message): %q", truncateForTest(text, 300))
	}
}

// ── R98.1: the hot-reload path must bound the error it returns ───────────
func TestAttack_LoadErrorMustNotEchoPolicySource(t *testing.T) {
	e, err := NewEmbedded(EmbedConfig{Policy: "package l3_firewall\n\nallow := true\n"})
	if err != nil {
		t.Fatalf("building the evaluator: %v", err)
	}
	policy := unterminatedPolicy(policyEchoPad)
	assertErrorDoesNotEchoPolicy(t, e.Load(policy), len(policy))

	// A pre-fix sanity check on the mechanism: the raw OPA error is an
	// amplifier (measured 3× for an unterminated string). If that ever stops
	// being true this test becomes vacuous, so pin the amplification here.
	if raw := rawCompileErrorSize(t, policy); raw <= len(policy) {
		t.Logf("NOTE: OPA no longer amplifies compile errors (%d bytes for a %d-byte policy) — the echo assertion above is what still matters", raw, len(policy))
	}
}

// ── R98.2: the startup path bounds it too ───────────────────────────────
// NewEmbedded's error reaches main() as a log.Fatalf argument: a 30 MB
// message on stderr at startup, before the firewall ever filters a packet.
func TestAttack_NewEmbeddedErrorMustNotEchoPolicySource(t *testing.T) {
	policy := unterminatedPolicy(policyEchoPad)
	_, err := NewEmbedded(EmbedConfig{Policy: policy})
	assertErrorDoesNotEchoPolicy(t, err, len(policy))
}

// rawCompileErrorSize compiles the policy directly to measure how much of the
// source the underlying library echoes, independent of this package's fix.
func rawCompileErrorSize(t *testing.T, policy string) int {
	t.Helper()
	if err := compileRaw(policy); err != nil {
		return len(err.Error())
	}
	return 0
}

// compileRaw runs the library compile with no bounding, to measure how much of
// the source OPA itself echoes.
func compileRaw(policy string) error {
	_, err := ast.CompileModules(map[string]string{"policy.rego": policy})
	return err
}

func truncateForTest(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
