// Red-team security hardening Round 75 — the policy-package-shape gap at the
// Load/NewEmbedded boundary: the evaluator queries the hardcoded decision
// document data.l3_firewall (embed.go rebuild), but Load() and NewEmbedded()
// accept ANY compile-valid Rego module regardless of its declared package.
// A policy that compiles but declares any other package (a typo'd package
// line, a `package firewall`/`package evil` module, or a sub-package such as
// `l3_firewall.sub`) can NEVER produce a decision at data.l3_firewall:
// Evaluate returns the zero-result default (Allowed=true, err=nil — the R5
// deny-override empty-document semantics) and the firewall silently allows
// every packet.
//
// This is the fail-open SIBLING of the compile-error path: a policy that
// FAILS to compile is rejected loudly by Load (error return, old policy
// keeps governing, pollPolicyFile/syncer log the error — fail-safe), but a
// compile-VALID policy in the wrong package is accepted with a nil error and
// the log line "OPA policy reloaded" while the enforced policy silently
// becomes allow-all — bypassing an emergency block-everything policy that a
// same-plane push moments earlier had applied (the R65/R66/R73/R74
// stale-policy class, reached through the load gate instead of the mtime
// comparator). Attack reach:
//
//  1. etcd plane (R51/R52 model — plaintext etcd, malicious/compromised
//     server or MITM): push any compile-valid module whose package line is
//     wrong (or omit the package) → syncer watch → onUpdate → opaEval.Load
//     succeeds → the deny policy stops governing. The attacker needs no
//     allow rules and no Rego knowledge beyond a valid package clause;
//     compile-garbage would be REJECTED (fail-safe) but the no-decision
//     shape slips through the only gate the reload path has.
//  2. File plane (R42/R70-R74 model): a policy file edit that breaks the
//     package line (operator typo, or the same attacker influence the file
//     plane assumes) hot-reloads to allow-all with no error — the 5-second
//     watcher's eval.Load succeeds, lastMod advances, and the firewall is
//     disabled until the next DISTINCT fix.
//  3. Boot (NewEmbedded): a wrong-package file at --opa-embed boots the
//     firewall allow-all with no error at all.
//
// The R5 TestAttack_OPANoResult case (correct package `l3_firewall`, no
// rules) is the deny-override DESIGN (an empty policy in the right package
// has no deny rules → allows) and is preserved — see the regression tests
// below. The distinguishing, checkable property is the DECLARED PACKAGE:
// the compiled module set must contain the decision package. That check is
// unambiguous at load time (unlike the runtime empty-result case, which is
// indistinguishable from "no deny rules matched this packet").
package opa

import (
	"testing"

	"github.com/monch1962/l3-firewall/internal/packet"
)

// goodPolicy blocks SSH (dst 22) and allows everything else — the baseline
// deny-override policy that must keep governing when a bad policy is Loaded.
const r75GoodPolicy = `package l3_firewall
import rego.v1
default allow := true
allow := false if { input.packet.dst_port == 22 }
reason := "deny-ssh" if { input.packet.dst_port == 22 }
`

// wrongPkgPolicy is compile-valid but declares package evil: it would deny
// port 22 IF it governed (its rules are written correctly), yet the
// evaluator queries data.l3_firewall, so pre-R75 loading it silently made
// the firewall allow EVERYTHING — including port 22.
const r75WrongPkgPolicy = `package evil
import rego.v1
default allow := true
allow := false if { input.packet.dst_port == 22 }
reason := "deny-ssh-wrong-package" if { input.packet.dst_port == 22 }
`

func r75SSHInput() *Input {
	return &Input{
		Packet: PacketInfo{
			SrcIP: "10.0.1.100", DstIP: "10.0.2.50", Protocol: "TCP",
			SrcPort: 44001, DstPort: 22,
			TCPFlags: packet.TCPFlags{SYN: true},
		},
	}
}

func r75WebInput() *Input {
	return &Input{
		Packet: PacketInfo{
			SrcIP: "10.0.1.100", DstIP: "10.0.2.50", Protocol: "TCP",
			SrcPort: 44002, DstPort: 443,
			TCPFlags: packet.TCPFlags{SYN: true},
		},
	}
}

// ── R75.1: Load of a wrong-package policy must be REJECTED and the ──
// governing deny policy must survive. RED (pre-fix): Load returns nil, logs
// "OPA policy reloaded", and Evaluate now allows the SSH packet the GOOD
// policy blocked — the reload gate accepted a policy that can never produce
// a decision and silently switched the firewall to allow-all (the fail-open
// sibling of the loud compile-error path).
func TestAttack_LoadWrongPackageSilentFailOpen(t *testing.T) {
	eval, err := NewEmbedded(EmbedConfig{Policy: r75GoodPolicy})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	// Baseline: SSH is blocked by the good policy.
	res, err := eval.Evaluate(r75SSHInput())
	if err != nil {
		t.Fatalf("Evaluate baseline: %v", err)
	}
	if res.Allowed {
		t.Fatalf("baseline broken: good policy allowed SSH")
	}

	// A compile-valid policy in the WRONG package (its deny rule would fire
	// if it governed, but the evaluator reads data.l3_firewall).
	err = eval.Load(r75WrongPkgPolicy)
	if err == nil {
		t.Errorf("R75 RED: Load accepted a policy that declares package %q — it can never produce a decision at the hardcoded data.l3_firewall query, so the firewall silently switched to allow-all (Evaluate returns the zero-result default Allowed=true with no error; the only reload gate — compile success — is satisfied). The load must be REJECTED so the last-good deny policy keeps governing.", "evil")
	}

	// The GOOD policy must keep governing: SSH still blocked.
	res, err = eval.Evaluate(r75SSHInput())
	if err != nil {
		t.Fatalf("Evaluate after Load: %v", err)
	}
	if res.Allowed {
		t.Errorf("R75 RED: after the wrong-package Load, the SSH packet is ALLOWED — the deny policy stopped governing and the firewall permits everything (silent fail-open; pre-R75 Load returned nil error)")
	}
}

// ── R75.2: NewEmbedded (the --opa-embed boot path) must reject a ──
// wrong-package policy instead of booting an allow-all firewall. RED
// (pre-fix): NewEmbedded succeeds and Evaluate allows everything — a typo'd
// package line in the policy file disables the firewall at startup with NO
// error, no log, no way for the operator to notice until traffic flows.
func TestAttack_NewEmbeddedWrongPackageBootAllowAll(t *testing.T) {
	for _, tc := range []struct {
		name     string
		policy   string
		declares string
	}{
		{"unrelated package", "package evil\nimport rego.v1\ndefault allow := false\nreason := \"evil\"\n", "evil"},
		{"near-miss package", "package firewall\nimport rego.v1\ndefault allow := false\nreason := \"firewall\"\n", "firewall"},
		{"sub-package of the decision package", "package l3_firewall.sub\nimport rego.v1\ndefault allow := false\nreason := \"sub\"\n", "l3_firewall.sub"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eval, err := NewEmbedded(EmbedConfig{Policy: tc.policy})
			if err == nil {
				// Prove the fail-open: the "deny" policy declares no
				// decision at data.l3_firewall, so Evaluate allows.
				res, eerr := eval.Evaluate(r75SSHInput())
				t.Errorf("R75 RED: NewEmbedded accepted a policy declaring package %q — Evaluate returned Allowed=%v err=%v with NO error from NewEmbedded; the firewall boots allow-all (the boot path has no last-good policy to fall back to, so the package-shape gate is the ONLY defense)", tc.declares, res.Allowed, eerr)
			}
		})
	}
}

// ── R75.3: regression — the package gate must not over-reject: a ──
// correct-package deny-override policy WITHOUT a `default allow` (deny rules
// only) must still Load and enforce per-packet (matching → denied,
// non-matching → allowed by the R5 empty-document default). Guards the fix
// against requiring a particular RULE shape, which would break legitimate
// deny-override policies.
func TestAttack_LoadRightPackageNoDefaultPreservesDenyOverride(t *testing.T) {
	policy := `package l3_firewall
import rego.v1
allow := false if { input.packet.dst_port == 22 }
reason := "deny-ssh" if { input.packet.dst_port == 22 }
`
	eval, err := NewEmbedded(EmbedConfig{Policy: policy})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	if err := eval.Load(policy); err != nil {
		t.Fatalf("Load of a correct-package deny-override policy rejected: %v", err)
	}
	res, err := eval.Evaluate(r75SSHInput())
	if err != nil {
		t.Fatalf("Evaluate SSH: %v", err)
	}
	if res.Allowed {
		t.Errorf("deny-override regression: SSH (dst 22) allowed — the deny rule did not fire")
	}
	res, err = eval.Evaluate(r75WebInput())
	if err != nil {
		t.Fatalf("Evaluate web: %v", err)
	}
	if !res.Allowed {
		t.Errorf("deny-override regression: HTTPS (dst 443) blocked — non-matching packets must be allowed by the empty-document default")
	}
}

// ── R75.4: regression — the R5 deny-override contract on the LOAD path: ──
// a correct-package policy with NO rules still loads (nil error) and allows
// (empty decision document = no deny rules = allow). The package gate is
// about WHERE the rules are declared, not WHETHER rules exist.
func TestAttack_LoadRightPackageEmptyPolicyStillAllows(t *testing.T) {
	eval, err := NewEmbedded(EmbedConfig{Policy: r75GoodPolicy})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	if err := eval.Load("package l3_firewall\nimport rego.v1\n"); err != nil {
		t.Fatalf("Load of an empty correct-package policy rejected: %v (R5 deny-override allows an empty policy in the right package)", err)
	}
	res, err := eval.Evaluate(r75WebInput())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !res.Allowed {
		t.Errorf("empty correct-package policy must allow (R5): got Allowed=false")
	}
}
