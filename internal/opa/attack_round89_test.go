package opa

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// captureWarnings installs a slog handler that records every WARN line for
// the duration of fn and returns the captured text.
func captureWarnings(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)
	fn()
	return buf.String()
}

// decisionProblem is the substring warnIfNoDecision emits. Asserting on it
// (rather than on any warning) keeps the test independent of unrelated log
// noise from other code paths in this package.
const decisionProblem = "cannot produce an allow decision"

// ── R89.1: a policy that can never deny is loaded SILENTLY ──────────────
//
// The deny-override contract (R5, pinned by R75.3/R75.4) says a
// correct-package policy that declares no `allow` rule must still load and
// permit: a firewall built on "deny unless allowed" cannot reject a policy
// for denying nothing. R89 does NOT change that contract — every case below
// must still load with a nil error and still allow.
//
// What R89 fixes is the SILENCE. Each of these policies can never deny a
// single packet, yet every one of them loads, serves traffic and logs the
// same "OPA policy reloaded" line as a healthy policy:
//
//	package l3_firewall                      -- empty module
//	default permit := false / permit if ...  -- rule renamed by a typo
//	allow(x) := false if ...                 -- FUNCTION named allow (never a
//	                                            document value)
//	allow contains "permit" if ...           -- partial SET: Evaluate cannot
//	                                            read it as a boolean, so it
//	                                            falls through to allow
//
// An operator who believes they shipped a deny policy learns nothing from
// the logs. R40.4's doctrine — a control that is not what the deployment
// says it is must at least be audible — is what the warning restores.
func TestAttack_DecisionlessPolicyLoadsAudibly(t *testing.T) {
	cases := []struct{ name, policy string }{
		{name: "empty module", policy: "package l3_firewall\n"},
		{
			name: "renamed rule",
			policy: "package l3_firewall\n\nimport rego.v1\n\n" +
				"default permit := false\n\npermit if {\n\tinput.packet.dst_port == 22\n}\n",
		},
		{
			name:   "allow defined as a function",
			policy: "package l3_firewall\n\nimport rego.v1\n\nallow(x) := false if x == 1\n",
		},
		{
			name:   "allow defined as a partial set",
			policy: "package l3_firewall\n\nimport rego.v1\n\nallow contains \"permit\" if {\n\tinput.packet.dst_port == 22\n}\n",
		},
	}
	in := &Input{Packet: PacketInfo{SrcIP: "203.0.113.9", DstIP: "10.0.0.1", Protocol: "TCP", DstPort: 22}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var eval *EmbeddedEvaluator
			var loadErr error
			logs := captureWarnings(t, func() {
				eval, loadErr = NewEmbedded(EmbedConfig{Policy: tc.policy})
			})
			if loadErr != nil {
				t.Fatalf("deny-override contract (R5/R75.3/R75.4) requires this policy to LOAD: %v", loadErr)
			}
			if !strings.Contains(logs, decisionProblem) {
				t.Errorf("policy that can never deny loaded with no warning — an allow-all firewall is indistinguishable from a healthy reload in the logs; got %q", logs)
			}
			// The documented behaviour itself is unchanged (deny-override).
			res, err := eval.Evaluate(in)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if !res.Allowed {
				t.Errorf("deny-override contract changed: expected allow, got Allowed=false")
			}
		})
	}
}

// ── R89.1b: the warning must not fire on a healthy policy ───────────────
// A deny-override policy with `default allow := ...` always produces a
// decision; a deny-rules-only policy with a conditional `allow := false`
// (the R75.3 shape) does too. Warning on either would train operators to
// ignore the line.
func TestAttack_DecisionWarningSilentForEnforcingPolicies(t *testing.T) {
	policies := map[string]string{
		"default true + deny rule": "package l3_firewall\n\nimport rego.v1\n\ndefault allow := true\n\nallow := false if {\n\tinput.packet.dst_port == 22\n}\n",
		"conditional complete rule": "package l3_firewall\n\nimport rego.v1\n\n" +
			"allow := false if {\n\tinput.packet.dst_port == 22\n}\n",
		"default false": "package l3_firewall\n\nimport rego.v1\n\ndefault allow := false\n",
	}
	for name, policy := range policies {
		t.Run(name, func(t *testing.T) {
			logs := captureWarnings(t, func() {
				if _, err := NewEmbedded(EmbedConfig{Policy: policy}); err != nil {
					t.Fatalf("NewEmbedded: %v", err)
				}
			})
			if strings.Contains(logs, decisionProblem) {
				t.Errorf("false positive: an enforcing policy was reported as decision-less (%q)", logs)
			}
		})
	}
}

// ── R89.1c: the RELOAD path must warn too ───────────────────────────────
// The etcd syncer and the --opa-embed file watcher both go through Load.
// A denial-of-enforcement reload (an emergency push that lost its `allow`
// rule, or a policy fragment) must be as audible as on the boot path —
// otherwise the only signal is the absence of blocks.
func TestAttack_DecisionlessReloadWarns(t *testing.T) {
	const good = "package l3_firewall\n\nimport rego.v1\n\ndefault allow := false\n"
	ev, err := NewEmbedded(EmbedConfig{Policy: good})
	if err != nil {
		t.Fatalf("NewEmbedded(good): %v", err)
	}
	logs := captureWarnings(t, func() {
		if err := ev.Load("package l3_firewall\n\nimport rego.v1\n\ndefault permit := true\n"); err != nil {
			t.Fatalf("deny-override contract requires the reload to be accepted: %v", err)
		}
	})
	if !strings.Contains(logs, decisionProblem) {
		t.Errorf("allow-all reload applied with no warning: %q", logs)
	}
}
