// Package opa provides embedded OPA/Rego evaluation for firewall policies.
// Supports in-process embedded evaluation with policy hot-reload and
// result parsing with type-safe allow/reason extraction.
//
// Configuration is embedded directly in the Rego policy file as constants.
// To change configuration: edit the .rego file and trigger a reload.
package opa

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"

	"github.com/monch1962/l3-firewall/internal/redact"
)

// decisionQuery is the single Rego query the evaluator runs for every
// packet. The policy MUST declare exactly this package: a compile-valid
// module in any other package can never produce a decision here, and
// Evaluate then returns the zero-result default (Allowed=true) — a silent
// allow-all firewall (R75).
const decisionQuery = "data.l3_firewall"

// decisionRuleRef is the fully-qualified reference to the rule that must
// exist for the decision query to be meaningful (R89). The package gate
// alone accepted a module that declares `package l3_firewall` and nothing
// else — see verifyPolicyPackage.
const decisionRuleRef = "data.l3_firewall.allow"

// maxPolicyErrorBytes bounds the error text this package RETURNS. OPA's
// compile errors echo the offending source line (measured R98: 2x the policy
// for a parse error, 3x for an unterminated string literal), and the policy
// channel accepts maxPolicySize (10 MB) of attacker-controlled Rego. Every
// caller logs err.Error() — the etcd syncer's watch goroutine after each
// distinct failed reload, main() at startup — so an unbounded error turns the
// firewall's own logging into the attack: one 10 MB policy becomes a 20-30 MB
// log line, once per reload, on the goroutine that must keep applying policy
// (the R96.3 "per-event logging IS the DoS" class, payload supplied by the
// attacker). Bounding it HERE protects every present and future caller with
// one implementation (R85/R89: centralise, do not patch each consumer).
//
// 4 KiB keeps the actionable part — file:line plus the OPA message — and
// drops the echoed source.
const maxPolicyErrorBytes = 4096

// maxPolicyErrorLineBytes bounds any SINGLE LINE of an error string. OPA's
// parse errors reproduce the offending source line verbatim (twice: once for
// the primary error, once for the follow-on "illegal token", each with a
// caret ruler). A total cap alone is not enough: the echoed source is the
// HEAD of the message, so truncating to maxPolicyErrorBytes still reproduces
// the first 4 KiB of a 10 MB policy line. Clamping every line keeps the head
// of each (`policy.rego:5: rego_parse_error: ...`) and the caret, while no
// single line can dominate a log record. Applies to every line, not only the
// tab-indented ones, so an attacker-controlled message line cannot slip a
// long run through either.
const maxPolicyErrorLineBytes = 160

// clampErrorLines bounds each line of text to maxLine bytes. Text whose every
// line already fits is returned unchanged, so ordinary diagnostics are
// byte-identical to before.
func clampErrorLines(text string, maxLine int) string {
	if len(text) <= maxLine {
		return text
	}
	lines := strings.Split(text, "\n")
	for i, ln := range lines {
		if len(ln) > maxLine {
			lines[i] = redact.Truncate(ln, maxLine)
		}
	}
	return strings.Join(lines, "\n")
}

// boundPolicyError caps err's text at maxPolicyErrorBytes and each of its
// lines at maxPolicyErrorLineBytes. Errors already within both caps are
// returned UNCHANGED (including their wrap chain), so ordinary diagnostics
// are byte-identical to before.
func boundPolicyError(err error, policyLen int) error {
	if err == nil {
		return nil
	}
	text := err.Error()
	clamped := clampErrorLines(text, maxPolicyErrorLineBytes)
	if clamped == text && len(text) <= maxPolicyErrorBytes {
		return err
	}
	if len(clamped) > maxPolicyErrorBytes {
		clamped = redact.Truncate(clamped, maxPolicyErrorBytes)
	}
	return fmt.Errorf("%s [policy source withheld: the error text was %d bytes for a %d-byte policy]",
		clamped, len(text), policyLen)
}

// EmbedConfig configures the in-process OPA evaluator.
type EmbedConfig struct {
	Policy  string        // Rego policy source code
	Timeout time.Duration // Evaluation timeout (0 = default 500ms)
}

// verifyPolicyPackage rejects a compiled module set that does not declare the
// decision package (R75). Both Load and NewEmbedded gate on it: without the
// gate, a compile-valid policy with a wrong package line (a typo, a
// `package firewall`/`package evil` module, or a sub-package such as
// `l3_firewall.sub` whose rules never surface at the queried document) is
// accepted with a nil error while the firewall silently allows every packet
// — the fail-open sibling of the compile-error path, which is rejected
// loudly and keeps the last-good policy. The exact-match requirement mirrors
// the query: rules under a descendant package (l3_firewall.sub) do not
// define `allow` at data.l3_firewall, so only the exact package can govern.
//
// The gate deliberately checks WHERE the rules are declared, not WHETHER an
// `allow` rule exists: this firewall is a DENY-OVERRIDE engine (R5), so a
// correct-package policy that defines only deny rules — or none at all —
// must still load and permit (R75.3/R75.4 pin that contract). A policy that
// cannot produce a decision is handled by warnIfNoDecision below: it permits,
// but it is no longer silent (R89).
func verifyPolicyPackage(compiler *ast.Compiler) error {
	for _, mod := range compiler.Modules {
		if mod != nil && mod.Package != nil && mod.Package.Path.String() == decisionQuery {
			return nil
		}
	}
	return fmt.Errorf("policy must declare package at %s: compiled modules declare %s (a policy in any other package can never produce a decision for the %q query and would silently allow every packet)", decisionQuery, declaredPackages(compiler), decisionQuery)
}

// warnIfNoDecision logs when a loaded policy can never produce an explicit
// `allow` decision, i.e. when the module set declares no COMPLETE rule named
// allow at the decision package.
//
// This is the R89 observability half of the R75 gate, and it is warn-only by
// design. The deny-override contract (R5/R75.3/R75.4) says such a policy
// loads and permits — a firewall whose decisions are "deny unless allowed"
// must not start rejecting policies that simply deny nothing. But "permits
// everything because nobody ever wrote an allow rule" is indistinguishable,
// in the logs, from a healthy reload: `package l3_firewall` alone, a rule
// renamed by a refactor typo (`default permit := false; permit if {...}`), an
// `allow` that is a FUNCTION (`allow(x) := ...` — functions never become
// document values), or an `allow` that is a partial set (`allow contains ...`,
// which Evaluate cannot read as a boolean) all leave the firewall allowing
// every packet while the process logs "OPA policy reloaded". R40.4's doctrine
// — a control that is not what the deployment says it is must at least be
// audible — is what this warning restores.
func warnIfNoDecision(compiler *ast.Compiler, origin string) {
	for _, rule := range compiler.GetRulesExact(ast.MustParseRef(decisionRuleRef)) {
		if rule == nil || rule.Head == nil {
			continue
		}
		// Complete rules (including `default allow := ...`) carry a value;
		// functions carry arguments, partial sets/objects carry a key. None
		// of the latter produce a boolean the evaluator can read.
		if len(rule.Head.Args) == 0 && rule.Head.Key == nil && rule.Head.Value != nil {
			return
		}
	}
	slog.Warn("OPA policy cannot produce an allow decision — every packet will be PERMITTED (deny-override: the policy defines no complete `allow` rule at "+decisionRuleRef+"); if this is unintended (renamed rule, function or set-valued allow), the firewall is allowing all traffic",
		"origin", origin)
}

// declaredPackages lists the package paths of a compiled module set for
// error messages.
func declaredPackages(compiler *ast.Compiler) []string {
	seen := map[string]bool{}
	var out []string
	for _, mod := range compiler.Modules {
		if mod == nil || mod.Package == nil {
			continue
		}
		p := mod.Package.Path.String()
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// EmbeddedEvaluator evaluates Rego policies in-process using the OPA Go library.
// Supports hot-reload via Load() and a reload-notification channel.
type EmbeddedEvaluator struct {
	// loadMu serializes Load calls (R67). Two independent policy sources
	// call Load concurrently in the deployed binary — the etcd syncer's
	// watch goroutine and the --opa-embed file hot-reload watcher (both
	// always wired when --etcd-endpoints is configured, since --opa-embed
	// is mandatory). Load swaps compiler/policy in one critical section,
	// then rebuild() RE-READS e.compiler and swaps e.prepared in a second
	// one; without serialization an OLDER policy whose slower rebuild
	// lands its prepared swap LAST silently supersedes a NEWER policy
	// whose Load completed first — the newer Load returns nil error but
	// never governs, the R66 stale-policy-regression class at the
	// evaluator boundary (reverting an operator's emergency policy). A
	// dedicated mutex (NOT mu): mu is shared with Evaluate, so holding it
	// across a multi-hundred-ms compile would stall the packet hot path —
	// the R61/R63 DoS the out-of-lock compile exists to prevent. With
	// loadMu, loads serialize by issue order (last-issued governs) while
	// Evaluate stays lock-free behind the short field-swap section.
	loadMu      sync.Mutex
	mu          sync.RWMutex
	prepared    *rego.PreparedEvalQuery
	compiler    *ast.Compiler
	store       storage.Store
	evalTimeout time.Duration
	policy      string        // Current policy source
	reloadCh    chan struct{} // Notified on each successful reload
}

// NewEmbedded creates an EmbeddedEvaluator from a Rego policy string.
func NewEmbedded(cfg EmbedConfig) (*EmbeddedEvaluator, error) {
	if cfg.Policy == "" {
		return nil, fmt.Errorf("Rego policy is required")
	}

	compiler, err := ast.CompileModules(map[string]string{
		"policy.rego": cfg.Policy,
	})
	if err != nil {
		return nil, boundPolicyError(fmt.Errorf("compiling Rego: %w", err), len(cfg.Policy))
	}
	// The module must declare the decision package (R75): without the gate,
	// a wrong-package policy boots an allow-all firewall with no error (see
	// verifyPolicyPackage).
	if err := verifyPolicyPackage(compiler); err != nil {
		return nil, boundPolicyError(err, len(cfg.Policy))
	}
	// A correct-package policy that can never produce a decision permits
	// everything by the deny-override contract — make that audible (R89).
	warnIfNoDecision(compiler, "startup")

	e := &EmbeddedEvaluator{
		compiler:    compiler,
		store:       inmem.New(),
		evalTimeout: cfg.Timeout,
		policy:      cfg.Policy,
		reloadCh:    make(chan struct{}, 1),
	}

	if err := e.rebuild(); err != nil {
		return nil, boundPolicyError(err, len(cfg.Policy))
	}

	return e, nil
}

// ReloadCh returns a channel that receives a signal on each successful reload.
// Consumers can use this to detect configuration changes.
func (e *EmbeddedEvaluator) ReloadCh() <-chan struct{} {
	return e.reloadCh
}

// Load recompiles the evaluator with a new policy source.
// This is the hot-reload entry point — call it when the policy file changes.
func (e *EmbeddedEvaluator) Load(policy string) error {
	if policy == "" {
		return fmt.Errorf("policy source is empty")
	}

	// Serialize concurrent loads by issue order (R67): the last-issued
	// Load must be the one that governs once it completes. Without this,
	// an overlapping older Load whose slower rebuild finishes last
	// supersedes the newer policy (see loadMu above). loadMu, not mu —
	// Evaluate must never block behind a compile.
	e.loadMu.Lock()
	defer e.loadMu.Unlock()

	compiler, err := ast.CompileModules(map[string]string{
		"policy.rego": policy,
	})
	if err != nil {
		return boundPolicyError(fmt.Errorf("compiling Rego: %w", err), len(policy))
	}
	// Reject a policy that cannot produce a decision at the queried document
	// (R75): a wrong-package policy would otherwise Load successfully and
	// silently switch the firewall to allow-all — the fail-open sibling of
	// the compile-error path. Rejecting here keeps the last-good policy
	// governing (callers log the error; pollPolicyFile/syncer keep their
	// existing retry semantics).
	if err := verifyPolicyPackage(compiler); err != nil {
		return boundPolicyError(err, len(policy))
	}
	// Same observability rule on the hot-reload path (etcd syncer / policy
	// file watcher): a reload that silently switches the firewall to
	// allow-all must say so (R89).
	warnIfNoDecision(compiler, "reload")

	// Atomically swap the compiler and rebuild the prepared query
	e.mu.Lock()
	e.compiler = compiler
	e.policy = policy
	e.mu.Unlock()

	if err := e.rebuild(); err != nil {
		return boundPolicyError(err, len(policy))
	}

	// Notify reload channel (non-blocking send)
	select {
	case e.reloadCh <- struct{}{}:
	default:
	}

	slog.Info("OPA policy reloaded")
	return nil
}

// rebuild creates a new prepared query from the compiled policy.
func (e *EmbeddedEvaluator) rebuild() error {
	ctx := context.Background()

	e.mu.RLock()
	compiler := e.compiler
	store := e.store
	e.mu.RUnlock()

	r := rego.New(
		rego.Query(decisionQuery),
		rego.Compiler(compiler),
		rego.Store(store),
	)
	prepared, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("preparing rego query: %w", err)
	}

	e.mu.Lock()
	e.prepared = &prepared
	e.mu.Unlock()
	return nil
}

// Evaluate executes the Rego policy against the given input and returns the result.
// The timeout is configurable via EmbedConfig.Timeout (default 500ms).
func (e *EmbeddedEvaluator) Evaluate(input *Input) (*Result, error) {
	timeout := e.evalTimeout
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	e.mu.RLock()
	prepared := e.prepared
	e.mu.RUnlock()

	if prepared == nil {
		return nil, fmt.Errorf("evaluator not initialized")
	}

	results, err := prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("OPA eval: %w", err)
	}

	// DENY-OVERRIDE (R5/R75): the result starts as allow and only an explicit
	// false-ish `allow` value denies. An empty document, a document without an
	// `allow` key (deny rules only, or `allow` undefined for this input) and a
	// non-boolean `allow` all mean "no deny rule fired" and therefore permit —
	// R75.3/R75.4 pin this contract. The silent-allow-all risk of a policy
	// that can NEVER produce a decision is surfaced where it belongs, once per
	// load, by warnIfNoDecision.
	if len(results) == 0 {
		return &Result{Allowed: true}, nil
	}

	result := &Result{Allowed: true}
	for _, r := range results {
		for _, expr := range r.Expressions {
			val, ok := expr.Value.(map[string]interface{})
			if !ok {
				continue
			}
			if allowed, ok := val["allow"]; ok {
				switch a := allowed.(type) {
				case bool:
					result.Allowed = a
				case string:
					result.Allowed = a == "true" || a == "1"
				case json.Number:
					if n, nErr := a.Float64(); nErr == nil {
						result.Allowed = n != 0
					}
				case nil:
					result.Allowed = false
				}
			}
			if reason, ok := val["reason"]; ok {
				if s, ok := reason.(string); ok {
					result.Reason = s
				}
			}
		}
	}

	return result, nil
}
