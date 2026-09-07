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
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

// decisionQuery is the single Rego query the evaluator runs for every
// packet. The policy MUST declare exactly this package: a compile-valid
// module in any other package can never produce a decision here, and
// Evaluate then returns the zero-result default (Allowed=true) — a silent
// allow-all firewall (R75).
const decisionQuery = "data.l3_firewall"

// EmbedConfig configures the in-process OPA evaluator.
type EmbedConfig struct {
	Policy  string        // Rego policy source code
	Timeout time.Duration // Evaluation timeout (0 = default 500ms)
}

// verifyPolicyPackage rejects a compiled module set that does not declare
// the decision package (R75). Both Load and NewEmbedded gate on it: without
// the gate, a compile-valid policy with a wrong package line (a typo, a
// `package firewall`/`package evil` module, or a sub-package such as
// `l3_firewall.sub` whose rules never surface at the queried document) is
// accepted with a nil error while the firewall silently allows every packet
// — the fail-open sibling of the compile-error path, which is rejected
// loudly and keeps the last-good policy. The exact-match requirement mirrors
// the query: rules under a descendant package (l3_firewall.sub) do not
// define `allow` at data.l3_firewall, so only the exact package can govern.
func verifyPolicyPackage(compiler *ast.Compiler) error {
	for _, mod := range compiler.Modules {
		if mod != nil && mod.Package != nil && mod.Package.Path.String() == decisionQuery {
			return nil
		}
	}
	return fmt.Errorf("policy must declare package at %s: compiled modules declare %s (a policy in any other package can never produce a decision for the %q query and would silently allow every packet)", decisionQuery, declaredPackages(compiler), decisionQuery)
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
		return nil, fmt.Errorf("compiling Rego: %w", err)
	}
	// The module must declare the decision package (R75): without the gate,
	// a wrong-package policy boots an allow-all firewall with no error (see
	// verifyPolicyPackage).
	if err := verifyPolicyPackage(compiler); err != nil {
		return nil, err
	}

	e := &EmbeddedEvaluator{
		compiler:    compiler,
		store:       inmem.New(),
		evalTimeout: cfg.Timeout,
		policy:      cfg.Policy,
		reloadCh:    make(chan struct{}, 1),
	}

	if err := e.rebuild(); err != nil {
		return nil, err
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
		return fmt.Errorf("compiling Rego: %w", err)
	}
	// Reject a policy that cannot produce a decision at the queried document
	// (R75): a wrong-package policy would otherwise Load successfully and
	// silently switch the firewall to allow-all — the fail-open sibling of
	// the compile-error path. Rejecting here keeps the last-good policy
	// governing (callers log the error; pollPolicyFile/syncer keep their
	// existing retry semantics).
	if err := verifyPolicyPackage(compiler); err != nil {
		return err
	}

	// Atomically swap the compiler and rebuild the prepared query
	e.mu.Lock()
	e.compiler = compiler
	e.policy = policy
	e.mu.Unlock()

	if err := e.rebuild(); err != nil {
		return err
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

	if len(results) == 0 {
		return &Result{Allowed: true}, nil
	}

	// Extract allow and reason from the result bindings
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
					n, err := a.Float64()
					if err == nil {
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
