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

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
)

// EmbedConfig configures the in-process OPA evaluator.
type EmbedConfig struct {
	Policy  string        // Rego policy source code
	Timeout time.Duration // Evaluation timeout (0 = default 500ms)
}

// EmbeddedEvaluator evaluates Rego policies in-process using the OPA Go library.
// Supports hot-reload via Load() and a reload-notification channel.
type EmbeddedEvaluator struct {
	mu          sync.RWMutex
	prepared    *rego.PreparedEvalQuery
	compiler    *ast.Compiler
	store       storage.Store
	evalTimeout time.Duration
	policy      string // Current policy source
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

	compiler, err := ast.CompileModules(map[string]string{
		"policy.rego": policy,
	})
	if err != nil {
		return fmt.Errorf("compiling Rego: %w", err)
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
		rego.Query("data.l3_firewall"),
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
