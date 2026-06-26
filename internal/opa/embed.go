// Package opa provides embedded OPA/Rego evaluation for firewall policies.
// Supports two modes: in-process embedded evaluation (EmbeddedEvaluator) and
// external sidecar. The package handles input document construction from
// parsed packet data, thread-safe parameter management via DataStore, and
// OPA result parsing with type-safe allow/reason extraction.
package opa

import (
	"context"
	"encoding/json"
	"fmt"
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
	Store   *DataStore    // Parameters data store
	Timeout time.Duration // Evaluation timeout (0 = default 500ms)
}

// EmbeddedEvaluator evaluates Rego policies in-process using the OPA Go library.
type EmbeddedEvaluator struct {
	mu          sync.RWMutex
	prepared    *rego.PreparedEvalQuery
	compiler    *ast.Compiler
	store       storage.Store
	opaStore    *DataStore
	evalTimeout time.Duration
}

// NewEmbedded creates an EmbeddedEvaluator from a Rego policy string.
func NewEmbedded(cfg EmbedConfig) (*EmbeddedEvaluator, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("DataStore is required")
	}
	if cfg.Policy == "" {
		return nil, fmt.Errorf("Rego policy is required")
	}

	// Compile the Rego module
	compiler, err := ast.CompileModules(map[string]string{
		"policy.rego": cfg.Policy,
	})
	if err != nil {
		return nil, fmt.Errorf("compiling Rego: %w", err)
	}

	e := &EmbeddedEvaluator{
		compiler:    compiler,
		store:       inmem.New(),
		opaStore:    cfg.Store,
		evalTimeout: cfg.Timeout,
	}

	if err := e.rebuild(); err != nil {
		return nil, err
	}

	return e, nil
}

// rebuild creates a new prepared query from the compiled policy.
func (e *EmbeddedEvaluator) rebuild() error {
	ctx := context.Background()

	// Build data with params injected
	data := map[string]interface{}{
		"params": e.opaStore.GetParams(),
	}
	e.store = inmem.NewFromObject(data)

	r := rego.New(
		rego.Query("data.l3_firewall"),
		rego.Compiler(e.compiler),
		rego.Store(e.store),
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

// SetParams updates the OPA data store parameters at runtime.
// This is used by the admin API for live rule updates.
func (e *EmbeddedEvaluator) SetParams(params map[string]interface{}) {
	e.opaStore.SetParams(params)
	// Rebuild prepared query with new params
	if err := e.rebuild(); err != nil {
		// Log and continue — old params remain active
		fmt.Printf("OPA: failed to rebuild with new params: %v\n", err)
	}
}
