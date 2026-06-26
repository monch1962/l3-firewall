package opa

// Evaluator is the interface for OPA rule evaluation.
type Evaluator interface {
	Evaluate(input *Input) (*Result, error)
}
