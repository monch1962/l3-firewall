package opa

// Result holds the OPA evaluation outcome.
type Result struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}
