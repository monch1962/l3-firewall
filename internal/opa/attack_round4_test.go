// Red-team security hardening Round 4 — Config validation attack tests.
package opa

import (
	"testing"
)

// ── R36: Params with wrong type for array field ──────────────────
// Attacker sends blocked_ports as a string instead of array via admin API.
func TestAttack_ParamsWrongType(t *testing.T) {
	store := NewDataStore()

	// Wrong type: string instead of array
	store.SetParams(map[string]interface{}{
		"blocked_ports": "not-an-array",
	})

	params := store.GetParams()
	if params["blocked_ports"] != "not-an-array" {
		t.Errorf("blocked_ports = %v, want 'not-an-array'", params["blocked_ports"])
	}

	// OPA's object.get with default should handle this gracefully
	// The blocked_ports_set in Rego uses: object.get(data.params, "blocked_ports", {22, 23, ...})
	// If blocked_ports is a string, it would use the string as the set value
	// This is a type mismatch but not a crash vector — OPA handles it
}

// ── R37: Params with nil value ──────────────────────────────────
// JSON null values should not cause issues in the store.
func TestAttack_ParamsNilValue(t *testing.T) {
	store := NewDataStore()

	store.SetParams(map[string]interface{}{
		"syn_rate_per_second": nil,
	})

	params := store.GetParams()
	if params["syn_rate_per_second"] != nil {
		t.Errorf("syn_rate_per_second = %v, want nil", params["syn_rate_per_second"])
	}
}

// ── R38: Params with deeply nested structure ──────────────────────
// Deeply nested params object should not cause evaluation issues.
func TestAttack_ParamsDeeplyNested(t *testing.T) {
	store := NewDataStore()

	nested := map[string]interface{}{}
	current := nested
	for i := 0; i < 100; i++ {
		child := map[string]interface{}{}
		current["level"] = child
		current = child
	}

	store.SetParams(map[string]interface{}{
		"deep": nested,
	})

	// Should not panic or cause issues
	params := store.GetParams()
	if params["deep"] == nil {
		t.Error("deep param not stored")
	}
}

// ── R39: Params with very many keys ──────────────────────────────
// Large number of keys in params could affect OPA evaluation time.
func TestAttack_ParamsManyKeys(t *testing.T) {
	store := NewDataStore()

	params := make(map[string]interface{})
	for i := 0; i < 10000; i++ {
		params[testKey(i)] = float64(i)
	}
	store.SetParams(params)

	got := store.GetParams()
	if len(got) != 10000 {
		t.Errorf("params count = %d, want 10000", len(got))
	}
}

func testKey(i int) string {
	return "param_" + string(rune('a'+(i%26))) + itoa(i)
}

// Simple integer to string conversion without fmt import.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

// ── R40: Params loaded from invalid JSON path ─────────────────────
// Test that LoadParamsFromJSON handles edge cases gracefully.
func TestAttack_LoadParamsEdgeCases(t *testing.T) {
	store := NewDataStore()

	tests := []struct {
		name string
		data []byte
	}{
		{"empty object", []byte(`{}`)},
		{"null values", []byte(`{"rate": null}`)},
		{"boolean values", []byte(`{"enabled": true}`)},
		{"very large number", []byte(`{"rate": 999999999999999999999999999999}`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.LoadParamsFromJSON(tt.data)
			if err != nil {
				t.Fatalf("LoadParamsFromJSON failed: %v", err)
			}
		})
	}
}
