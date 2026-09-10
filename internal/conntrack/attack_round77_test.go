package conntrack

import (
	"fmt"
	"testing"
)

// ── R77: NewConnectionRate's 10000-entry slice cap aliases sustained new-conn
// floods at exactly 1000.0 conn/s ─────────────────────────────────────────────
// The shipped deny-override policy (opa-policies/l3.rego RULE 13,
// deny_new_conn_rate) denies when input.rate.new_conns_per_sec > 1000
// (max_new_connections_per_second := 1000). The producer is
// Table.NewConnectionRate: count of new-conn timestamps within the last 10
// seconds divided by 10. recordNewConn hard-caps the timestamp slice at 10000
// entries, so the maximum reportable value is exactly 10000/10 = 1000.0 — and
// the rule requires STRICTLY greater than 1000. Any sustained new-connection
// flood at >= 1000 conn/s (up to arbitrarily high rates) saturates the
// measurement at exactly 1000.0 and the rule can never fire in the production
// binary. This is the R76 class (a default-on shipped deny rule whose input
// producer can never exceed its threshold) applied to the sibling input field
// R76's audit never examined (R76 documented only PacketsInFlow/AgeMs;
// new_conns_per_sec's producer was left unexamined).
//
// Empirical proof at HEAD (probe): 15000 new 5-tuples within the window →
// NewConnectionRate() == 1000.0 (not > 1000); a 1100-conn burst reads 110.0
// (10s-window dilution). The Rego tests mock input.rate.new_conns_per_sec as
// 2000 directly (l3_test.rego), proving only the rule logic, never the
// production plumbing — the R76 default-enabled-policy × dead-input chain.
func TestAttack_NewConnRateSaturatesAtDenyThreshold(t *testing.T) {
	ct := NewTable(DefaultConfig())
	flooder := "10.9.9.9"

	// Attacker: one sustained new-connection flood — 15000 fresh 5-tuples
	// from a single source within the 10s measurement window (each a
	// distinct dst IP:port so every call creates a new flow).
	for i := 0; i < 15000; i++ {
		ct.LookupOrCreate(flooder, fmt.Sprintf("203.0.%d.%d", i/250, i%250), "TCP", uint16(i%60000+1), 443)
	}

	rate := ct.NewConnectionRate(flooder)
	// The rule fires only when the rate EXCEEDS 1000. A producer that can
	// never report above 1000.0 makes the default-on deny_new_conn_rate
	// rule dead code in the deployed binary.
	if rate <= 1000 {
		t.Errorf("NewConnectionRate(%s) = %.1f after a 15000-conn flood — the rate is capped at the policy threshold (1000) by the 10000-entry slice, so deny_new_conn_rate (> 1000, default-on) can never fire; sustained new-conn floods are silently allowed", flooder, rate)
	}
}

// ── R77: per-source attribution — a second source must not inherit the
// flooder's rate ──────────────────────────────────────────────────────────────
// opa.BuildInput documents Rate.NewConnsPerSec as "New connections/sec from
// this source" and the policy comment on max_new_connections_per_second says
// "Per-IP new connection rate limit" — but pre-R77 NewConnectionRate() summed
// a TABLE-GLOBAL timestamp slice: every packet, from every source, carried the
// aggregate new-conn rate of all sources. The rule is evaluated per packet, so
// a single flooder's rate was attributed to innocent sources' packets (deny
// fires on the wrong IP) while the flooder's own packet saw a diluted global
// average. Post-fix the rate must be keyed by the source IP.
func TestAttack_NewConnRateIsPerSource(t *testing.T) {
	ct := NewTable(DefaultConfig())
	flooder := "10.9.9.9"
	clean := "10.1.1.1"

	for i := 0; i < 15000; i++ {
		ct.LookupOrCreate(flooder, fmt.Sprintf("203.0.%d.%d", i/250, i%250), "TCP", uint16(i%60000+1), 443)
	}
	// Innocent source opens a single connection.
	ct.LookupOrCreate(clean, "10.2.2.2", "TCP", 50000, 443)

	floodRate := ct.NewConnectionRate(flooder)
	cleanRate := ct.NewConnectionRate(clean)
	if cleanRate >= 1000 {
		t.Errorf("clean source %s reports new-conn rate %.1f conn/s (inherited the flooder's table-global rate) — deny_new_conn_rate would fire on the WRONG source's packets; the rate must be attributed per source (clean source opened 1 conn)", clean, cleanRate)
	}
	if floodRate <= 1000 {
		t.Errorf("flooder %s reports %.1f conn/s after 15000 conns — saturates at the policy threshold, rule never fires", flooder, floodRate)
	}
}
