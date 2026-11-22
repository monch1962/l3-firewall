package main

import (
	"os"
	"strings"
	"testing"
)

// ── R95.3: the country plane is inert unless --geoip-db is set, and nothing
// said so.
//
// opa-policies/l3.rego ships `blocked_src_countries := {"KP"}` and three
// country rules keyed on `input.geo.src_country` / `input.geo.dst_country`.
// The engine only populates `input.geo` when a MaxMind database is configured
// (`--geoip-db`), and its DEFAULT is "" — so in every default deployment the
// shipped "GeoIP Blocking" control (README attack category 17) evaluates
// against an empty country for every packet and can never deny anything. That
// is the R83/R90 "control that is not what the deployment says it is" class:
// the policy file says KP traffic is blocked, the deployment blocks nothing,
// and both the startup log and /admin/health are silent about it.
//
// The fix makes it audible instead of pretending: main() already has the
// policy source it just read and the database path it parsed, so it can state
// the consequence at startup.
func TestAttack_GeoCountryRulesInertWithoutDatabase(t *testing.T) {
	policy, err := os.ReadFile("../../opa-policies/l3.rego")
	if err != nil {
		t.Fatalf("reading the shipped policy: %v", err)
	}

	w := geoipControlWarning(string(policy), "")
	if w == "" {
		t.Fatal("the shipped policy declares non-empty country sets (blocked_src_countries := {\"KP\"}) and jobs " +
			"run without --geoip-db by default, but nothing warns that the country rules cannot fire: an operator " +
			"believes KP-sourced traffic is blocked while every input.geo.src_country is empty")
	}
	if !strings.Contains(strings.ToLower(w), "cannot fire") {
		t.Errorf("warning does not state the consequence (the rules cannot fire): %q", w)
	}
	if !strings.Contains(w, "blocked_src_countries") {
		t.Errorf("warning does not name the inert setting: %q", w)
	}
	if !strings.Contains(w, "--geoip-db") {
		t.Errorf("warning is not actionable (does not name --geoip-db): %q", w)
	}

	// With a database configured the country plane works: no warning.
	if w := geoipControlWarning(string(policy), "/var/lib/geoip/GeoLite2-Country.mmdb"); w != "" {
		t.Errorf("warning fired although --geoip-db is configured: %q", w)
	}

	// An operator who deliberately emptied the sets has no inert control, so
	// there must be no noise (a warning that fires for a no-op config trains
	// the operator to ignore warnings).
	emptied := strings.NewReplacer(
		`blocked_src_countries := {"KP"}  # North Korea`, `blocked_src_countries := {}`,
	).Replace(string(policy))
	if w := geoipControlWarning(emptied, ""); w != "" {
		t.Errorf("warning fired for a policy whose country sets are empty: %q", w)
	}

	// A policy with no country rules at all is silent.
	if w := geoipControlWarning("package l3_firewall\nimport rego.v1\ndefault allow := true\n", ""); w != "" {
		t.Errorf("warning fired for a policy that has no country rules: %q", w)
	}
}

// ── R95.3b: the warning must be WIRED into main() (R40.4 — a correct helper
// nobody calls is the silently-dropped-control class again).
func TestAttack_GeoWarningIsWiredIntoStartup(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	s := string(src)
	if !strings.Contains(s, "geoipControlWarning(") {
		t.Fatal("main.go never calls geoipControlWarning: the country plane stays silently inert without --geoip-db")
	}
	if !strings.Contains(s, "geoipControlWarning(string(policyData), *geoipDBPath)") {
		t.Error("main.go does not evaluate the warning against the policy source it loaded and the configured " +
			"--geoip-db path, so it cannot know whether the policy actually declares country rules")
	}
}
