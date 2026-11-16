package main

import (
	"os"
	"strings"
	"testing"
)

// ── R90.2: the shipped admin posture is routable AND unauthenticated ─────
//
// The admin API's defaults are `--admin-listen :8082` (every interface) and
// `--admin-token ""` / `--admin-read-token ""` (no credentials). admin's
// require*Auth wrappers return the handler unwrapped when BOTH tokens are
// empty — the documented "no auth configured" mode — so a default deployment
// serves the full control plane to anyone who can reach the port:
//
//	GET  /admin/stats /admin/blocks /admin/block-stats   (blocked-host
//	     telemetry and internal traffic counters: network reconnaissance)
//	POST /admin/policy/reload                            (write)
//
// The R84 Host guard does not help: it exists to stop a browser rebinding to
// the listener, and it accepts any IP literal — a direct attacker simply
// sends the IP as Host. R87 made the plaintext-token combination warn, but
// this combination — routable, no credential at all — logged nothing. An
// operator who runs the README's `docker run -p 8082:8082` gets an open
// control plane and no signal that they have one (R40.4: a control that is
// not what the deployment says it is must at least be audible).
//
// Changing the default binding would break that documented deployment, so
// the fix is the audible half: `adminExposureWarning` returns a warning when
// the listener is reachable from off-host and no credential is configured.
func TestAttack_RoutableUnauthenticatedAdminIsSilent(t *testing.T) {
	cases := []struct {
		name      string
		listen    string
		token     string
		readToken string
		wantWarn  bool
	}{
		{"shipped default", ":8082", "", "", true},
		{"explicit all interfaces", "0.0.0.0:8082", "", "", true},
		{"explicit all interfaces v6", "[::]:8082", "", "", true},
		{"specific routable address", "10.1.2.3:8082", "", "", true},
		{"loopback v4 is fine", "127.0.0.1:8082", "", "", false},
		{"loopback v6 is fine", "[::1]:8082", "", "", false},
		{"localhost is fine", "localhost:8082", "", "", false},
		{"no listener", "", "", "", false},
		{"admin token configured", ":8082", "s3cret", "", false},
		{"read token configured", ":8082", "", "r3ad", false},
		{"both tokens configured", ":8082", "s3cret", "r3ad", false},
		{"loopback with no token", "127.0.0.1:8082", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := adminExposureWarning(tc.listen, tc.token, tc.readToken)
			if tc.wantWarn && got == "" {
				t.Errorf("listen=%q token=%q readToken=%q produced no warning — an unauthenticated control plane reachable from off-host starts silently", tc.listen, tc.token, tc.readToken)
			}
			if !tc.wantWarn && got != "" {
				t.Errorf("listen=%q token=%q readToken=%q warned spuriously (%q) — a warning that fires on safe configurations trains operators to ignore it", tc.listen, tc.token, tc.readToken, got)
			}
		})
	}
}

// ── R90.2b: the warning must name the exposure and the remedy ────────────
// The operator reading this line at 3am needs to know *what* is exposed and
// *which* flag fixes it. A bare "insecure admin configuration" would satisfy
// the letter of the rule and none of its purpose.
func TestAttack_AdminExposureWarningIsActionable(t *testing.T) {
	got := adminExposureWarning(":8082", "", "")
	if got == "" {
		t.Fatal("no warning for the shipped default posture")
	}
	for _, want := range []string{"8082", "no authentication", "--admin-token"} {
		if !strings.Contains(got, want) {
			t.Errorf("warning does not mention %q, so the operator cannot tell what is exposed or how to fix it: %q", want, got)
		}
	}
}

// ── R90.2c: the warning is actually wired into startup ───────────────────
// A helper that nothing calls is not a control. R86 found the metrics
// collectors registered but never incremented; the same audit applies to a
// warning that exists only in the test file.
func TestAttack_AdminExposureWarningIsWired(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	body := string(src)
	if !strings.Contains(body, "adminExposureWarning(") {
		t.Error("main.go never calls adminExposureWarning — the unauthenticated-routable-admin case stays silent (R90)")
	}
	if !strings.Contains(body, "--admin-listen") || !strings.Contains(body, `":8082"`) {
		t.Error("the admin listener default is no longer :8082 — re-derive the exposure predicate for the new default before trusting this round's warning")
	}
}
