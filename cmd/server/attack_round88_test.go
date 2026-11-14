// Red-team security hardening Round 88 — the last raw URL in the startup log.
//
// R87 swept the startup lines for credential-bearing URLs and routed the alert
// webhook and the threat-intel feeds through internal/redact. The etcd endpoint
// list was left verbatim:
//
//	slog.Info("etcd syncer started", "endpoints", *etcdEndpoints, "key", *etcdKey)
//
// etcd's own tooling accepts endpoints in URL form, and the documented way to
// point etcdctl or a Helm values file at a protected cluster is
// `https://user:password@etcd-0:2379`. Operators copy that form into
// --etcd-endpoints. The firewall then prints it at startup into the container
// log, and on every syncer failure the etcd client's error text repeats the
// endpoint URL.
//
// Severity is lower than R87.2 (the etcd client authenticates with fields, not
// the URL, so the embedded password is not necessarily usable by the etcd
// client itself) but the class is identical and the exposure is permanent:
// credentials, cluster-internal hostnames and topology in a log with wider
// readership than the process environment. The fix is one call to the helper
// that already exists — redact.URLs — so the two log lines cannot drift.
package main

import (
	"os"
	"strings"
	"testing"

	"github.com/monch1962/l3-firewall/internal/redact"
)

// ── R88.4: etcd endpoints are URL-shaped configuration and must be redacted ──
func TestAttack_EtcdEndpointURLCannotCarryCredential(t *testing.T) {
	src, err := os.ReadFile(mainSourcePath)
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	body := string(src)

	// The raw flag value must not reach the log directly.
	for _, raw := range []string{
		`"endpoints", *etcdEndpoints`,
		`"endpoints", endpoints`,
	} {
		if strings.Contains(body, raw) {
			t.Errorf("main.go logs etcd endpoints verbatim (%s): an endpoint URL may carry userinfo "+
				"and always discloses cluster topology — route it through redact.URLs (R88)", raw)
		}
	}

	if !strings.Contains(body, `"endpoints", redact.URLs(*etcdEndpoints)`) {
		t.Error("main.go does not redact the etcd endpoint list through redact.URLs — " +
			"the R87 class has a consumer that was missed (R88)")
	}
}

// The helper must actually remove the credential while keeping the topology
// count visible, so the fix above is not cosmetic.
func TestAttack_EtcdEndpointRedactionKeepsCountHidesSecret(t *testing.T) {
	// redact is exercised in its own package; this test pins the property that
	// makes the main.go change meaningful: userinfo never survives.
	const in = "https://user:SUPERSECRETPASSWORD@etcd-0.internal:2379,https://etcd-1.internal:2379"
	got := redact.URLs(in)
	if strings.Contains(got, "SUPERSECRETPASSWORD") {
		t.Errorf("redaction kept the endpoint credential: %q", got)
	}
	if n := strings.Count(got, "https://"); n != 2 {
		t.Errorf("redaction lost an endpoint (an operator must see how many endpoints are configured): %q", got)
	}
	if strings.Contains(got, "user") {
		t.Errorf("redaction kept the endpoint userinfo: %q", got)
	}
}
