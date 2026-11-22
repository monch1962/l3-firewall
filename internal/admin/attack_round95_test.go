// Red-team hardening Round 95 (admin control plane) — the two surfaces an
// operator believes about a firewall that is not firewalling.
//
// R95.1 `/admin/health` is documented as the liveness/readiness probe, but its
// body's `status` field is the CONSTANT string "ok": a process whose NFQUEUE
// receive loop has stopped (see internal/engine/attack_round95_test.go — a
// failed verdict, a PacketID-less frame, or a non-transient netlink error all
// stop it) answers `{"status":"ok","engine_running":true}` forever. The
// engineering fact the operator needs is "this process was asked to filter and
// is no longer doing it", which is `started && !running`.
//
// R95.2 `/admin/stats` reports `conntrack_entries` from `Stats.Created`, the
// CUMULATIVE number of flows ever created, while `/metrics`'s
// `l3_firewall_conntrack_entries` gauge reports the LIVE table size. Two
// surfaces of one fact disagree (the R86 doctrine), in the direction that
// blinds capacity alerting: the admin number only ever grows, so "table nearly
// full" fires permanently after sufficient churn and can never show recovery.
package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/engine"
	"github.com/monch1962/l3-firewall/internal/opa"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
)

// ── R95.1: the health body must not claim "ok" once a started engine has
// stopped filtering.
func TestAttack_HealthClaimsOKWhileFirewallStopped(t *testing.T) {
	// started + not running = the receive loop stopped (or Run failed): the
	// process is alive but nothing is inspecting packets.
	code, status := healthState(false, true)
	if code == http.StatusOK {
		t.Errorf("health HTTP status = %d for a started engine that is no longer running, want a non-200 failure status: "+
			"an orchestrator's liveness probe (curl -f) never restarts a firewall that is not filtering", code)
	}
	if status == "ok" {
		t.Errorf("health status = %q for a started engine that is no longer running: the probe reads \"ok\" "+
			"while netfilter drops every queued packet", status)
	}

	// Healthy: started and running.
	if code, status = healthState(true, true); code != http.StatusOK || status != "ok" {
		t.Errorf("health for a running engine = (%d, %q), want (200, \"ok\")", code, status)
	}

	// Before Run: the admin API is intentionally usable for diagnostics and
	// starts before eng.Run, so the pre-start window must stay 200/"ok" —
	// otherwise every existing probe would fail during a normal startup.
	if code, status = healthState(false, false); code != http.StatusOK || status != "ok" {
		t.Errorf("health before the engine is started = (%d, %q), want (200, \"ok\") (startup window)", code, status)
	}
}

// ── R95.1b: the handler must WIRE the started/running pair into the body (a
// correct helper nobody calls is the R40.4 silently-dropped-control class).
func TestAttack_HealthWiringExposesFirewallingState(t *testing.T) {
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatalf("reading api.go: %v", err)
	}
	s := string(src)
	if !strings.Contains(s, "Started()") {
		t.Error("handleHealth does not consult Engine.Started(): health cannot distinguish \"not started yet\" " +
			"from \"started and no longer filtering\", so a dead receive loop still reports ok")
	}
	if !strings.Contains(s, "firewalling") {
		t.Error("handleHealth does not expose a `firewalling` field: a probe keying on the JSON body has no " +
			"machine-readable signal that the firewall is not inspecting packets")
	}
	if !strings.Contains(s, "healthState(") {
		t.Error("handleHealth does not use healthState(): the status/code decision is inline again and the " +
			"degraded branch can rot unnoticed")
	}
}

// ── R95.1c: end-to-end shape — a never-started engine still answers 200 but
// the body states it is not firewalling.
func TestAttack_HealthBodyStatesItIsNotFirewalling(t *testing.T) {
	api := newTestAPI(t)
	req := httptest.NewRequest(http.MethodGet, "/admin/health", nil)
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	fw, ok := resp["firewalling"]
	if !ok {
		t.Fatalf("health response has no `firewalling` field: %v", resp)
	}
	if fw != false {
		t.Errorf("firewalling = %v for an engine that was never started, want false", fw)
	}
	if resp["engine_running"] != false {
		t.Errorf("engine_running = %v, want false", resp["engine_running"])
	}
}

// ── R95.2: `conntrack_entries` must be the live table size, not the cumulative
// number of flows ever created.
func TestAttack_StatsConntrackEntriesIsTheLiveTableSize(t *testing.T) {
	eval, err := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	// MaxEntries=1: creating a second flow evicts the first, so the table holds
	// one flow while two have been created in total.
	ct := conntrack.NewTable(conntrack.Config{MaxEntries: 1})
	rl := ratelimit.NewLimiter(1000, 1000000)
	eng := engine.New(eval, ct, rl, false, false, nil, nil, nil, nil, nil, "", nil)
	api := New(eval, eng, "test", "", "")

	if f := ct.LookupOrCreate("10.0.0.1", "10.0.0.2", "TCP", 1234, 80); f == nil {
		t.Fatal("setup: first flow not created")
	}
	if f := ct.LookupOrCreate("10.0.0.3", "10.0.0.2", "TCP", 1235, 80); f == nil {
		t.Fatal("setup: second flow not created")
	}
	live := ct.Len()
	if live != 1 {
		t.Fatalf("setup: live table size = %d, want 1 (eviction should have held it at MaxEntries)", live)
	}
	if created := ct.Stats().Created; created != 2 {
		t.Fatalf("setup: Created = %d, want 2", created)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	var resp struct {
		ConntrackEntries json.Number `json:"conntrack_entries"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, err := resp.ConntrackEntries.Int64()
	if err != nil {
		t.Fatalf("conntrack_entries is not an integer: %v", err)
	}
	if got != int64(live) {
		t.Errorf("conntrack_entries = %d, want the LIVE table size %d (cumulative Created = 2): "+
			"the admin view only ever grows, so a capacity alert keyed on it fires forever and can never "+
			"show recovery, while /metrics reports the live count — two surfaces of one fact disagree (R86)", got, live)
	}
}
