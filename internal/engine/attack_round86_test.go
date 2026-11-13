// Red-team security hardening Round 86 — detection-plane integrity
// (engine side).
//
// The engine is where every firewall decision is made, and it is the only
// component that knows what the decision WAS. Before this round it published
// that knowledge only as log lines and as two integer counters behind
// /admin/stats — no metrics sink existed, so the Prometheus endpoint
// documented in the README could never show a block. The engine now reports
// each decision through a consumer-side interface (R10 doctrine: the
// interface lives in the consumer package, so `*metrics.Metrics` satisfies it
// implicitly and tests can record decisions).
//
// Also fixed here: the packetHandler panic recovery counted a packet it DROPS
// (ret = NF_DROP) as ALLOWED. The direction of that error is the dangerous
// one — the counters that an operator watches for "the firewall is blocking"
// move the wrong way, so a fail-closed drop-everything condition (the R49
// outage shape) reads as normal allowed traffic.
package engine

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/florianl/go-nfqueue"
	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/metrics"
	"github.com/monch1962/l3-firewall/internal/opa"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
)

// recordingSink records the decisions the engine reports. It is the test
// stand-in for *metrics.Metrics (which stays free of any engine dependency).
type recordingSink struct {
	mu        sync.Mutex
	processed map[string]int
	allowed   map[string]int
	blocked   map[string]int
	audit     map[string]int
}

func newRecordingSink() *recordingSink {
	return &recordingSink{
		processed: map[string]int{},
		allowed:   map[string]int{},
		blocked:   map[string]int{},
		audit:     map[string]int{},
	}
}

func (r *recordingSink) ObservePacket(protocol string) {
	r.mu.Lock()
	r.processed[protocol]++
	r.mu.Unlock()
}

func (r *recordingSink) ObserveAllowed(protocol string) {
	r.mu.Lock()
	r.allowed[protocol]++
	r.mu.Unlock()
}

func (r *recordingSink) ObserveBlocked(reason string) {
	r.mu.Lock()
	r.blocked[reason]++
	r.mu.Unlock()
}

func (r *recordingSink) ObserveAuditBlock(reason string) {
	r.mu.Lock()
	r.audit[reason]++
	r.mu.Unlock()
}

func (r *recordingSink) totals() (processed, allowed, blocked, audit int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range r.processed {
		processed += v
	}
	for _, v := range r.allowed {
		allowed += v
	}
	for _, v := range r.blocked {
		blocked += v
	}
	for _, v := range r.audit {
		audit += v
	}
	return
}

// newDenyAllEngine builds an engine whose policy denies everything, wired to
// the given sink.
func newDenyAllEngine(t *testing.T, sink MetricsSink) *Engine {
	t.Helper()
	eval, err := opa.NewEmbedded(opa.EmbedConfig{
		Policy: "package l3_firewall\nimport rego.v1\ndefault allow := false\nreason := \"denied by test policy\"\n",
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return New(eval, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(10000, 100000000),
		true, false, nil, nil, nil, nil, nil, "", nil).WithMetrics(sink)
}

func runPacket(t *testing.T, eng *Engine, srcIP, dstIP string, dstPort uint16) int {
	t.Helper()
	payload := buildTestTCPPacket(net.ParseIP(srcIP), net.ParseIP(dstIP), 54321, dstPort, true, false, false, false)
	id := uint32(1)
	return eng.packetHandler(nfqueue.Attribute{Payload: &payload, PacketID: &id})
}

// ── R86.6: every decision reaches the sink ───────────────────────────────
// One allowed packet (port 443) and one blocked packet (port 22, deny-all
// policy means port is irrelevant — use the allow-all policy for the allow
// case). The sink must see both, with the block's reason.
func TestAttack_EngineReportsDecisionsToMetrics(t *testing.T) {
	sink := newRecordingSink()

	allowEval, err := opa.NewEmbedded(opa.EmbedConfig{
		Policy: "package l3_firewall\nimport rego.v1\ndefault allow := true\n",
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	allowEng := New(allowEval, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(10000, 100000000), true, false, nil, nil, nil, nil, nil, "", nil).WithMetrics(sink)
	if got := runPacket(t, allowEng, "10.10.10.1", "10.0.0.1", 443); got != 0 {
		t.Fatalf("allowed packet verdict = %d, want 0", got)
	}

	denyEng := newDenyAllEngine(t, sink)
	if got := runPacket(t, denyEng, "10.10.10.2", "10.0.0.1", 22); got != 1 {
		t.Fatalf("blocked packet verdict = %d, want 1", got)
	}

	processed, allowed, blocked, _ := sink.totals()
	if processed != 2 {
		t.Errorf("processed = %d, want 2 — the engine's decisions never reach the metrics endpoint", processed)
	}
	if allowed != 1 {
		t.Errorf("allowed = %d, want 1", allowed)
	}
	if blocked != 1 {
		t.Errorf("blocked = %d, want 1", blocked)
	}
	sink.mu.Lock()
	_, hasReason := sink.blocked["denied by test policy"]
	sink.mu.Unlock()
	if !hasReason {
		t.Errorf("block reason not reported to metrics: got %v", sink.blocked)
	}
}

// ── R86.7: a fail-closed panic drop is NOT an allow ──────────────────────
// packetHandler's recover returns ret = 1 (NF_DROP, fail-closed — R10) but
// pre-R86 it incremented packetsAllowed. The packet is dropped; counting it
// as allowed inverts the one signal an operator uses to detect that the
// firewall has started dropping traffic, and double-counts packetsProcessed
// (once by evaluatePacket, once by the recover).
func TestAttack_PanicDropCountedAsBlockedNotAllowed(t *testing.T) {
	// Deny-all policy: the packet is blocked and reaches the pcap write,
	// which panics (simulated disk failure / attacker-influenced capture
	// path). The recover path must still report a block.
	eval, err := opa.NewEmbedded(opa.EmbedConfig{
		Policy: "package l3_firewall\nimport rego.v1\ndefault allow := false\nreason := \"denied by test policy\"\n",
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	sink := newRecordingSink()
	eng := New(eval, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(10000, 100000000),
		true, false, nil, nil, nil, nil, &panicPcapWriter{}, "", nil).WithMetrics(sink)

	if got := runPacket(t, eng, "10.20.20.20", "10.0.0.1", 22); got != 1 {
		t.Fatalf("verdict after panic = %d, want 1 (DROP)", got)
	}

	stats := eng.Stats()
	if stats.PacketsAllowed != 0 {
		t.Errorf("packetsAllowed = %d after a fail-closed DROP, want 0 — the drop is reported to operators as allowed traffic", stats.PacketsAllowed)
	}
	if stats.PacketsBlocked != 1 {
		t.Errorf("packetsBlocked = %d after a fail-closed DROP, want 1", stats.PacketsBlocked)
	}
	if stats.PacketsProcessed != 1 {
		t.Errorf("packetsProcessed = %d for one packet, want 1 (the recover double-counts)", stats.PacketsProcessed)
	}

	_, allowed, blocked, _ := sink.totals()
	if allowed != 0 || blocked != 1 {
		t.Errorf("metrics allowed=%d blocked=%d after a panic drop, want 0/1", allowed, blocked)
	}
}

// ── R86.11: the real /metrics document reports a real engine decision ────
// The end-to-end statement of the finding: scrape the endpoint the README
// documents, after the engine decided something, and find that decision. This
// also pins that *metrics.Metrics satisfies engine.MetricsSink (the wiring is
// interface-based, so a signature drift fails to compile — but only here is
// the DOCUMENT checked, not just the call).
func TestAttack_MetricsEndpointShowsEngineDecisions(t *testing.T) {
	m := metrics.Init(nil)
	eng := newDenyAllEngine(t, m)

	raw := buildTestTCPPacket(net.ParseIP("10.40.40.40"), net.ParseIP("10.0.0.1"), 54321, 22, true, false, false, false)
	id := uint32(1)
	if ret := eng.packetHandler(nfqueue.Attribute{Payload: &raw, PacketID: &id}); ret != 1 {
		t.Fatalf("verdict = %d, want 1", ret)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d", w.Code)
	}
	body := w.Body.String()

	want := []string{
		`l3_firewall_packets_processed_total{protocol="TCP"}`,
		`l3_firewall_packets_blocked_total{reason="denied by test policy"}`,
	}
	for _, series := range want {
		if !strings.Contains(body, series) {
			t.Errorf("/metrics document does not contain %s — the endpoint reports none of the firewall's decisions:\n%s", series, body)
		}
	}
	if strings.Contains(body, `l3_firewall_packets_allowed_total{protocol="TCP"} 1`) {
		t.Error("/metrics reports a blocked packet as allowed")
	}
}

// ── R86.8: audit-only "would block" is reported as such ──────────────────
// In --opa-audit-only mode a policy deny is allowed through but logged. No
// monitoring surface showed those would-be blocks, so an operator could not
// size the impact of turning enforcement on.
func TestAttack_AuditOnlyBlockReportedAsAuditBlock(t *testing.T) {
	eval, err := opa.NewEmbedded(opa.EmbedConfig{
		Policy: "package l3_firewall\nimport rego.v1\ndefault allow := false\nreason := \"denied by test policy\"\n",
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	sink := newRecordingSink()
	eng := New(eval, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(10000, 100000000),
		true, true /* auditOnly */, nil, nil, nil, nil, nil, "", nil).WithMetrics(sink)

	if got := runPacket(t, eng, "10.30.30.30", "10.0.0.1", 22); got != 0 {
		t.Fatalf("audit-only verdict = %d, want 0 (allowed through)", got)
	}

	_, allowed, blocked, audit := sink.totals()
	if audit != 1 {
		t.Errorf("audit-block metric = %d, want 1 — would-be blocks are invisible to monitoring", audit)
	}
	if allowed != 1 || blocked != 0 {
		t.Errorf("allowed=%d blocked=%d, want 1/0", allowed, blocked)
	}
}
