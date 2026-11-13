// Red-team security hardening Round 86 — detection-plane integrity.
//
// The firewall's operator-visible monitoring surface is the Prometheus
// endpoint documented in the README (`--metrics-listen`, "/metrics →
// Prometheus format"). Until this round, EVERY collector in this package was
// registered and NONE was ever incremented: `grep -rn WithLabelValues` over
// the whole tree returned zero production call sites. The endpoint therefore
// answered 200 with a valid Prometheus document containing no
// `l3_firewall_*` sample at all — an observability control whose real
// behaviour differs from its documentation (the R83 class), in the direction
// that matters most for a firewall: an operator's alert on "blocking
// stopped" / "block rate spiked" can never fire, so a silently disabled deny
// plane (a policy defect, an R78 eval-error path, an R85 attacker-supplied
// policy) is indistinguishable from a quiet network.
//
// Wiring the counters is only half the job: the pre-R86 metric DEFINITIONS
// were themselves attacker-exploitable. `l3_firewall_packet_rate` carried a
// `{src_ip}` label (one series per source address — unbounded cardinality
// from spoofed sources, plus internal-address disclosure on an
// unauthenticated listener) and `{reason}` labels carry strings produced
// from attacker-influenced packet fields. These tests pin the fixed
// contract: real decisions are reported, label cardinality is bounded with
// an overflow series (so totals stay honest), and no per-source-IP series
// exists to leak or explode.
package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// ── R86.1: the endpoint must report what the engine actually decided ──────
// Before this round the four Observe* methods did not exist, so the only way
// to get a sample was to call WithLabelValues by hand — nothing did. A
// scraper therefore saw no packet at all.
//
// Reason labels are RULE-level, not value-level: digit runs fold to '#', so
// "blocked port 22 (TCP)" and "blocked port 23 (TCP)" are the same series
// (see maxReasonLabels). That is the granularity an operator needs for
// alerting, and it is what makes the label safe against per-packet values;
// the exact reason for each block stays on /admin/block-stats and in the log.
func TestAttack_MetricsExposeRealDecisions(t *testing.T) {
	m := Init(nil)

	m.ObservePacket("TCP")
	m.ObserveAllowed("TCP")
	m.ObservePacket("TCP")
	m.ObserveBlocked("blocked port 22 (TCP)")
	m.ObserveBlocked("blocked port 23 (TCP)")
	m.ObserveAuditBlock("blocked port 22 (TCP)")

	if got := counterValue(t, "l3_firewall_packets_processed_total", "protocol", "TCP"); got < 2 {
		t.Errorf("packets_processed{protocol=TCP} = %v, want >= 2 — the /metrics endpoint reports no decisions at all", got)
	}
	if got := counterValue(t, "l3_firewall_packets_allowed_total", "protocol", "TCP"); got < 1 {
		t.Errorf("packets_allowed{protocol=TCP} = %v, want >= 1", got)
	}
	if got := counterValue(t, "l3_firewall_packets_blocked_total", "reason", "blocked port # (TCP)"); got < 2 {
		t.Errorf("packets_blocked{reason=\"blocked port # (TCP)\"} = %v, want >= 2 (the two blocked ports must fold into ONE rule-level series)", got)
	}
	if got := counterValue(t, "l3_firewall_audit_blocks_total", "reason", "blocked port # (TCP)"); got < 1 {
		t.Errorf("audit_blocks{reason=\"blocked port # (TCP)\"} = %v, want >= 1 — audit-only mode is invisible to monitoring", got)
	}
}

// ── R86.2: reason labels cannot be exploded by attacker-shaped input ─────
// Block reasons embed values derived from the packet (ports, rates) and, on
// the OPA-error path, an evaluator error string. Unbounded distinct label
// values are a Prometheus cardinality DoS: every series is retained for the
// process lifetime and every scrape serialises all of them. Adversary: send
// traffic that produces a fresh reason string per packet.
func TestAttack_BlockReasonCardinalityBounded(t *testing.T) {
	m := Init(nil)

	const attempts = 5000
	for i := 0; i < attempts; i++ {
		// Distinct numeric payload per call — exactly the shape an attacker
		// produces via per-packet ports/rates — plus up to 400 distinct
		// alphabetic suffixes so the cap, not just the digit folding, is
		// exercised.
		m.ObserveBlocked("per-IP rate limit exceeded: " + itoa(i) + " pps / " + itoa(i*7) + " bps" + strings.Repeat("z", i%400))
	}

	series := seriesCount(t, "l3_firewall_packets_blocked_total")
	if series > maxReasonLabels+1 { // +1 for the overflow bucket
		t.Errorf("%d distinct {reason} series from %d blocked packets, cap is %d (+1 overflow) — unbounded label cardinality (memory + scrape amplification)", series, attempts, maxReasonLabels)
	}

	// The cap must not lose the count: folding into an overflow series keeps
	// the total honest, otherwise the operator's "blocked" total silently
	// under-reports exactly when the attack is loudest.
	total := familySum(t, "l3_firewall_packets_blocked_total")
	if total < attempts {
		t.Errorf("sum of blocked series = %v, want >= %d — folded labels must preserve the total", total, attempts)
	}
}

// ── R86.3: protocol labels are bounded too ───────────────────────────────
// The parser reports unknown IP protocols as "IP-<n>" (0-255) and ICMPv6 as
// its own name; a crafted flood cycling protocol numbers must not create one
// series per number.
func TestAttack_ProtocolLabelCardinalityBounded(t *testing.T) {
	m := Init(nil)

	for i := 0; i < 300; i++ {
		m.ObservePacket("IP-" + itoa(i))
	}

	series := seriesCount(t, "l3_firewall_packets_processed_total")
	if series > maxProtocolLabels+1 {
		t.Errorf("%d distinct {protocol} series, cap is %d (+1 overflow)", series, maxProtocolLabels)
	}
	if total := familySum(t, "l3_firewall_packets_processed_total"); total < 300 {
		t.Errorf("sum of processed series = %v, want >= 300", total)
	}
}

// ── R86.4: no metric may carry a per-source-IP label ─────────────────────
// l3_firewall_packet_rate{src_ip} was registered but never populated. It is
// withdrawn rather than wired: one series per source address is unbounded
// under spoofing, and the /metrics listener is unauthenticated — the label
// would disclose internal source addresses to anyone who can reach it
// (including a DNS-rebinding page, R84).
func TestAttack_NoPerSourceIPSeries(t *testing.T) {
	m := Init(nil)
	m.ObservePacket("TCP")
	m.ObserveAllowed("TCP")
	m.ObserveBlocked("blocked port 22 (TCP)")

	for _, fam := range gather(t) {
		if !strings.HasPrefix(fam.GetName(), "l3_firewall_") {
			continue
		}
		for _, mt := range fam.GetMetric() {
			for _, lp := range mt.GetLabel() {
				if n := lp.GetName(); n == "src_ip" || n == "dst_ip" {
					t.Errorf("metric %s exposes a per-address label %q — unbounded cardinality and internal-address disclosure on an unauthenticated endpoint", fam.GetName(), n)
				}
			}
		}
	}
}

// ── R86.5: label values must not smuggle control bytes ──────────────────
// Reason strings reach the exposition format; newline/control bytes would
// either corrupt the scrape or be escaped into one long line. The label
// sanitiser keeps the value printable and short.
func TestAttack_ReasonLabelSanitised(t *testing.T) {
	m := Init(nil)
	m.ObserveBlocked("OPA error: boom\ninjected: scraper-split\r\n# TYPE fake counter")

	saw := false
	for _, fam := range gather(t) {
		if fam.GetName() != "l3_firewall_packets_blocked_total" {
			continue
		}
		for _, mt := range fam.GetMetric() {
			for _, lp := range mt.GetLabel() {
				if lp.GetName() != "reason" {
					continue
				}
				saw = true
				v := lp.GetValue()
				if strings.ContainsAny(v, "\r\n") {
					t.Errorf("reason label contains a control byte: %q", v)
				}
				if len(v) > maxReasonLabelLen {
					t.Errorf("reason label is %d bytes, cap is %d: %q", len(v), maxReasonLabelLen, v)
				}
			}
		}
	}
	if !saw {
		t.Error("no {reason} label was published at all")
	}
}

// ── helpers ─────────────────────────────────────────────────────────────

func gather(t *testing.T) []*dto.MetricFamily {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	return fams
}

// counterValue returns the value of the series in family `name` whose label
// `labelName` equals `labelValue`.
func counterValue(t *testing.T, name, labelName, labelValue string) float64 {
	t.Helper()
	var sum float64
	for _, fam := range gather(t) {
		if fam.GetName() != name {
			continue
		}
		for _, mt := range fam.GetMetric() {
			if labelOf(mt, labelName) != labelValue {
				continue
			}
			if c := mt.GetCounter(); c != nil {
				sum += c.GetValue()
			}
			if g := mt.GetGauge(); g != nil {
				sum += g.GetValue()
			}
		}
	}
	return sum
}

// seriesCount returns how many series the named family publishes.
func seriesCount(t *testing.T, name string) int {
	t.Helper()
	n := 0
	for _, fam := range gather(t) {
		if fam.GetName() == name {
			n += len(fam.GetMetric())
		}
	}
	return n
}

// familySum returns the sum of every series value in the named family.
func familySum(t *testing.T, name string) float64 {
	t.Helper()
	var sum float64
	for _, fam := range gather(t) {
		if fam.GetName() != name {
			continue
		}
		for _, mt := range fam.GetMetric() {
			if c := mt.GetCounter(); c != nil {
				sum += c.GetValue()
			}
			if g := mt.GetGauge(); g != nil {
				sum += g.GetValue()
			}
		}
	}
	return sum
}

func labelOf(mt *dto.Metric, name string) string {
	for _, lp := range mt.GetLabel() {
		if lp.GetName() == name {
			return lp.GetValue()
		}
	}
	return ""
}

// itoa avoids importing strconv in a file whose job is label arithmetic.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
