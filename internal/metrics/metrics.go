// Package metrics provides Prometheus metrics for the L3 firewall.
package metrics

import (
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics struct holds all Prometheus metric collectors.
//
// R86 changed what lives here. Two collectors were REMOVED rather than wired:
//
//   - `l3_firewall_packet_rate{src_ip}` — a gauge labelled with the source
//     address. It was never populated, and it must not be: one series per
//     source address is unbounded under source spoofing (a cardinality DoS
//     that inflates memory and every scrape), and the /metrics listener is
//     unauthenticated, so the label would disclose internal source addresses
//     to anyone who can reach it — including a DNS-rebinding page (R84).
//   - `l3_firewall_rule_updates_total` — the admin API no longer has a rules
//     mutation route (only /admin/policy/reload), so nothing could ever
//     legitimately increment it.
//
// Every remaining collector is incremented from the engine's decision points,
// so the endpoint reports what the firewall actually did.
type Metrics struct {
	PacketsProcessed *prometheus.CounterVec // {protocol}
	PacketsAllowed   *prometheus.CounterVec // {protocol}
	PacketsBlocked   *prometheus.CounterVec // {reason}
	ConntrackEntries prometheus.GaugeFunc
	AuditBlocks      *prometheus.CounterVec // {reason}

	protocols *labelGuard
	reasons   *labelGuard
}

var (
	m        *Metrics
	initOnce sync.Once // makes Init idempotent — see R44
)

// Label-cardinality bounds (R86). Every distinct label value allocates a
// Prometheus series that lives for the process lifetime and is serialised on
// every scrape, so label values must not be attacker-controlled without a
// bound. Reasons additionally fold digit runs, because the reason strings
// that vary per packet are exactly the numeric ones ("per-IP rate limit
// exceeded: 918 pps / 41234 bps", "blocked port 22 (TCP)", "OPA error: ...").
// The cap is a backstop for anything that still varies.
//
// Exact (unfolded) reasons remain available on /admin/block-stats and in the
// per-packet log lines — metrics are for aggregation, logs for forensics.
const (
	maxProtocolLabels    = 64
	maxReasonLabels      = 256 // mirrors engine.maxBlockStatsReasons
	maxReasonLabelLen    = 96
	maxProtocolLabelLen  = 32
	overflowLabel        = "other"
	unknownProtocolLabel = "unknown"
)

// labelGuard admits a bounded set of label values and folds the rest into a
// single overflow series. Folding (rather than dropping the observation)
// keeps the reported TOTAL honest: an operator summing the series still sees
// every packet, which is the property that matters when the input is
// adversarial and loud.
type labelGuard struct {
	metric string
	max    int
	mu     sync.Mutex
	seen   map[string]struct{}
	warned bool
}

func newLabelGuard(metric string, max int) *labelGuard {
	return &labelGuard{metric: metric, max: max, seen: make(map[string]struct{}, max)}
}

// admit returns the value to record: v when it is already known or there is
// room, the overflow label otherwise. The warning is latched (R82): an
// unlatched warning driven by attacker input is itself a log-flood vector.
func (g *labelGuard) admit(v string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.seen[v]; ok {
		return v
	}
	if len(g.seen) >= g.max {
		if !g.warned {
			g.warned = true
			slog.Warn("metrics: label cardinality cap reached — further values are folded into an overflow series, so per-value detail for this label is now incomplete",
				"metric", g.metric, "cap", g.max)
		}
		return overflowLabel
	}
	g.seen[v] = struct{}{}
	return v
}

// sanitiseLabel makes a string safe to publish as a Prometheus label value:
// control bytes (which would break or bloat the exposition line) become
// spaces, the value is length-capped, and — for reasons — runs of digits
// collapse to a single '#'. Digit folding is what keeps per-packet reasons
// ("... 918 pps", "blocked port 22") from becoming a new series per packet.
func sanitiseLabel(v string, maxLen int, foldDigits bool) string {
	var b strings.Builder
	b.Grow(min(len(v), maxLen))
	prevDigit := false
	for _, r := range v {
		if b.Len() >= maxLen {
			break
		}
		switch {
		case r >= '0' && r <= '9':
			if foldDigits {
				if !prevDigit {
					b.WriteByte('#')
				}
				prevDigit = true
				continue
			}
			prevDigit = false
		case r < 0x20 || r == 0x7f:
			// Control byte (CR/LF/TAB/NUL/...) — never legal in a label and
			// would corrupt or pad the exposition document.
			b.WriteByte(' ')
			prevDigit = false
			continue
		default:
			prevDigit = false
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return overflowLabel
	}
	return out
}

// ObservePacket records one inspected packet under its protocol label.
func (m *Metrics) ObservePacket(protocol string) {
	if m == nil {
		return
	}
	m.PacketsProcessed.WithLabelValues(m.protocolLabel(protocol)).Inc()
}

// ObserveAllowed records one packet the firewall passed.
func (m *Metrics) ObserveAllowed(protocol string) {
	if m == nil {
		return
	}
	m.PacketsAllowed.WithLabelValues(m.protocolLabel(protocol)).Inc()
}

// ObserveBlocked records one packet the firewall dropped, by reason.
func (m *Metrics) ObserveBlocked(reason string) {
	if m == nil {
		return
	}
	m.PacketsBlocked.WithLabelValues(m.reasonLabel(reason)).Inc()
}

// ObserveAuditBlock records a would-be block that --opa-audit-only allowed
// through, so the impact of enabling enforcement can be sized from
// monitoring instead of from log grepping.
func (m *Metrics) ObserveAuditBlock(reason string) {
	if m == nil {
		return
	}
	m.AuditBlocks.WithLabelValues(m.reasonLabel(reason)).Inc()
}

func (m *Metrics) protocolLabel(protocol string) string {
	if protocol == "" {
		protocol = unknownProtocolLabel
	}
	return m.protocols.admit(sanitiseLabel(protocol, maxProtocolLabelLen, false))
}

func (m *Metrics) reasonLabel(reason string) string {
	if reason == "" {
		reason = unknownProtocolLabel
	}
	return m.reasons.admit(sanitiseLabel(reason, maxReasonLabelLen, true))
}

// Init registers all Prometheus metrics and returns the Metrics struct.
// Idempotent: only the first call constructs and registers the collectors.
// A second call would re-register the same collector names on the default
// registry and panic inside prometheus.MustRegister ("duplicate metrics
// collector registration attempted") — an unhandled panic that crashes the
// whole firewall process. Subsequent calls return the first instance (R44).
func Init(getConntrackLen func() int) *Metrics {
	initOnce.Do(func() {
		m = newMetrics(getConntrackLen)
	})
	return m
}

func newMetrics(getConntrackLen func() int) *Metrics {
	m = &Metrics{
		PacketsProcessed: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "l3_firewall_packets_processed_total",
				Help: "Total number of packets processed.",
			}, []string{"protocol"},
		),
		PacketsAllowed: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "l3_firewall_packets_allowed_total",
				Help: "Total number of packets allowed.",
			}, []string{"protocol"},
		),
		PacketsBlocked: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "l3_firewall_packets_blocked_total",
				Help: "Total number of packets blocked.",
			}, []string{"reason"},
		),
		AuditBlocks: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "l3_firewall_audit_blocks_total",
				Help: "Total number of audit-only blocks that were logged.",
			}, []string{"reason"},
		),
		protocols: newLabelGuard("l3_firewall_packets_processed_total{protocol}", maxProtocolLabels),
		reasons:   newLabelGuard("l3_firewall_packets_blocked_total{reason}", maxReasonLabels),
	}

	if getConntrackLen != nil {
		m.ConntrackEntries = prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Name: "l3_firewall_conntrack_entries",
				Help: "Current number of tracked connections.",
			}, func() float64 {
				return float64(getConntrackLen())
			},
		)
	}

	prometheus.MustRegister(
		m.PacketsProcessed,
		m.PacketsAllowed,
		m.PacketsBlocked,
		m.AuditBlocks,
	)
	if getConntrackLen != nil {
		prometheus.MustRegister(m.ConntrackEntries)
	}

	return m
}

// Get returns the global Metrics. Panics if Init hasn't been called.
func Get() *Metrics {
	if m == nil {
		panic("metrics: Init() must be called before Get()")
	}
	return m
}

// Handler returns the Prometheus HTTP handler for /metrics.
func Handler() http.Handler {
	return promhttp.Handler()
}
