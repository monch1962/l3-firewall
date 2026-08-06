// Package metrics provides Prometheus metrics for the L3 firewall.
package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

// Metrics struct holds all Prometheus metric collectors.
type Metrics struct {
	PacketsProcessed *prometheus.CounterVec
	PacketsAllowed   *prometheus.CounterVec
	PacketsBlocked   *prometheus.CounterVec
	PacketRate       *prometheus.GaugeVec
	ConntrackEntries prometheus.GaugeFunc
	RuleUpdates      prometheus.Counter
	AuditBlocks      *prometheus.CounterVec
}

var (
	m        *Metrics
	initOnce sync.Once // makes Init idempotent — see R44
)

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
		PacketRate: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "l3_firewall_packet_rate",
				Help: "Current packet rate by source IP (PPS).",
			}, []string{"src_ip"},
		),
		RuleUpdates: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "l3_firewall_rule_updates_total",
				Help: "Total number of rule updates via admin API.",
			},
		),
		AuditBlocks: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "l3_firewall_audit_blocks_total",
				Help: "Total number of audit-only blocks that were logged.",
			}, []string{"reason"},
		),
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
		m.PacketRate,
		m.RuleUpdates,
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
