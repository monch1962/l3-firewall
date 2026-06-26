// l3-firewall — Layer 3 firewall sidecar.
//
// Architecture:
//   Traffic → [nftables NFQUEUE] → [l3-firewall]
//     gopacket parses packet headers → OPA/Rego evaluates →
//     NF_ACCEPT or NF_DROP verdict
//
// Deny-override model: traffic passes by default, blocked only by
// matching OPA deny rules.
package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/monch1962/l3-firewall/internal/admin"
	"github.com/monch1962/l3-firewall/internal/alert"
	"github.com/monch1962/l3-firewall/internal/audit"
	"github.com/monch1962/l3-firewall/internal/capture"
	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/engine"
	"github.com/monch1962/l3-firewall/internal/geoip"
	"github.com/monch1962/l3-firewall/internal/metrics"
	"github.com/monch1962/l3-firewall/internal/opa"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
	"github.com/monch1962/l3-firewall/internal/threatintel"
)

const version = "0.1.0"

func main() {
	var (
		listenAddr       = flag.String("admin-listen", ":8082", "Admin API listen address")
		adminToken       = flag.String("admin-token", "", "Bearer token for admin API auth (full access)")
		adminReadToken   = flag.String("admin-read-token", "", "Bearer token for read-only admin API access")
		queueNum         = flag.Uint("queue", 0, "NFQUEUE number for forward traffic")
		queueNumInput    = flag.Uint("queue-input", 1, "NFQUEUE number for input traffic")
		opaEmbed         = flag.String("opa-embed", "./opa-policies/l3.rego", "Path to Rego policy file")
		opaFailClosed    = flag.Bool("opa-fail-closed", false, "Block when OPA is unreachable")
		opaAuditOnly     = flag.Bool("opa-audit-only", false, "Log would-be blocks without enforcing")
		logFormat        = flag.String("log-format", "text", "Log format: text or json")
		metricsListen    = flag.String("metrics-listen", "", "Separate address for /metrics (empty = serve on admin port)")
		rateLimitPPS     = flag.Float64("rate-limit-pps", 0, "Per-IP packet rate limit (0 = unlimited)")
		rateLimitBPS     = flag.Float64("rate-limit-bps", 0, "Per-IP byte rate limit (0 = unlimited)")
		conntrackMax     = flag.Int("conntrack-max", 65536, "Max tracked connections")
		conntrackIdle    = flag.Duration("conntrack-idle", 5*time.Minute, "TCP connection idle timeout")
		conntrackUDP     = flag.Duration("conntrack-udp-timeout", 30*time.Second, "UDP connection idle timeout")
		conntrackICMP    = flag.Duration("conntrack-icmp-timeout", 5*time.Second, "ICMP connection idle timeout")
		conntrackMaxFlowsPerSrc = flag.Int("conntrack-max-flows-per-src", 0, "Max concurrent flows per source IP (0 = unlimited)")
		auditLogPath   = flag.String("audit-log", "", "Path to structured audit log file (empty = no audit logging)")
		alertWebhookURL = flag.String("alert-webhook-url", "", "Webhook URL for firewall alerts (e.g. Slack, Discord)")
		geoipDBPath   = flag.String("geoip-db", "", "Path to MaxMind GeoLite2/GeoIP2 .mmdb database for country lookup")
		threatIntelURL = flag.String("threat-intel-url", "", "URL(s) to IP reputation blocklists (comma-separated)")
		pcapDir       = flag.String("pcap-dir", "", "Directory for blocked packet pcap captures")
	)
	flag.Parse()

	// Structured logging
	var logHandler slog.Handler
	switch *logFormat {
	case "json":
		logHandler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	default:
		logHandler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	slog.SetDefault(slog.New(logHandler))
	log.SetFlags(0)
	log.SetOutput(slog.NewLogLogger(logHandler, slog.LevelInfo).Writer())

	slog.Info("starting l3-firewall",
		"version", version,
		"queue", *queueNum,
		"queue_input", *queueNumInput,
		"opa_embed", *opaEmbed,
		"audit_only", *opaAuditOnly,
		"fail_closed", *opaFailClosed,
	)

	// Load OPA policy
	if *opaEmbed == "" {
		log.Fatal("--opa-embed is required")
	}
	policyData, err := os.ReadFile(*opaEmbed)
	if err != nil {
		log.Fatalf("failed to read policy file %s: %v", *opaEmbed, err)
	}

	// Create embedded OPA evaluator from policy file
	opaEval, err := opa.NewEmbedded(opa.EmbedConfig{
		Policy: string(policyData),
	})
	if err != nil {
		log.Fatalf("failed to initialize OPA: %v", err)
	}
	slog.Info("OPA evaluator ready")

	// Create components
	ctConfig := conntrack.Config{
		MaxEntries:       *conntrackMax,
		MaxFlowsPerSrcIP: *conntrackMaxFlowsPerSrc,
		IdleTimeout:      *conntrackIdle,
		UDPTimeout:       *conntrackUDP,
		ICMPTimeout:      *conntrackICMP,
	}
	ct := conntrack.NewTable(ctConfig)

	// Create audit logger if path is specified
	var auditLogger *audit.Logger
	if *auditLogPath != "" {
		al, err := audit.NewLogger(audit.Config{
			Path: *auditLogPath,
		})
		if err != nil {
			log.Fatalf("failed to create audit logger: %v", err)
		}
		auditLogger = al
		slog.Info("audit logging enabled", "path", *auditLogPath)
	}

	// Create alert router if webhook URL is specified
	var alertRouter *alert.Router
	if *alertWebhookURL != "" {
		alertRouter = alert.NewRouter(alert.Config{
			WebhookURL: *alertWebhookURL,
		})
		slog.Info("alerts enabled", "webhook", *alertWebhookURL)
	}

	// Create GeoIP reader if database path is specified
	var geoIPReader *geoip.Reader
	if *geoipDBPath != "" {
		r, err := geoip.NewReader(*geoipDBPath)
		if err != nil {
			log.Fatalf("failed to open GeoIP database: %v", err)
		}
		geoIPReader = r
		slog.Info("GeoIP enabled", "db", *geoipDBPath)
	}

	// Create threat intel blocklist if URLs are specified
	var threatIntelBlocklist *threatintel.Blocklist
	if *threatIntelURL != "" {
		urls := strings.Split(*threatIntelURL, ",")
		bl := threatintel.NewBlocklist()
		for _, url := range urls {
			url = strings.TrimSpace(url)
			count, err := bl.FetchFromURL(url)
			if err != nil {
				slog.Warn("threat intel fetch failed", "url", url, "error", err)
			} else {
				slog.Info("threat intel loaded", "url", url, "entries", count)
			}
		}
		bl.StartRefresher(urls, 30*time.Minute)
		threatIntelBlocklist = bl
		slog.Info("threat intel enabled", "urls", *threatIntelURL)
	}

	// Create pcap capture writer if directory is specified
	var pcapCapture *capture.Writer
	if *pcapDir != "" {
		var err error
		pcapCapture, err = capture.NewWriter(capture.Config{Dir: *pcapDir})
		if err != nil {
			log.Fatalf("failed to create pcap writer: %v", err)
		}
		slog.Info("pcap capture enabled", "dir", *pcapDir)
	}

	rl := ratelimit.NewLimiter(*rateLimitPPS, *rateLimitBPS)

	eng := engine.New(opaEval, ct, rl, *opaFailClosed, *opaAuditOnly, auditLogger, alertRouter, geoIPReader, threatIntelBlocklist, pcapCapture)

	// Initialize metrics
	metrics.Init(func() int { return ct.Len() })
	slog.Info("metrics initialized")

	// Admin API — configuration is in the policy file, no external params needed
	adminAPI := admin.New(opaEval, eng, version, *adminToken, *adminReadToken)
	var adminServer *http.Server
	if *listenAddr != "" {
		adminServer = adminAPI.StartServer(*listenAddr)
	}

	// Start file watcher for hot-reload of the OPA policy file
	if *opaEmbed != "" {
		go watchPolicyFile(*opaEmbed, opaEval)
	}

	// Metrics HTTP handler on separate port or admin port
	if *metricsListen != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", metrics.Handler())
		metricsServer := &http.Server{
			Addr:              *metricsListen,
			Handler:           metricsMux,
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       30 * time.Second,
		}
		go func() {
			slog.Info("metrics listening", "addr", *metricsListen)
			if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("metrics error", "error", err)
			}
		}()
	}

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		slog.Info("shutting down gracefully...")
		if adminServer != nil {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer shutdownCancel()
			adminServer.Shutdown(shutdownCtx)
		}
		eng.Stop()
		cancel()
	}()

	// Start the NFQUEUE firewall engine (blocks until shutdown)
	slog.Info("starting firewall engine", "queue", *queueNum)
	if err := eng.Run(uint16(*queueNum)); err != nil {
		slog.Error("firewall engine failed", "error", err)
		// Don't exit — admin API still useful for diagnostics
		<-ctx.Done()
	}

	slog.Info("shutdown complete")
}

// watchPolicyFile polls the OPA policy file for modifications every 5 seconds
// and triggers a hot-reload when the file changes.
func watchPolicyFile(path string, eval *opa.EmbeddedEvaluator) {
	var lastMod time.Time
	for {
		fi, err := os.Stat(path)
		if err != nil {
			slog.Error("hot-reload: failed to stat policy file", "path", path, "error", err)
			time.Sleep(30 * time.Second)
			continue
		}
		modTime := fi.ModTime()
		if !lastMod.IsZero() && modTime.After(lastMod) {
			data, err := os.ReadFile(path)
			if err != nil {
				slog.Error("hot-reload: failed to read policy file", "path", path, "error", err)
			} else if err := eval.Load(string(data)); err != nil {
				slog.Error("hot-reload: failed to reload policy", "path", path, "error", err)
			}
		}
		lastMod = modTime
		time.Sleep(5 * time.Second)
	}
}
