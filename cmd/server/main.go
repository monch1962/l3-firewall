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
	"syscall"
	"time"

	"github.com/monch1962/l3-firewall/internal/admin"
	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/engine"
	"github.com/monch1962/l3-firewall/internal/metrics"
	"github.com/monch1962/l3-firewall/internal/opa"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
)

const version = "0.1.0"

func main() {
	var (
		listenAddr       = flag.String("admin-listen", ":8082", "Admin API listen address")
		adminToken       = flag.String("admin-token", "", "Bearer token for admin API auth")
		queueNum         = flag.Uint("queue", 0, "NFQUEUE number for forward traffic")
		queueNumInput    = flag.Uint("queue-input", 1, "NFQUEUE number for input traffic")
		opaEmbed         = flag.String("opa-embed", "./opa-policies/l3.rego", "Path to Rego policy file")
		opaParams        = flag.String("opa-params", "./config/params.json", "Path to parameters JSON")
		opaFailClosed    = flag.Bool("opa-fail-closed", false, "Block when OPA is unreachable")
		opaAuditOnly     = flag.Bool("opa-audit-only", false, "Log would-be blocks without enforcing")
		logFormat        = flag.String("log-format", "text", "Log format: text or json")
		metricsListen    = flag.String("metrics-listen", "", "Separate address for /metrics (empty = serve on admin port)")
		rateLimitPPS     = flag.Float64("rate-limit-pps", 0, "Per-IP packet rate limit (0 = unlimited)")
		rateLimitBPS     = flag.Float64("rate-limit-bps", 0, "Per-IP byte rate limit (0 = unlimited)")
		conntrackMax     = flag.Int("conntrack-max", 65536, "Max tracked connections")
		conntrackIdle    = flag.Duration("conntrack-idle", 5*time.Minute, "Connection idle timeout")
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

	// Load params
	opaStore := opa.NewDataStore()
	if *opaParams != "" {
		paramsData, err := os.ReadFile(*opaParams)
		if err != nil {
			log.Fatalf("failed to read params file %s: %v", *opaParams, err)
		}
		if err := opaStore.LoadParamsFromJSON(paramsData); err != nil {
			log.Fatalf("failed to parse params JSON: %v", err)
		}
		slog.Info("loaded params", "file", *opaParams)
	}

	// Create embedded OPA evaluator
	opaEval, err := opa.NewEmbedded(opa.EmbedConfig{
		Policy: string(policyData),
		Store:  opaStore,
	})
	if err != nil {
		log.Fatalf("failed to initialize OPA: %v", err)
	}
	slog.Info("OPA evaluator ready")

	// Create components
	ctConfig := conntrack.Config{
		MaxEntries:  *conntrackMax,
		IdleTimeout: *conntrackIdle,
	}
	ct := conntrack.NewTable(ctConfig)

	rl := ratelimit.NewLimiter(*rateLimitPPS, *rateLimitBPS)

	eng := engine.New(opaEval, ct, rl, *opaFailClosed, *opaAuditOnly)

	// Initialize metrics
	metrics.Init(func() int { return ct.Len() })
	slog.Info("metrics initialized")

	// Admin API
	adminAPI := admin.New(opaEval, opaStore, eng, version, *adminToken)
	var adminServer *http.Server
	if *listenAddr != "" {
		adminServer = adminAPI.StartServer(*listenAddr)
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
