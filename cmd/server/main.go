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
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const version = "0.1.0"

func main() {
	var (
		listenAddr     = flag.String("admin-listen", ":8082", "Admin API listen address")
		adminToken     = flag.String("admin-token", "", "Bearer token for admin API auth")
		queueNum       = flag.Int("queue", 0, "NFQUEUE number to read from")
		queueNumInput  = flag.Int("queue-input", 1, "NFQUEUE number for input chain")
		opaEmbed       = flag.String("opa-embed", "./opa-policies/l3.rego", "Path to Rego policy file")
		opaParams      = flag.String("opa-params", "./config/params.json", "Path to parameters JSON")
		opaFailClosed  = flag.Bool("opa-fail-closed", false, "Block when OPA is unreachable")
		opaAuditOnly   = flag.Bool("opa-audit-only", false, "Log would-be blocks without enforcing")
		logFormat      = flag.String("log-format", "text", "Log format: text or json")
		maxBodyBytes   = flag.Int64("max-body-mb", 10, "Max admin API body size in MB")
	)
	flag.Parse()

	// Suppress unused-variable errors; these will be wired as features land.
	_ = adminToken
	_ = queueNumInput
	_ = opaFailClosed
	_ = opaAuditOnly
	_ = maxBodyBytes

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
		"opa_embed", *opaEmbed,
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
	var paramsData []byte
	if *opaParams != "" {
		var err error
		paramsData, err = os.ReadFile(*opaParams)
		if err != nil {
			log.Fatalf("failed to read params file %s: %v", *opaParams, err)
		}
	}

	// TODO: Initialize components as features are built
	_ = policyData
	_ = paramsData

	// Admin API server
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","version":"%s"}`, version)
	})

	adminServer := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		slog.Info("shutting down gracefully...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		adminServer.Shutdown(shutdownCtx)
		cancel()
	}()

	// Start admin API
	go func() {
		slog.Info("admin API listening", "addr", *listenAddr)
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("admin API error", "error", err)
		}
	}()

	// TODO: Start NFQUEUE reader
	slog.Info("l3-firewall initialized — NFQUEUE reader not yet implemented")

	// Block until shutdown
	<-ctx.Done()
	slog.Info("shutdown complete")
}

// TODO: Add admin/auth middleware, rate limit middleware
