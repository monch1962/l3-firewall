# l3-firewall

A **Layer 3 firewall sidecar** that intercepts, inspects, and filters IP packets using OPA/Rego policy-as-code. Built entirely in Go with zero cgo dependencies.

```
        ┌───────────┐  NFQUEUE   ┌──────────────┐  rules  ┌─────────┐
 Client ─▶  nftables │  queue     │  l3-firewall  │◀───────▶│  OPA    │
        │  QUEUE    │───────────▶│  sidecar      │  eval   │ Embedded │
        │  rule     │  verdict   │  (userspace)  │         │(in-proc) │
        └───────────┘            └──────────────┘         └─────────┘
```

## Attack Coverage

l3-firewall's OPA Rego policies cover **18 attack categories** with **~104 Go tests** and **76 Rego tests** plus **28 demo tests** across 10 internal packages and 12 standalone demos.

See the [`opa-demos/`](opa-demos/) directory for runnable, self-contained policy demonstrations covering every capability.

### OPA Policy Coverage (17 categories)

| # | Attack Vector | Detection | Status |
|---|---|---|---|
| 1 | **IP Spoofing** — Source IP not in allowed subnets | `allowed_subnets` check (CIDR) | ✅ |
| 2 | **Port Scanning** — Rapid connections to multiple dest ports | `recent_ports` threshold | ✅ |
| 3 | **SYN Flood** — Rate of SYN-only packets exceeds threshold | `syn_rate_per_second` | ✅ |
| 4 | **Protocol Anomaly** — Invalid TCP flags (SYN+RST, FIN+RST, SYN+FIN) | Flag combination check | ✅ |
| 5 | **Ingress/Egress Filtering** — Dest IP not in allowed subnets | `allowed_subnets` check (CIDR) | ✅ |
| 6 | **Port Control** — Block specific TCP/UDP ports (supports ranges) | `blocked_ports` list + `port_in_ranges()` | ✅ |
| 7 | **ICMP Control** — Block ICMP types/codes, rate limit floods | `blocked_icmp_types/codes` + rate | ✅ |
| 8 | **Connection State Violation** — RST to non-existent flow | TCP FSM state tracking | ✅ |
| 9 | **Protocol Blocking** — Block traffic by IP protocol | `blocked_protocols` list | ✅ |
| 10 | **Traffic Rate Limit** — Per-source-IP packets/sec budget | `max_packets_per_second` | ✅ |
| 11 | **Fragment Attack** — Non-zero-offset IP fragments | `fragment.offset > 0` check | ✅ |
| 12 | **Source Port Filtering** — Block traffic from specific source ports | `port_in_ranges(src_port, blocked_ports)` | ✅ |
| 13 | **New Connection Rate** — Too many new flows from one source | `new_conns_per_sec` threshold | ✅ |
| 14 | **Per-Port Rate Limit** — Too much traffic to a specific dst port | `src_port_pps` threshold | ✅ |
| 15 | **Connection Limit** — Too many concurrent flows from one source IP | Per-source flow counter + `MaxFlowsPerSrcIP` | ✅ |
| 16 | **Time-Based Access** — Block/allow by hour and day of week | `time_based_rules` with `utc_hour`/`utc_day` | ✅ |
| 17 | **GeoIP Blocking** — Block/allow by source/destination country | MaxMind .mmdb + `blocked_src_countries` / `allowed_src_countries` | ✅ |

### Red-Team Verified Transport Protection (9 attack simulation tests)

| # | Attack Vector | Defense | Status |
|---|---|---|---|
| R1 | **Block stats map unbounded** — Unique deny reasons exhaust memory | Capped at 256 entries | ✅ |
| R2 | **Rate limiter map unbounded** — Unique IPs exhaust memory | Capped at 100k entries, oldest-evicted | ✅ |
| R3 | **Engine panic crash** — Uncaught panic kills process | `recover()` in packetHandler + evaluatePacket | ✅ |
| R4 | **Port rate limiter unbounded** — IP:port combos exhaust memory | Same MaxEntries cap as R2 | ✅ |
| R5 | **OPA timeout hardcoded** — Cannot adjust for workload | `EmbedConfig.Timeout` (0 = 500ms default) | ✅ |
| R6 | **Concurrent block stats race** — Race on map writes | Protected by `sync.RWMutex` | ✅ |
| R7 | **Block stats reason flood** — Many unique reasons | Cap prevents new entries after 256 | ✅ |
| R8 | **Rate limiter burst gap** — 60s cleanup window OOM | MaxEntries eviction handles bursts | ✅ |
| R9 | **Per-source flow count unbounded** — Many src IPs exhaust `srcFlowCount` map | Per-IP counter naturally bounded by `MaxEntries` (65536) | ✅ |

### Verified Test Coverage (91 Go tests, 76 Rego tests)

| Package | Tests | What's Covered |
|---------|-------|----------------|
| `internal/packet` | 11 | TCP (SYN/SYN-ACK-RST-FIN), UDP, ICMP echo, short/nil, size, IPv6, fragment detection (nonzero offset, first-fragment, non-fragment) |
| `internal/opa` | 13 | Result JSON, input building (TCP/UDP/ICMP/ports/fragment/rate), data store CRUD, embedded eval blocking/allowing, runtime params, bad policy, nil store |
| `internal/conntrack` | 25 | Per-protocol timeouts, TCP/UDP/ICMP expiry, stats (hits/created/expired/evicted), new connection rate, TCP FSM (SYN→ESTABLISHED→FIN→RST→CLOSED), concurrent access, per-source flow limit (blocks under limit, multiple sources, after delete, after expire, stats, TCP state, default unlimited) |
| `internal/geoip` | 6 | NewReader nil path, bad path, lookup nil reader, invalid IP, nil DB, real file (skip) |
| `internal/ratelimit` | 15 | Basic allowance, burst, per-IP independence, byte rate, stale cleanup, active key preservation, concurrent, rate queries, per-dst-port AllowPort, GetPortPPS, port independence, unknown port |
| `internal/audit` | 7 | NewLogger default path, block events, allow events, concurrent safety, rotation, close, invalid path |
| `internal/engine` | 11 | Allow, block, TCP state tracking, conntrack updates, audit-only, fail-closed, rate limiting, ICMP, recent blocks, block metadata, running status, stats, connection limit blocking, different src OK |
| `internal/admin` | 8 | Health, stats, blocks, block-stats, rules GET/UPDATE, invalid JSON, wrong method, auth |
| OPA Policies (Rego) | 76 | Default allow, CIDR matching (6), IP spoofing (3), port scan (2), SYN flood (2), protocol anomaly (4), ingress/egress (2), port control (7), ICMP control (3), state violation (2), protocol blocking (2), traffic rate (3), fragment attack (3), port ranges (6), source port filtering (2), new conn rate (2), per-port rate (2), combined (1), time-based rules (13), GeoIP rules (11) |

## Architecture

```
Packets → [nftables NFQUEUE] → engine.evaluatePacket()
                                  ├── packet.ParsePacket(raw bytes)
                                  ├── conntrack.LookupOrCreate(5-tuple)
                                  ├── ratelimit.Allow(srcIP, packetSize)
                                  ├── opa.BuildInput(packet + rate + conn state + time)
                                  ├── opaEval.Evaluate(input)
                                  ├── NF_ACCEPT or NF_DROP + stats
                                  └── audit.Log() → JSON file (block/allow events)

Admin API (:8082)
  ├── /admin/health     → {"status":"ok","version":"0.1.0","uptime":"...","engine_running":bool}
  ├── /admin/stats      → {"packets_processed":N,"packets_allowed":N,"packets_blocked":N,
  │                        "conntrack_entries":N,"conntrack_expired":N,"conntrack_evicted":N}
  ├── /admin/blocks     → [{timestamp,src_ip,dst_ip,protocol,src_port,dst_port,reason,...}]
  ├── /admin/block-stats → {"blocked SSH": 42, "SYN flood": 7, ...}
  ├── /admin/policy/reload → Trigger policy hot-reload (POST)

Metrics (:9090 or admin port)
  └── /metrics → Prometheus format
```

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Interception** | NFQUEUE via `florianl/go-nfqueue` | Pure Go, kernel-level filtering, container-compatible with `CAP_NET_ADMIN` |
| **Packet Parsing** | `google/gopacket` | Well-established, comprehensive protocol support |
| **Policy Engine** | OPA embedded (in-process) | ~10µs eval, testable policies with `opa test`, same pattern as gql-firewall |
| **Security Model** | Deny-override | Traffic passes by default, blocked only by matching deny rules |
| **Rate Limiting** | EWMA-based PPS/BPS | Smooth rate estimation, no sudden drops |
| **Connection Tracking** | 5-tuple flow table | Stateful inspection for TCP state violations |

## Quick Start

### Prerequisites
- Go 1.25+
- OPA 1.0+ (for policy testing: `opa test opa-policies/`)
- Linux with nftables (for NFQUEUE runtime)
- Container: `--cap-add=NET_ADMIN`

### Build & Test

```bash
# Build
make build

# Run all Go and Rego tests
make test

# Run Go tests only
make test-go

# Run Rego tests only
make test-opa

# Lint and vet
make lint
make vet
```

### Run (Development — No NFQUEUE)

```bash
# Start just the admin API for testing (engine will log NFQUEUE error)
./l3-firewall --admin-listen :8082
```

### Run (Container)

```bash
docker build -t l3-firewall:latest .
docker run --cap-add=NET_ADMIN --rm -p 8082:8082 l3-firewall:latest
```

The entrypoint (`deploy/entrypoint.sh`) configures nftables to QUEUE forward and input traffic, then starts the firewall binary.

## Configuration

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--admin-listen` | `:8082` | Admin API listen address |
| `--admin-token` | `""` | Bearer token for admin API auth |
| `--queue` | `0` | NFQUEUE number for forward traffic |
| `--queue-input` | `1` | NFQUEUE number for input traffic |
| `--opa-embed` | `./opa-policies/l3.rego` | Path to Rego policy file (configuration is embedded here) |
| `--opa-fail-closed` | `false` | Block when OPA is unreachable |
| `--opa-audit-only` | `false` | Log would-be blocks without enforcing |
| `--log-format` | `text` | Log format: text or json |
| `--metrics-listen` | `""` | Separate metrics address (empty = serve on admin port) |
| `--rate-limit-pps` | `0` | Per-IP packet rate limit (0 = unlimited) |
| `--rate-limit-bps` | `0` | Per-IP byte rate limit (0 = unlimited) |
| `--conntrack-max` | `65536` | Max tracked connections |
| `--conntrack-idle` | `5m` | TCP connection idle timeout |
| `--conntrack-udp-timeout` | `30s` | UDP connection idle timeout |
| `--conntrack-icmp-timeout` | `5s` | ICMP connection idle timeout |
| `--conntrack-max-flows-per-src` | `0` | Max concurrent flows per source IP (0 = unlimited) |
| `--audit-log` | `""` | Path to structured JSON audit log (empty = no audit logging) |
| `--alert-webhook-url` | `""` | Webhook URL for firewall alerts (e.g. Slack, Discord, PagerDuty) |
| `--geoip-db` | `""` | Path to MaxMind GeoLite2/GeoIP2 .mmdb database for country lookup |
| `--threat-intel-url` | `""` | URL(s) to IP reputation blocklists (comma-separated, auto-refreshed) |

### Policy Configuration (embedded in `opa-policies/l3.rego`)

Configuration is embedded directly in the OPA/Rego policy file as Rego constants.
To change configuration: edit the `.rego` file — the hot-reloader picks up changes within 5 seconds.

| Constant | Type | Default | Description |
|----------|------|---------|-------------|
| `allowed_subnets` | array | `["0.0.0.0/0"]` | Allowed source/destination subnets |
| `allowed_ports` | array | `[]` | Only allow these ports (empty = allow all) |
| `blocked_ports` | array | `[22,23,3389,5900,5901]` | Blocked TCP/UDP ports |
| `blocked_protocols` | array | `[]` | Blocked IP protocols |
| `blocked_icmp_types` | array | `[8]` | Blocked ICMP types |
| `blocked_icmp_codes` | array | `[]` | Blocked ICMP codes |
| `syn_rate_per_second` | number | `100` | SYN flood threshold |
| `icmp_rate_per_second` | number | `10` | ICMP flood threshold |
| `max_packets_per_second` | number | `10000` | Per-IP packet rate limit |
| `enable_ip_spoofing_check` | bool | `true` | Enable IP spoofing detection |
| `enable_port_scan_detection` | bool | `true` | Enable port scan detection |
| `enable_syn_flood_protection` | bool | `true` | Enable SYN flood protection |
| `enable_stateful_inspection` | bool | `true` | Enable connection state tracking |
| `enable_ingress_egress_filtering` | bool | `true` | Enable ingress/egress filtering |
| `connection_table_size` | number | `65536` | Max tracked connections |
| `connection_idle_timeout_sec` | number | `300` | TCP connection idle timeout (s) |
| `connection_udp_timeout_sec` | number | `30` | UDP connection idle timeout (s) |
| `connection_icmp_timeout_sec` | number | `5` | ICMP connection idle timeout (s) |
| `port_scan_threshold` | number | `20` | Unique ports before scan detection |
| `port_scan_window_sec` | number | `10` | Port scan detection window |
| `max_new_connections_per_second` | number | `1000` | Per-IP new connection rate limit |
| `max_port_pps` | number | `500` | Per-destination-port PPS limit |
| `time_based_rules` | array | `[]` | Scheduled access rules: `{ports, days(0-6), start_hour, end_hour, effect("deny"|"allow")}` |
| `blocked_src_countries` | set | `{"KP"}` | Blocked source country codes (ISO 3166-1 alpha-2) |
| `allowed_src_countries` | set | `{}` | Only allow these source country codes (empty = allow all) |
| `allowed_dst_countries` | set | `{}` | Only allow these destination country codes (empty = allow all) |

## Security Features

| Feature | Mechanism | What it prevents |
|---------|-----------|------------------|
| Admin API auth | `--admin-token` | Unauthorized rule changes |
| OPA fail-closed | `--opa-fail-closed` | Bypass via OPA DoS |
| Audit-only mode | `--opa-audit-only` | Safe data collection before enforcement |
| Deny-override model | Default `allow := true` | Safe phased rollout |
| Rate limiter map cap | MaxEntries eviction (oldest-first) | Memory exhaustion from unique IPs |
| Block stats reason cap | 256 unique deny reasons max | Memory exhaustion from reason flooding |
| Engine panic recovery | defer/recover in packetHandler + evaluatePacket | Process crash from unexpected panics |
| Configurable OPA timeout | EmbedConfig.Timeout (0=500ms default) | Workload-specific timeout tuning |
| TCP FSM tracking | 9-state machine (SYN→ESTABLISHED→FIN→CLOSED) | Connection state violation, evasive handshakes |
| Fragmentation detection | Parse IPv4 FragOffset + MoreFragments | Fragment-based evasion (overlap, tiny fragment) |
| CIDR subnet matching | `net.cidr_contains` | Real subnet filtering (not string match) |
| Port ranges | `port_in_ranges()` helper | Range-based rules (e.g. `"8000-9000"`) |
| Per-protocol timeouts | TCP=300s, UDP=30s, ICMP=5s | Optimal memory usage per protocol |
| Drop logging | Structured slog + ring buffer | Forensic analysis of blocked traffic |
| Recent-blocks API | `/admin/blocks` | Real-time visibility into blocks |
| Conntrack stats | `/admin/stats` | Monitoring connection table health |
| Engine health | `/admin/health` endpoint | Liveness and readiness probes |
| Bodies size limit | `http.MaxBytesReader` | Admin API OOM |
| Server timeouts | `ReadHeaderTimeout`, `IdleTimeout` | Slow loris / connection exhaustion |
| Graceful shutdown | Signal handling + context cancellation | Dropped connections on deploy |
| Per-IP rate tracking | EWMA-based PPS/BPS | Memory-efficient rate estimation |
| Connection limit | Per-source flow counter capped by `MaxFlowsPerSrcIP` | DoS via excessive concurrent connections |
| Time-based scheduling | `time_based_rules` in Rego policy with UTC hour/day | Access outside approved hours |
| Audit logging | `--audit-log` writes structured JSON | SIEM integration, compliance audit trail |
| Webhook alerts | `--alert-webhook-url` fires JSON POST on events | Real-time incident notification |
| GeoIP filtering | `--geoip-db` + Rego `blocked_src_countries` / `allowed_src_countries` | Country-based access control |
| Threat intel feeds | `--threat-intel-url` fetches IP blocklists | Known-bad-IP blocking |

## Project Structure

```
l3-firewall/
├── cmd/server/main.go              # Entry point, flag parsing, wiring
├── internal/
│   ├── packet/parser.go            # L3/L4 header parsing (gopacket)
│   ├── engine/engine.go            # NFQUEUE reader, eval pipeline
│   ├── opa/                        # OPA embedded evaluator
│   │   ├── embed.go                #   In-process Rego evaluation
│   │   ├── input.go                #   Input document builder
│   │   ├── result.go               #   Result type
│   │   ├── store.go                #   Thread-safe params store
│   │   └── evaluator.go            #   Evaluator interface
│   ├── conntrack/table.go          # 5-tuple connection tracking
│   ├── ratelimit/ratelimit.go      # Per-IP EWMA rate limiter
│   ├── alert/alert.go              # Webhook alerting with cooldown
│   ├── audit/audit.go              # Structured JSON audit logging
│   ├── geoip/geoip.go              # MaxMind GeoIP country lookup
│   ├── threatintel/threatintel.go  # IP reputation blocklist fetcher
│   ├── metrics/metrics.go          # Prometheus metrics
│   └── admin/api.go                # REST admin API
├── opa-policies/
│   ├── l3.rego                     # 10 attack rule categories
│   └── l3_test.rego                # Rego policy tests
├── config/params.json              # Default parameters
├── deploy/entrypoint.sh            # Container nftables setup
├── Makefile                        # Build, test, lint, docker
├── Dockerfile                      # Multi-stage container build
└── .github/workflows/ci.yml        # CI pipeline
```

## OPA Policy Testing

All firewall rules are testable before deployment:

```bash
# Test all Rego policies
opa test opa-policies/ -v

# Test with coverage
opa test opa-policies/ --coverage

# Test individually
opa test opa-policies/ -r test_default_allow
```

Example Rego policy test (`opa-policies/l3_test.rego`):

```rego
package l3_firewall

mock_params := {"enable_ip_spoofing_check": false}

test_default_allow if {
    allow with data.params as mock_params
}

test_ip_in_subnets_exact if {
    ip_in_subnets("10.0.0.1", {"10.0.0.1"})
}
```

## Performance

- **Packet parsing**: ~1µs per packet (gopacket, cached layer types)
- **OPA evaluation**: ~10µs per packet (in-process, prepared query)
- **Connection lookup**: O(1) hash map with RWMutex
- **Rate limiting**: O(1) EWMA update

## Comparison

| Feature | l3-firewall | nftables | iptables |
|---------|-------------|----------|----------|
| Policy language | Rego (testable) | nft syntax | iptables syntax |
| Stateful inspection | ✅ 5-tuple tracking | ✅ conntrack | ✅ conntrack |
| Port scan detection | ✅ OPA configurable | ❌ | ❌ |
| Dynamic rule updates | ✅ REST API | nft commands | iptables commands |
| Audit-only mode | ✅ | ❌ | ❌ |
| Policy testing | ✅ `opa test` | ❌ | ❌ |
| Per-IP rate limiting | ✅ EWMA-based | ✅ limit match | ✅ limit match |
| Protocol anomaly detection | ✅ OPA rules | ❌ | ❌ |
| Container support | ✅ `--cap-add=NET_ADMIN` | ✅ | ✅ |
