# Configuration

**There is no parameters file. Configuration lives in the policy file.**

The firewall's behaviour is defined by the Rego policy loaded from
`--opa-embed` (default `./opa-policies/l3.rego`). Every tunable is a Rego
constant at the top of that file — `allowed_subnets`, `blocked_ports`,
`blocked_protocols`, `blocked_icmp_types` / `blocked_icmpv6_types`, the rate
thresholds, the `enable_*` detection toggles, the GeoIP country sets and
`time_based_rules`. Edit the policy, then either restart or let the hot-reload
watcher (5 s poll) pick it up.

The remaining knobs are command-line flags (`--queue`, `--conntrack-max`,
`--rate-limit-pps`, `--threat-intel-url`, `--admin-token`, …); see the flag
table in the top-level README.

## Why there is no `params.json` any more

Round 83 removed `config/params.json`. It was copied into the runtime image and
documented as "Default parameters", but **no code read it**: editing it changed
nothing, while its contents contradicted the enforced policy on three
security-relevant points —

| `params.json` said | Enforced policy said |
|---|---|
| `enable_fragment_attack_detection: true` | `enable_fragment := false` (RULE 11 off) |
| `enable_geo_ip_blocking: false` | `blocked_src_countries := {"KP"}` (blocking on) |
| `allowed_subnets: ["0.0.0.0/0"]` | `{"0.0.0.0/0", "::/0"}` (family-complete, R79.1) |

plus keys that exist nowhere (`allowed_ports`, `port_scan_window_sec`,
`enable_ip_spoofing_check`, `enable_stateful_inspection`). A file that looks
authoritative, changes nothing and misstates the control state is worse than no
file: it misleads operators and auditors, and anyone reconciling the drift by
wiring it would have reintroduced the R79.1 whole-family IPv6 blackhole and
silently disabled the GeoIP block. `cmd/server/attack_round83_test.go` keeps it
from coming back.
