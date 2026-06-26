# OPA Demo Policies for l3-firewall

This directory contains standalone, self-contained OPA/Rego policy demonstrations that showcase every capability of the l3-firewall. Each policy is a complete, runnable example with inline tests.

## Prerequisites

- [OPA (Open Policy Agent)](https://www.openpolicyagent.org/) v1.0+ installed
- l3-firewall running (for live testing with actual packet data)

```bash
# Install OPA
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod +x opa && sudo mv opa /usr/local/bin/

# Verify
opa version
```

## Running the Demos

### Run all demo tests:

```bash
opa test opa-demos/ -v
```

### Run a single demo:

```bash
opa test opa-demos/01-deny-override.rego -v
```

### Evaluate a policy with custom input:

```bash
# Allow test (packet to port 80)
echo '{"packet":{"protocol":"TCP","dst_port":80}}' | \
  opa eval --data opa-demos/01-deny-override.rego \
    --input-file /dev/stdin "data.demo01"

# Block test (packet to port 22)
echo '{"packet":{"protocol":"TCP","dst_port":22}}' | \
  opa eval --data opa-demos/01-deny-override.rego \
    --input-file /dev/stdin "data.demo01"
```

### Evaluate with injected parameters:

```bash
# CIDR matching with custom allowed subnets
echo '{"packet":{"src_ip":"10.0.1.100"}}' | \
  opa eval --data opa-demos/02-cidr-subnet.rego \
    --data '{"params":{"allowed_subnets":{"10.0.0.0/8"}}}' \
    --input-file /dev/stdin "data.demo02"
```

## Demo Index

| # | File | Concept | Key OPA Features |
|---|------|---------|-----------------|
| 01 | `01-deny-override.rego` | Deny-override security model | `default allow`, complete rules, rule chaining |
| 02 | `02-cidr-subnet.rego` | CIDR subnet matching | `net.cidr_contains`, `contains()`, `some` iteration |
| 03 | `03-port-scan.rego` | Port scan detection | `object.get()`, `count()`, multi-condition rules |
| 04 | `04-tcp-flags.rego` | TCP flag anomaly detection | Function definitions (`invalid_tcp_flags`), conjunction |
| 05 | `05-port-ranges.rego` | Port range blocking | `split()`, `to_number()`, string parsing in Rego |
| 06 | `06-icmp-control.rego` | ICMP type/code blocking | `sprintf()`, pointer types (`icmp_type`) |
| 07 | `07-stateful-inspection.rego` | TCP state violation | Connection state awareness, `established` flag |
| 08 | `08-rate-limiting.rego` | Per-IP and per-port rate limits | `input.rate` object, multi-level limits |
| 09 | `09-fragment-attack.rego` | IP fragment attack detection | `input.packet.fragment` sub-object |
| 10 | `10-source-port.rego` | Source port filtering | `src_port` vs `dst_port`, bidirectional rules |
| 11 | `11-combined-policy.rego` | Real-world combined policy | `default allow := false`, multiple `allow` rules, CIDR + port + stateful |
| 12 | `12-params-injection.rego` | Dynamic parameter injection | `object.get()` with defaults, runtime configuration |

## Demo Details

### 01 — Deny-Override Model

The fundamental security model of l3-firewall. Traffic passes by default (`allow := true`) and is blocked only when a deny rule matches. This is safer than default-deny because a misconfigured policy still allows traffic through rather than blocking everything.

```rego
default allow := true      # Traffic passes by default

deny_ssh if { input.packet.dst_port == 22 }
allow := false if { deny_ssh }  # Only blocked when deny rule fires
```

### 02 — CIDR Subnet Matching

Uses OPA's built-in `net.cidr_contains` function for proper IP-in-subnet checks. Supports both CIDR notation (`"10.0.0.0/8"`) and exact IPs (`"10.0.0.1"`).

The policy uses two `ip_in_subnets` rules: one that checks for CIDR notation (strings containing "/") and one that checks for exact IP membership. This separation handles both cases efficiently.

### 03 — Port Scan Detection

Detects rapid connections to many different destination ports from a single source IP. The connection tracking module (in Go) accumulates recent destination ports per source IP and passes them to OPA via `input.connection.recent_ports`.

The rule triggers when all conditions are met:
- Port scan detection is enabled
- This is the first packet in a new flow (`packets_in_flow == 1`)
- The packet is a SYN (new connection attempt)
- The number of recent unique destination ports exceeds the threshold

### 04 — TCP Flag Anomaly Detection

Detects invalid TCP flag combinations that should never occur in normal TCP traffic. These combinations are often used by port scanners and malicious tools:

| Combination | Why Invalid |
|-------------|-------------|
| **SYN + RST** | Cannot synchronize AND reset simultaneously |
| **FIN + RST** | Cannot finish AND reset simultaneously |
| **SYN + FIN** | Cannot synchronize AND finish simultaneously |

### 05 — Port Ranges

Block ports using individual port numbers (`22`) or ranges (`"8000-9000"`). The `port_in_ranges` helper parses the `"LOWER-UPPER"` syntax using OPA's `split()` and `to_number()` built-ins.

This enables concise configurations like:
```json
{"blocked_ports": [22, 3389, "8000-9000", "10000-20000"]}
```

### 06 — ICMP Control

Block specific ICMP types and codes, and rate-limit ICMP floods. Common ICMP types:

| Type | Name | Common Use |
|------|------|------------|
| 0 | Echo Reply | ping response |
| 3 | Destination Unreachable | routing errors |
| 8 | Echo Request | ping request |
| 11 | Time Exceeded | traceroute |

### 07 — Stateful TCP Inspection

Detects RST packets sent to non-existent connections. The Go conntrack module tracks TCP connections through a 9-state finite state machine (SYN_SENT → SYN_RECEIVED → ESTABLISHED → FIN_WAIT → CLOSED) and passes the state to OPA.

### 08 — Rate Limiting

Three levels of rate limiting with configurable thresholds:

1. **Per-source-IP**: Total packets per second from a single source
2. **Per-destination-port**: Packets per second to a specific port from one source
3. **New connection rate**: New TCP connections per second from one source

All rates are computed via EWMA (Exponentially Weighted Moving Average) for smooth estimation.

### 09 — Fragment Attack Detection

IP fragments with non-zero offset can be used to evade signature-based detection. The packet parser extracts fragmentation information from the IPv4 header and passes it to OPA:

```json
"fragment": {"is_fragment": true, "offset": 100, "more_fragments": true}
```

### 10 — Source Port Filtering

In addition to blocking by destination port, l3-firewall can block traffic based on source port. This is useful for blocking traffic from known bad actor source ports or enforcing egress policies. Uses the same `port_in_ranges` helper so ranges are supported.

### 11 — Combined Policy (Real-World Scenario)

A complete policy that demonstrates multiple rules working together. This is similar to a real-world firewall configuration protecting a web server:

- **Default**: Deny all inbound traffic (ingress protection)
- **Allow**: Web traffic to ports 80/443 from any allowed subnet
- **Allow**: SSH from a management subnet only
- **Allow**: Established connections (stateful firewall)
- **Deny**: Everything else with a clear reason

This demo uses `default allow := false` (default-deny) instead of the traditional deny-override model, demonstrating both security postures.

### 12 — Dynamic Parameter Injection

Demonstrates how configuration parameters are injected into OPA via `data.params`. Parameters can be:
- Loaded from `config/params.json` at startup
- Updated at runtime via `POST /admin/rules/update`
- Different per source IP (via tenant-aware configuration)

Each parameter uses `object.get(data.params, "key", default_value)` to provide safe defaults when a parameter is not configured.

## Learning OPA/Rego

### Official Resources

| Resource | Description | Link |
|----------|-------------|------|
| **OPA Documentation** | Official docs — policy language, CLI, API | https://www.openpolicyagent.org/docs/latest/ |
| **Rego Playground** | Interactive Rego editor in your browser | https://play.openpolicyagent.org/ |
| **Policy Reference** | Complete Rego built-in function reference | https://www.openpolicyagent.org/docs/latest/policy-reference/ |
| **Rego Cheatsheet** | Quick syntax reference | https://www.openpolicyagent.org/docs/latest/rego-cheatsheet/ |
| **OPA GitHub** | Source code, issues, discussions | https://github.com/open-policy-agent/opa |
| **OPA Slack** | Community chat (join via website) | https://openpolicyagent.slack.com/ |

### Key Rego Concepts Used in These Demos

| Concept | Syntax | When to Use |
|---------|--------|-------------|
| **Default rule** | `default allow := true` | Set fallback value when no other rule matches |
| **Complete rule** | `allow := false if { ... }` | Define a single value based on conditions |
| **Partial rule** | `deny_ssh if { ... }` | Define a boolean that's true when conditions met |
| **Rule chaining** | `allow := false if { deny_ssh }` | Compose rules from other rules |
| **Data injection** | `object.get(data.params, "key", default)` | Accept external configuration with defaults |
| **Set membership** | `blocked_ports[port]` | Check if a value is in a set |
| **Iteration** | `some cidr in subnets` | Iterate over a collection |
| **String functions** | `split()`, `contains()`, `sprintf()` | Parse and format strings |
| **Net functions** | `net.cidr_contains(cidr, ip)` | Check if an IP belongs to a subnet |
| **Function rules** | `invalid_tcp_flags(flags) if { ... }` | Reusable logic with parameters |
| **`with` keyword** | `allow with data.params as {...}` | Override data/input for testing |
| **`not` operator** | `not allow with ...` | Assert that a rule does NOT match |

### Testing OPA Policies

```bash
# Run all tests
opa test opa-demos/ -v

# Run with coverage
opa test opa-demos/ --coverage

# Run a single test
opa test opa-demos/ -r test_scan_blocked -v

# Format a policy file
opa fmt opa-demos/05-port-ranges.rego
```

### Typical Workflow

1. **Write the policy** in a `.rego` file
2. **Add tests** (rules starting with `test_`)
3. **Run `opa test`** to verify
4. **Deploy** the policy to l3-firewall via `--opa-embed`
5. **Iterate** using `POST /admin/rules/update` for live parameter tuning

## Relationship to l3-firewall

These demos use the same input structure that l3-firewall sends to OPA:

```json
{
  "packet": {
    "src_ip": "10.0.1.100",
    "dst_ip": "10.0.2.50",
    "protocol": "TCP",
    "src_port": 44001,
    "dst_port": 443,
    "tcp_flags": {"syn": true, "ack": false, "rst": false, "fin": false},
    "icmp_type": null,
    "icmp_code": null,
    "fragment": {"is_fragment": false, "more_fragments": false, "offset": 0},
    "packet_size": 64
  },
  "connection": {
    "established": true,
    "tcp_state": "ESTABLISHED",
    "packets_in_flow": 42,
    "age_ms": 5000,
    "recent_ports": [22, 80, 443]
  },
  "rate": {
    "src_ip_pps": 10.5,
    "src_ip_bps": 84000,
    "src_port_pps": 2.1,
    "src_port_bps": 16800,
    "new_conns_per_sec": 5.0
  }
}
```

The full l3-firewall Rego policy is at `opa-policies/l3.rego` — it combines all these capabilities into a single policy used by the firewall engine.
