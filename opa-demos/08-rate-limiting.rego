package demo08

import rego.v1

# =============================================================================
# Demo 08: Traffic Rate Limiting
#
# Three levels of rate limiting:
#   1. Per-source-IP: packets/sec from a single source
#   2. Per-destination-port: packets/sec to a specific port from one source
#   3. New connection rate: new TCP connections/sec from one source
#
# Rates are computed via EWMA (Exponentially Weighted Moving Average) for
# smooth estimation. The rates are passed to OPA via input.rate.
#
# Try it:
#   echo '{"packet":{"protocol":"TCP","dst_port":80},
#          "rate":{"src_ip_pps":500,"src_port_pps":200,"new_conns_per_sec":50}}' | \
#     opa eval --data 08-rate-limiting.rego --input-file /dev/stdin "data.demo08"
# =============================================================================

default allow := true

# Configurable limits (injected via data.params)
max_pps := object.get(data.params, "max_packets_per_second", 10000)
max_port_pps := object.get(data.params, "max_port_pps", 500)
max_new_conns := object.get(data.params, "max_new_connections_per_second", 1000)

# Level 1: Per-IP rate limit
deny_ip_rate if {
    input.rate.src_ip_pps > max_pps
}

allow := false if { deny_ip_rate }
deny_reason := sprintf("rate limit: %v pps", [input.rate.src_ip_pps]) if { deny_ip_rate }

# Level 2: Per-port rate limit  
deny_port_rate if {
    input.rate.src_port_pps > max_port_pps
}

allow := false if { deny_port_rate }
deny_reason := sprintf("port rate limit: %v pps to port %v", [input.rate.src_port_pps, input.packet.dst_port]) if { deny_port_rate }

# Level 3: New connection rate limit
deny_new_conn_rate if {
    input.rate.new_conns_per_sec > max_new_conns
}

allow := false if { deny_new_conn_rate }
deny_reason := sprintf("new conn rate: %v/sec", [input.rate.new_conns_per_sec]) if { deny_new_conn_rate }

test_ip_rate_allowed if {
    allow with input.rate as {"src_ip_pps": 100}
}

test_ip_rate_blocked if {
    not allow with data.params as {"max_packets_per_second": 10000}
        with input.rate as {"src_ip_pps": 99999}
}

test_port_rate_blocked if {
    not allow with data.params as {"max_port_pps": 100}
        with input.rate as {"src_port_pps": 200}
        with input.packet as {"protocol": "TCP", "dst_port": 80}
}
