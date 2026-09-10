package demo06

import rego.v1

# =============================================================================
# Demo 06: ICMP Control
#
# Block specific ICMP types and codes, and rate-limit ICMP floods.
# ICMP type 8 = Echo Request (ping), type 0 = Echo Reply
# ICMP type 3 = Destination Unreachable, type 11 = Time Exceeded
#
# Try it:
#   echo '{"packet":{"protocol":"ICMP","icmp_type":8,"icmp_code":0}}' | \
#     opa eval --data 06-icmp-control.rego --input-file /dev/stdin "data.demo06"
# =============================================================================

default allow := true

blocked_icmp_types := object.get(data.params, "blocked_icmp_types", {8})
blocked_icmp_codes := object.get(data.params, "blocked_icmp_codes", {})
icmp_rate_limit := object.get(data.params, "icmp_rate_per_second", 10)

# Block specific ICMP types (default: block Echo Request / ping)
deny_icmp_type if {
    input.packet.protocol == "ICMP"
    blocked_icmp_types[input.packet.icmp_type]
}

allow := false if { deny_icmp_type }
deny_reasons contains sprintf("blocked ICMP type %v", [input.packet.icmp_type]) if { deny_icmp_type }

# Block specific ICMP codes
deny_icmp_code if {
    input.packet.protocol == "ICMP"
    blocked_icmp_codes[input.packet.icmp_code]
}

allow := false if { deny_icmp_code }

# Rate-limit ICMP floods
deny_icmp_flood if {
    input.packet.protocol == "ICMP"
    input.rate.src_ip_pps > icmp_rate_limit
}

allow := false if { deny_icmp_flood }
deny_reasons contains "ICMP flood" if { deny_icmp_flood }

# Result: exactly one deterministic reason string. deny_reasons is a partial
# set on purpose — an ICMP echo request during a flood matches deny_icmp_type
# AND deny_icmp_flood, and spelling these as repeated complete rules
# (`deny_reason := "..." if {...}`) makes OPA raise
#   eval_conflict_error: complete rules must not produce multiple outputs
# for the whole document, which an embedded engine can turn into an allow (R78).
deny_reason := sorted[0] if {
    sorted := sort(deny_reasons)
    count(sorted) > 0
}

test_echo_request_blocked if {
    not allow with data.params as {} with input.packet as {"protocol": "ICMP", "icmp_type": 8, "icmp_code": 0}
}

# Overlapping rules must deny with a settled reason, not error out (R78).
test_echo_request_during_flood_denies if {
    not allow
        with data.params as {}
        with input.packet as {"protocol": "ICMP", "icmp_type": 8, "icmp_code": 0}
        with input.rate as {"src_ip_pps": 50}
}

test_echo_request_during_flood_reason_is_settled if {
    # Both deny_icmp_type and deny_icmp_flood match; the single-body
    # deny_reason rule reports the lexicographically first, so the document
    # evaluates instead of raising eval_conflict_error.
    deny_reason == "ICMP flood"
        with data.params as {}
        with input.packet as {"protocol": "ICMP", "icmp_type": 8, "icmp_code": 0}
        with input.rate as {"src_ip_pps": 50}
}

test_echo_reply_allowed if {
    allow with input.packet as {"protocol": "ICMP", "icmp_type": 0, "icmp_code": 0}
}
