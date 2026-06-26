package demo12

import rego.v1

# =============================================================================
# Demo 12: Dynamic Parameter Injection
#
# l3-firewall injects configuration parameters into OPA via data.params.
# Parameters can be:
#   1. Loaded from config/params.json at startup
#   2. Updated at runtime via POST /admin/rules/update
#   3. Different per tenant (via X-API-Key header)
#
# This enables live policy tuning without restarting the firewall.
# The object.get function provides safe defaults when a parameter
# is not configured.
#
# Try it (override default limit):
#   opa eval --data 12-params-injection.rego \
#     --data '{"params":{"syn_rate_per_second":500}}' \
#     --input '{"rate":{"src_ip_pps":200},"packet":{"protocol":"TCP",
#              "tcp_flags":{"syn":true,"ack":false}}}' "data.demo12"
# =============================================================================

default allow := true

# Each parameter uses object.get with a safe default
syn_rate_limit := object.get(data.params, "syn_rate_per_second", 100)
max_field_count := object.get(data.params, "max_field_count", 500)
blocked_ports := object.get(data.params, "blocked_ports", {22, 23, 3389})
enable_feature := object.get(data.params, "enable_feature_x", false)
custom_message := object.get(data.params, "custom_block_message", "blocked by policy")

# Example: SYN flood protection with configurable threshold
deny_syn_flood if {
    input.packet.protocol == "TCP"
    input.packet.tcp_flags.syn == true
    input.packet.tcp_flags.ack == false
    input.rate.src_ip_pps > syn_rate_limit
}

allow := false if { deny_syn_flood }
deny_reason := custom_message if { deny_syn_flood }

# An optional feature that can be toggled at runtime
deny_custom_rule if {
    enable_feature == true
    # custom logic here
    false  # disabled in this demo
}

# Test with custom params
test_custom_limit if {
    not allow with data.params as {"syn_rate_per_second": 50}
        with input.packet as {"protocol": "TCP", "tcp_flags": {"syn": true, "ack": false}}
        with input.rate as {"src_ip_pps": 100}
}

test_custom_message if {
    deny_reason == "custom block" with data.params as {"custom_block_message": "custom block", "syn_rate_per_second": 1}
        with input.packet as {"protocol": "TCP", "tcp_flags": {"syn": true, "ack": false}}
        with input.rate as {"src_ip_pps": 100}
}
