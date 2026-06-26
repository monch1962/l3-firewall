package demo04

import rego.v1

# =============================================================================
# Demo 04: TCP Flag Anomaly Detection
#
# Detects invalid TCP flag combinations that should never occur in normal TCP
# traffic. These are often used by scanners and malicious tools.
#
# Invalid combinations:
#   SYN + RST  — Cannot synchronize AND reset simultaneously
#   FIN + RST  — Cannot finish AND reset simultaneously
#   SYN + FIN  — Cannot synchronize AND finish simultaneously
#
# Try it:
#   echo '{"packet":{"protocol":"TCP","tcp_flags":{"syn":true,"rst":true}}}' | \
#     opa eval --data 04-tcp-flags.rego --input-file /dev/stdin "data.demo04"
# =============================================================================

default allow := true

# Detect invalid TCP flag combinations
deny_anomaly if {
    input.packet.protocol == "TCP"
    invalid_tcp_flags(input.packet.tcp_flags)
}

allow := false if { deny_anomaly }
deny_reason := "invalid TCP flag combination" if { deny_anomaly }

invalid_tcp_flags(flags) if { flags.syn == true; flags.rst == true }
invalid_tcp_flags(flags) if { flags.fin == true; flags.rst == true }
invalid_tcp_flags(flags) if { flags.syn == true; flags.fin == true }

test_syn_rst_blocked if {
    not allow with input.packet as {"protocol": "TCP", "tcp_flags": {"syn": true, "rst": true}}
}

test_normal_syn_allowed if {
    allow with input.packet as {"protocol": "TCP", "tcp_flags": {"syn": true, "ack": false, "rst": false, "fin": false}}
}
