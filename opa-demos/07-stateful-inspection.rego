package demo07

import rego.v1

# =============================================================================
# Demo 07: Stateful TCP Inspection
#
# Tracks TCP connection state via a 9-state finite state machine.
# The conntrack module tracks SYN → SYN-ACK → ESTABLISHED → FIN → CLOSED
# transitions and passes the state to OPA via input.connection.tcp_state.
#
# This rule detects RST packets sent to non-existent connections.
#
# Try it:
#   echo '{"packet":{"protocol":"TCP","tcp_flags":{"rst":true}},
#          "connection":{"established":false,"tcp_state":"SYN_SENT"}}' | \
#     opa eval --data 07-stateful-inspection.rego \
#     --input-file /dev/stdin "data.demo07"
# =============================================================================

default allow := true

enable_stateful := object.get(data.params, "enable_stateful_inspection", true)

# RST to a non-existent connection is a state violation
deny_state_violation if {
    enable_stateful == true
    input.packet.protocol == "TCP"
    input.packet.tcp_flags.rst == true
    input.connection.established == false
}

allow := false if { deny_state_violation }
deny_reason := "RST to non-existent flow" if { deny_state_violation }

test_rst_no_flow_blocked if {
    not allow with data.params as {"enable_stateful_inspection": true}
        with input.packet as {"protocol": "TCP", "tcp_flags": {"rst": true}}
        with input.connection as {"established": false}
}

test_rst_established_allowed if {
    allow with input.packet as {"protocol": "TCP", "tcp_flags": {"rst": true}}
        with input.connection as {"established": true}
}
