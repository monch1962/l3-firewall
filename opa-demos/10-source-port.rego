package demo10

import rego.v1

# =============================================================================
# Demo 10: Source Port Filtering
#
# In addition to blocking by destination port, l3-firewall can also block
# traffic based on source port. This is useful for blocking traffic from
# known bad actor source ports or enforcing egress source port policies.
#
# Uses the same port_in_ranges helper as destination port blocking, so
# ranges like "1024-65535" are supported.
#
# Try it:
#   echo '{"packet":{"protocol":"TCP","src_port":31337,"dst_port":443}}' | \
#     opa eval --data 10-source-port.rego \
#     --data '{"params":{"blocked_ports":{"31337"}}}' \
#     --input-file /dev/stdin "data.demo10"
# =============================================================================

default allow := true

blocked_ports_set := object.get(data.params, "blocked_ports", {})

port_in_ranges(port, ranges) if {
    some r in ranges
    contains(r, "-")
    parts := split(r, "-")
    lower := to_number(parts[0])
    upper := to_number(parts[1])
    port >= lower
    port <= upper
}

port_in_ranges(port, ranges) if {
    ranges[port]
}

deny_src_port if {
    input.packet.protocol == "TCP"
    port_in_ranges(input.packet.src_port, blocked_ports_set)
}

allow := false if { deny_src_port }
deny_reason := sprintf("blocked source port %v", [input.packet.src_port]) if { deny_src_port }

test_source_port_blocked if {
    not allow with data.params as {"blocked_ports": {31337}}
        with input.packet as {"protocol": "TCP", "src_port": 31337, "dst_port": 443}
}

test_source_port_allowed if {
    allow with data.params as {"blocked_ports": {31337}}
        with input.packet as {"protocol": "TCP", "src_port": 44001, "dst_port": 443}
}
