package demo05

import rego.v1

# =============================================================================
# Demo 05: Port Ranges
#
# Block ports using individual port numbers ("22") or ranges ("8000-9000").
# The port_in_ranges helper parses "LOWER-UPPER" syntax and checks if a port
# falls within the range. Single ports are checked via set membership.
#
# Configured via data.params.blocked_ports which can contain:
#   [22, 3389, "8000-9000", "10000-20000"]
#
# Try it:
#   echo '{"packet":{"protocol":"TCP","dst_port":8500}}' | \
#     opa eval --data 05-port-ranges.rego \
#     --data '{"params":{"blocked_ports":[22,"8000-9000"]}}' \
#     --input-file /dev/stdin "data.demo05"
# =============================================================================

default allow := true

blocked_ports_set := object.get(data.params, "blocked_ports", {})

# Port range helper — handles "8000-9000" and individual ports
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

deny_port if {
    input.packet.protocol == "TCP"
    port_in_ranges(input.packet.dst_port, blocked_ports_set)
}

allow := false if { deny_port }
deny_reason := sprintf("blocked port %v", [input.packet.dst_port]) if { deny_port }

test_range_lower_bound if {
    not allow with data.params as {"blocked_ports": {"8000-9000"}}
        with input.packet as {"protocol": "TCP", "dst_port": 8000}
}

test_range_upper_bound if {
    not allow with data.params as {"blocked_ports": {"8000-9000"}}
        with input.packet as {"protocol": "TCP", "dst_port": 9000}
}

test_range_midpoint if {
    not allow with data.params as {"blocked_ports": {"8000-9000"}}
        with input.packet as {"protocol": "TCP", "dst_port": 8500}
}

test_single_port if {
    not allow with data.params as {"blocked_ports": {22}}
        with input.packet as {"protocol": "TCP", "dst_port": 22}
}
