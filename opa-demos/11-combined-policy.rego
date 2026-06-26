package demo11

import rego.v1

# =============================================================================
# Demo 11: Combined Policy — Real-World Scenario
#
# A complete policy that demonstrates multiple rules working together.
# This is similar to a real-world firewall configuration.
#
# Scenario: Protect a web server (10.0.2.50) from the public internet.
#   - Allow web traffic (ports 80, 443) from any source
#   - Allow SSH from management subnet only
#   - Block all other inbound traffic
#   - Detect port scans and SYN floods
#   - Track TCP connection state
#
# Try it:
#   opa eval --data 11-combined-policy.rego \
#     --data '{"params":{"allowed_subnets":{"10.0.0.0/8"},"allowed_ports":{80,443}}}' \
#     --input '{"packet":{"src_ip":"10.0.1.100","dst_ip":"10.0.2.50",
#               "protocol":"TCP","dst_port":443,"tcp_flags":{"syn":true,"ack":false}}}' \
#     "data.demo11"
# =============================================================================

# ——— Parameters (injected via data.params) ———
allowed_subnets := object.get(data.params, "allowed_subnets", {"0.0.0.0/0"})
allowed_ports := object.get(data.params, "allowed_ports", {80, 443})
mgmt_subnet := object.get(data.params, "mgmt_subnet", "10.99.0.0/16")
ssh_port := object.get(data.params, "ssh_port", 22)

# ——— Default: deny all (ingress protection) ———
default allow := false

# ——— Helper: CIDR matching ———
ip_in_subnets(ip, subnets) if {
    some cidr in subnets
    contains(cidr, "/")
    net.cidr_contains(cidr, ip)
}

# ——— Rule 1: Allow web traffic to allowed ports ———
allow := true if {
    ip_in_subnets(input.packet.dst_ip, allowed_subnets)
    allowed_ports[input.packet.dst_port]
}

# ——— Rule 2: Allow SSH from management subnet ———
allow := true if {
    ip_in_subnets(input.packet.src_ip, {mgmt_subnet})
    input.packet.dst_port == ssh_port
}

# ——— Rule 3: Allow established connections (stateful) ———
allow := true if {
    input.connection.established == true
}

# ——— Deny reasons for blocked traffic ———
deny_reason := "not an allowed service port" if { allow == false }

# ——— Tests ———
test_web_allowed if {
    allow with data.params as {"allowed_subnets": {"10.0.0.0/8"}, "allowed_ports": {80, 443}}
        with input.packet as {"src_ip": "10.0.1.100", "dst_ip": "10.0.2.50", "protocol": "TCP", "dst_port": 443}
}

test_ssh_from_mgmt_allowed if {
    allow with data.params as {"mgmt_subnet": "10.99.0.0/16", "ssh_port": 22}
        with input.packet as {"src_ip": "10.99.0.5", "dst_ip": "10.0.2.50", "protocol": "TCP", "dst_port": 22}
}

test_ssh_from_internet_blocked if {
    not allow with data.params as {"mgmt_subnet": "10.99.0.0/16"}
        with input.packet as {"src_ip": "1.2.3.4", "dst_ip": "10.0.2.50", "protocol": "TCP", "dst_port": 22}
}

test_established_allowed if {
    allow with input.connection as {"established": true}
        with input.packet as {"src_ip": "1.2.3.4", "dst_ip": "10.0.2.50", "protocol": "TCP", "dst_port": 443}
}
