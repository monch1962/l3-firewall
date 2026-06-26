package demo02

import rego.v1

# =============================================================================
# Demo 02: CIDR Subnet Matching
#
# Uses net.cidr_contains for proper IP-in-subnet checks.
# Supports both CIDR notation ("10.0.0.0/8") and exact IPs ("10.0.0.1").
#
# Try it:
#   echo '{"packet":{"src_ip":"10.0.1.100"}}' | \
#     opa eval --data 02-cidr-subnet.rego \
#     --input-file /dev/stdin "data.demo02"
# =============================================================================

default allow := true

# Parameter is injected via data.params.allowed_subnets
allowed_subnets := object.get(data.params, "allowed_subnets", {"0.0.0.0/0"})

# IP belonging test — handles both CIDR and exact IPs
ip_in_subnets(ip, subnets) if {
    some cidr in subnets
    contains(cidr, "/")
    net.cidr_contains(cidr, ip)
}

ip_in_subnets(ip, subnets) if {
    subnets[ip]
}

deny_spoof if {
    not ip_in_subnets(input.packet.src_ip, allowed_subnets)
}

allow := false if { deny_spoof }
deny_reason := "IP not in allowed subnets" if { deny_spoof }

# Test rules — run with: opa test 02-cidr-subnet.rego
test_cidr_match if {
    ip_in_subnets("10.0.1.100", {"10.0.0.0/8"})
}

test_cidr_no_match if {
    not ip_in_subnets("10.0.1.100", {"192.168.0.0/16"})
}

test_exact_ip if {
    ip_in_subnets("10.0.0.1", {"10.0.0.1"})
}
