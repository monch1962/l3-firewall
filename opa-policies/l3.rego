# l3-firewall — L3 firewall Rego policies
#
# Deny-override model: traffic passes by default, blocked only by matching deny rules.
# Parameters are injected via OPA data (data.params).
#
# Input structure:
#   input.packet       — parsed packet headers
#   input.connection   — connection state (established, packets_in_flow, age_ms)
#   input.rate         — per-source rate info (src_ip_pps, src_ip_bps)

package l3_firewall

import rego.v1

# =============================================================================
# PARAMETERS (injected via data.params)
# =============================================================================

# Helper function to safely get parameters with defaults
param_or_default(key, default_val) := val if {
    val := object.get(data.params, key, default_val)
}

# Parameter accessors
allowed_subnets_set := object.get(data.params, "allowed_subnets", {"0.0.0.0/0"})
allowed_ports_set := object.get(data.params, "allowed_ports", {})
blocked_ports_set := object.get(data.params, "blocked_ports", {22, 23, 3389, 5900, 5901})
blocked_protocols_set := object.get(data.params, "blocked_protocols", {})
blocked_icmp_types_set := object.get(data.params, "blocked_icmp_types", {8})
blocked_icmp_codes_set := object.get(data.params, "blocked_icmp_codes", {})
syn_rate_limit := object.get(data.params, "syn_rate_per_second", 100)
icmp_rate_limit := object.get(data.params, "icmp_rate_per_second", 10)
max_pps := object.get(data.params, "max_packets_per_second", 10000)
port_scan_threshold := object.get(data.params, "port_scan_threshold", 20)
enable_ip_spoofing := object.get(data.params, "enable_ip_spoofing_check", true)
enable_port_scan := object.get(data.params, "enable_port_scan_detection", true)
enable_syn_flood := object.get(data.params, "enable_syn_flood_protection", true)
enable_stateful := object.get(data.params, "enable_stateful_inspection", true)
enable_fragment := object.get(data.params, "enable_fragment_attack_detection", true)
enable_ingress_egress := object.get(data.params, "enable_ingress_egress_filtering", true)

# =============================================================================
# DEFAULT: allow all traffic
# =============================================================================

default allow := true

# =============================================================================
# RULE 1: IP Spoofing — source IP not in allowed subnets
# =============================================================================

deny_ip_spoofing if {
    enable_ip_spoofing == true
    src_ip := input.packet.src_ip
    not ip_in_subnets(src_ip, allowed_subnets_set)
}

allow := false if { deny_ip_spoofing }
deny_reason := "IP spoofing detected" if { deny_ip_spoofing }

# =============================================================================
# RULE 2: Port Scanning — rapid connections to multiple ports
# =============================================================================

deny_port_scan if {
    enable_port_scan == true
    input.connection.packets_in_flow == 1
    input.packet.tcp_flags.syn == true
    input.packet.tcp_flags.ack == false
    count(input.connection.recent_ports) >= port_scan_threshold
}

allow := false if { deny_port_scan }
deny_reason := "port scan detected" if { deny_port_scan }

# =============================================================================
# RULE 3: SYN Flood — rate of SYN-only packets exceeds threshold
# =============================================================================

deny_syn_flood if {
    enable_syn_flood == true
    input.packet.protocol == "TCP"
    input.packet.tcp_flags.syn == true
    input.packet.tcp_flags.ack == false
    input.rate.src_ip_pps > syn_rate_limit
}

allow := false if { deny_syn_flood }
deny_reason := "SYN flood detected" if { deny_syn_flood }

# =============================================================================
# RULE 4: Protocol Anomaly — invalid flag combinations
# =============================================================================

deny_protocol_anomaly if {
    input.packet.protocol == "TCP"
    invalid_tcp_flags(input.packet.tcp_flags)
}

allow := false if { deny_protocol_anomaly }
deny_reason := "protocol anomaly detected" if { deny_protocol_anomaly }

invalid_tcp_flags(flags) if {
    flags.syn == true
    flags.rst == true
}

invalid_tcp_flags(flags) if {
    flags.fin == true
    flags.rst == true
}

invalid_tcp_flags(flags) if {
    flags.syn == true
    flags.fin == true
}

# =============================================================================
# RULE 5: Ingress/Egress Filtering — source/dest not in allowed subnets
# =============================================================================

deny_ingress_egress if {
    enable_ingress_egress == true
    dst_ip := input.packet.dst_ip
    not ip_in_subnets(dst_ip, allowed_subnets_set)
}

allow := false if { deny_ingress_egress }
deny_reason := "ingress/egress filtering blocked" if { deny_ingress_egress }

# =============================================================================
# RULE 6: Port Control — block specific ports
# =============================================================================

deny_blocked_port if {
    input.packet.protocol == "TCP"
    blocked_ports_set[input.packet.dst_port]
}

allow := false if { deny_blocked_port }

deny_blocked_port if {
    input.packet.protocol == "UDP"
    blocked_ports_set[input.packet.dst_port]
}

allow := false if { deny_blocked_port }

deny_reason := sprintf("blocked port %v (%s)", [input.packet.dst_port, input.packet.protocol]) if { deny_blocked_port }

# =============================================================================
# RULE 7: ICMP Control — block specific ICMP types/codes
# =============================================================================

deny_icmp if {
    input.packet.protocol == "ICMP"
    blocked_icmp_types_set[input.packet.icmp_type]
}

allow := false if { deny_icmp }

deny_icmp if {
    input.packet.protocol == "ICMP"
    blocked_icmp_codes_set[input.packet.icmp_code]
}

allow := false if { deny_icmp }

deny_reason := sprintf("blocked ICMP type=%v code=%v", [input.packet.icmp_type, input.packet.icmp_code]) if { deny_icmp }

deny_icmp_flood if {
    input.packet.protocol == "ICMP"
    input.rate.src_ip_pps > icmp_rate_limit
}

allow := false if { deny_icmp_flood }
deny_reason := "ICMP flood detected" if { deny_icmp_flood }

# =============================================================================
# RULE 8: Connection State Violation
# =============================================================================

deny_state_violation if {
    enable_stateful == true
    input.packet.protocol == "TCP"
    input.packet.tcp_flags.rst == true
    input.connection.established == false
}

allow := false if { deny_state_violation }
deny_reason := "connection state violation: RST to non-existent flow" if { deny_state_violation }

# =============================================================================
# RULE 9: Protocol Blocking
# =============================================================================

deny_blocked_protocol if {
    blocked_protocols_set[input.packet.protocol]
}

allow := false if { deny_blocked_protocol }
deny_reason := sprintf("blocked protocol %v", [input.packet.protocol]) if { deny_blocked_protocol }

# =============================================================================
# RULE 10: Traffic Rate Limit
# =============================================================================

deny_traffic_rate if {
    input.rate.src_ip_pps > max_pps
}

allow := false if { deny_traffic_rate }
deny_reason := sprintf("rate limit exceeded: %v pps", [input.rate.src_ip_pps]) if { deny_traffic_rate }

# =============================================================================
# HELPERS
# =============================================================================

# Check if an IP belongs to any subnet in the set.
# Supports exact IPs (e.g. "10.0.0.1") and CIDR notation (e.g. "10.0.0.0/8").
# Uses net.cidr_contains for proper subnet matching.
ip_in_subnets(ip, subnets) if {
    some cidr in subnets
    contains(cidr, "/")
    net.cidr_contains(cidr, ip)
}

ip_in_subnets(ip, subnets) if {
    subnets[ip]
}

# =============================================================================
# RESULT — single reason string from the first matching deny rule
# =============================================================================

reason := deny_reason if { deny_reason != "" }
