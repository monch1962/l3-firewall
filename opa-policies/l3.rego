# l3-firewall — L3 firewall Rego policies
#
# Configuration is embedded directly in this file as policy constants.
# To change configuration: edit this file, then hot-reload or restart.
# Tests: opa test opa-policies/ -v
#
# Input structure:
#   input.packet       — parsed packet headers (src_ip, dst_ip, protocol, ports, flags, fragment)
#   input.connection   — connection state (established, tcp_state, packets_in_flow, age_ms, recent_ports)
#   input.rate         — per-source rate info (src_ip_pps, src_ip_bps, src_port_pps, new_conns_per_sec)

package l3_firewall

import rego.v1

# =============================================================================
# CONFIGURATION — policy constants (edit to reconfigure)
# =============================================================================

# Network filtering
allowed_subnets := {"0.0.0.0/0"}           # Authorized source/destination subnets
blocked_ports := {22, 23, 3389, 5900, 5901} # Blocked TCP/UDP ports
blocked_protocols := {}                      # Blocked IP protocols (e.g. {"ICMP"})

# ICMP control
blocked_icmp_types := {8}                    # Blocked ICMP types (8 = Echo Request)
blocked_icmp_codes := {}                     # Blocked ICMP codes

# Rate limits
syn_rate_per_second := 100                   # SYN flood threshold (packets/sec)
icmp_rate_per_second := 10                   # ICMP flood threshold (packets/sec)
max_packets_per_second := 10000              # Per-IP rate limit (packets/sec)
max_port_pps := 500                          # Per-destination-port rate limit (packets/sec)
max_new_connections_per_second := 1000       # Per-IP new connection rate limit

# Detection toggles
enable_ip_spoofing := true
enable_port_scan := true
enable_syn_flood := true
enable_stateful := true
enable_fragment := false                     # Off by default; enable if fragmentation is not expected
enable_ingress_egress := true

# Port scan detection
port_scan_threshold := 20

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
    not ip_in_subnets(src_ip, allowed_subnets)
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
    input.rate.src_ip_pps > syn_rate_per_second
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

invalid_tcp_flags(flags) if { flags.syn == true; flags.rst == true }
invalid_tcp_flags(flags) if { flags.fin == true; flags.rst == true }
invalid_tcp_flags(flags) if { flags.syn == true; flags.fin == true }

# =============================================================================
# RULE 5: Ingress/Egress Filtering — dest IP not in allowed subnets
# =============================================================================

deny_ingress_egress if {
    enable_ingress_egress == true
    dst_ip := input.packet.dst_ip
    not ip_in_subnets(dst_ip, allowed_subnets)
}

allow := false if { deny_ingress_egress }
deny_reason := "ingress/egress filtering blocked" if { deny_ingress_egress }

# =============================================================================
# RULE 6: Port Control — block specific ports (with range support)
# =============================================================================

deny_blocked_port if { input.packet.protocol == "TCP"; port_in_ranges(input.packet.dst_port, blocked_ports) }
allow := false if { deny_blocked_port }

deny_blocked_port if { input.packet.protocol == "UDP"; port_in_ranges(input.packet.dst_port, blocked_ports) }
allow := false if { deny_blocked_port }

deny_reason := sprintf("blocked port %v (%s)", [input.packet.dst_port, input.packet.protocol]) if { deny_blocked_port }

# =============================================================================
# RULE 7: ICMP Control — block specific ICMP types/codes, rate-limit floods
# =============================================================================

deny_icmp if { input.packet.protocol == "ICMP"; blocked_icmp_types[input.packet.icmp_type] }
allow := false if { deny_icmp }

deny_icmp if { input.packet.protocol == "ICMP"; blocked_icmp_codes[input.packet.icmp_code] }
allow := false if { deny_icmp }

deny_reason := sprintf("blocked ICMP type=%v code=%v", [input.packet.icmp_type, input.packet.icmp_code]) if { deny_icmp }

deny_icmp_flood if { input.packet.protocol == "ICMP"; input.rate.src_ip_pps > icmp_rate_per_second }
allow := false if { deny_icmp_flood }
deny_reason := "ICMP flood detected" if { deny_icmp_flood }

# =============================================================================
# RULE 8: Connection State Violation — RST to non-existent flow
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

deny_blocked_protocol if { blocked_protocols[input.packet.protocol] }
allow := false if { deny_blocked_protocol }
deny_reason := sprintf("blocked protocol %v", [input.packet.protocol]) if { deny_blocked_protocol }

# =============================================================================
# RULE 10: Traffic Rate Limit — per-IP packets/sec budget
# =============================================================================

deny_traffic_rate if { input.rate.src_ip_pps > max_packets_per_second }
allow := false if { deny_traffic_rate }
deny_reason := sprintf("rate limit exceeded: %v pps", [input.rate.src_ip_pps]) if { deny_traffic_rate }

# =============================================================================
# RULE 11: Fragment Attack — non-zero-offset IP fragments
# =============================================================================

deny_fragment_attack if {
    enable_fragment == true
    input.packet.fragment.is_fragment == true
    input.packet.fragment.offset > 0
}

allow := false if { deny_fragment_attack }
deny_reason := sprintf("fragment attack: offset=%v", [input.packet.fragment.offset]) if { deny_fragment_attack }

# =============================================================================
# RULE 12: Source Port Filtering — block traffic from specific source ports
# =============================================================================

deny_source_port if { input.packet.protocol == "TCP"; port_in_ranges(input.packet.src_port, blocked_ports) }
allow := false if { deny_source_port }
deny_reason := sprintf("blocked source port %v (TCP)", [input.packet.src_port]) if { deny_source_port }

deny_source_port if { input.packet.protocol == "UDP"; port_in_ranges(input.packet.src_port, blocked_ports) }
allow := false if { deny_source_port }
deny_reason := sprintf("blocked source port %v (UDP)", [input.packet.src_port]) if { deny_source_port }

# =============================================================================
# RULE 13: New Connection Rate Limit
# =============================================================================

deny_new_conn_rate if { input.rate.new_conns_per_sec > max_new_connections_per_second }
allow := false if { deny_new_conn_rate }
deny_reason := sprintf("new connection rate exceeded: %v/sec", [input.rate.new_conns_per_sec]) if { deny_new_conn_rate }

# =============================================================================
# RULE 14: Per-Port Rate Limit — too much traffic to a specific dst port
# =============================================================================

deny_port_rate if { input.rate.src_port_pps > max_port_pps }
allow := false if { deny_port_rate }
deny_reason := sprintf("per-port rate limit: %v pps to port %v", [input.rate.src_port_pps, input.packet.dst_port]) if { deny_port_rate }

# =============================================================================
# HELPERS
# =============================================================================

# CIDR subnet matching — supports "10.0.0.0/8" and exact IPs
ip_in_subnets(ip, subnets) if {
    some cidr in subnets
    contains(cidr, "/")
    net.cidr_contains(cidr, ip)
}
ip_in_subnets(ip, subnets) if { subnets[ip] }

# Port range matching — supports "8000-9000" and single ports
port_in_ranges(port, ranges) if {
    some r in ranges
    contains(r, "-")
    parts := split(r, "-")
    lower := to_number(parts[0])
    upper := to_number(parts[1])
    port >= lower
    port <= upper
}
port_in_ranges(port, ranges) if { ranges[port] }

# =============================================================================
# RESULT — single reason string from the first matching deny rule
# =============================================================================

reason := deny_reason if { deny_reason != "" }
