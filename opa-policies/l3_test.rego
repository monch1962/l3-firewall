package l3_firewall

import rego.v1

# =============================================================================
# Mock data: params with all features disabled except the one under test
# =============================================================================

# All features disabled — everything allowed
default_mock := {"enable_ip_spoofing_check": false, "enable_port_scan_detection": false, "enable_syn_flood_protection": false, "enable_stateful_inspection": false, "enable_fragment_attack_detection": false, "enable_ingress_egress_filtering": false}

# IP spoofing enabled with specific subnets
ip_spoofing_params := object.union(default_mock, {"enable_ip_spoofing_check": true, "allowed_subnets": {"10.0.0.0/8", "192.168.0.0/16"}})

# Port scan enabled with low threshold
port_scan_params := object.union(default_mock, {"enable_port_scan_detection": true, "port_scan_threshold": 3})

# SYN flood enabled with low limit
syn_flood_params := object.union(default_mock, {"enable_syn_flood_protection": true, "syn_rate_per_second": 10})

# Ingress/egress filtering enabled
ingress_egress_params := object.union(default_mock, {"enable_ingress_egress_filtering": true, "allowed_subnets": {"10.0.0.0/8"}})

# Stateful inspection enabled
stateful_params := object.union(default_mock, {"enable_stateful_inspection": true})

# =============================================================================
# DEFAULT ALLOW TEST
# =============================================================================

test_default_allow if {
    allow with data.params as default_mock
}

# =============================================================================
# RULE 1: CIDR SUBNET MATCHING
# =============================================================================

test_ip_in_subnets_cidr_match if {
    ip_in_subnets("10.0.1.100", {"10.0.0.0/8"})
}

test_ip_in_subnets_cidr_no_match if {
    not ip_in_subnets("10.0.1.100", {"192.168.0.0/16"})
}

test_ip_in_subnets_exact_ip if {
    ip_in_subnets("10.0.0.1", {"10.0.0.1"})
}

test_ip_in_subnets_exact_no_match if {
    not ip_in_subnets("10.0.0.2", {"10.0.0.1"})
}

test_ip_in_subnets_multiple if {
    ip_in_subnets("10.0.1.100", {"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"})
}

test_ip_in_subnets_v6_loopback if {
    ip_in_subnets("::1", {"::1/128"})
}

# =============================================================================
# RULE 1: IP SPOOFING
# =============================================================================

test_ip_spoofing_allowed if {
    allow with data.params as ip_spoofing_params with input.packet as {"src_ip": "10.0.1.100"}
}

test_ip_spoofing_blocked if {
    not allow with data.params as ip_spoofing_params with input.packet as {"src_ip": "1.2.3.4"}
}

test_ip_spoofing_deny_reason if {
    deny_reason == "IP spoofing detected" with data.params as ip_spoofing_params with input.packet as {"src_ip": "1.2.3.4"}
}

# =============================================================================
# RULE 2: PORT SCAN
# =============================================================================

test_port_scan_allowed_low_ports if {
    allow with data.params as port_scan_params
        with input.packet as {"tcp_flags": {"syn": true, "ack": false}}
        with input.connection as {"packets_in_flow": 1, "recent_ports": [22, 23]}
}

test_port_scan_blocked_when_exceeds if {
    not allow with data.params as port_scan_params
        with input.packet as {"tcp_flags": {"syn": true, "ack": false}}
        with input.connection as {"packets_in_flow": 1, "recent_ports": [22, 23, 25, 80]}
}

# =============================================================================
# RULE 3: SYN FLOOD
# =============================================================================

test_syn_flood_allowed_low_rate if {
    allow with data.params as syn_flood_params
        with input.packet as {"protocol": "TCP", "tcp_flags": {"syn": true, "ack": false}}
        with input.rate as {"src_ip_pps": 5}
}

test_syn_flood_blocked_high_rate if {
    not allow with data.params as syn_flood_params
        with input.packet as {"protocol": "TCP", "tcp_flags": {"syn": true, "ack": false}}
        with input.rate as {"src_ip_pps": 50}
}

# =============================================================================
# RULE 4: PROTOCOL ANOMALY
# =============================================================================

test_protocol_anomaly_syn_rst if {
    not allow with input.packet as {"protocol": "TCP", "tcp_flags": {"syn": true, "rst": true}}
}

test_protocol_anomaly_fin_rst if {
    not allow with input.packet as {"protocol": "TCP", "tcp_flags": {"fin": true, "rst": true}}
}

test_protocol_anomaly_syn_fin if {
    not allow with input.packet as {"protocol": "TCP", "tcp_flags": {"syn": true, "fin": true}}
}

test_protocol_anomaly_normal_syn if {
    allow with input.packet as {"protocol": "TCP", "tcp_flags": {"syn": true, "ack": false, "rst": false, "fin": false}}
}

# =============================================================================
# RULE 5: INGRESS/EGRESS FILTERING
# =============================================================================

test_ingress_egress_allowed if {
    allow with data.params as ingress_egress_params
        with input.packet as {"src_ip": "10.0.1.100", "dst_ip": "10.0.2.50"}
}

test_ingress_egress_blocked if {
    not allow with data.params as ingress_egress_params
        with input.packet as {"src_ip": "10.0.1.100", "dst_ip": "1.2.3.4"}
}

# =============================================================================
# RULE 6: PORT CONTROL
# =============================================================================

test_port_control_blocked_tcp_22 if {
    not allow with data.params as default_mock
        with input.packet as {"protocol": "TCP", "dst_port": 22}
}

test_port_control_blocked_udp_23 if {
    not allow with data.params as default_mock
        with input.packet as {"protocol": "UDP", "dst_port": 23}
}

test_port_control_blocked_tcp_3389 if {
    not allow with data.params as default_mock
        with input.packet as {"protocol": "TCP", "dst_port": 3389}
}

test_port_control_allowed_https if {
    allow with data.params as default_mock
        with input.packet as {"protocol": "TCP", "dst_port": 443}
}

test_port_control_deny_reason_tcp if {
    allow == false with data.params as default_mock with input.packet as {"protocol": "TCP", "dst_port": 22}
    deny_reason == "blocked port 22 (TCP)" with data.params as default_mock with input.packet as {"protocol": "TCP", "dst_port": 22}
}

test_port_control_deny_reason_udp if {
    allow == false with data.params as default_mock with input.packet as {"protocol": "UDP", "dst_port": 23}
    deny_reason == "blocked port 23 (UDP)" with data.params as default_mock with input.packet as {"protocol": "UDP", "dst_port": 23}
}

# =============================================================================
# RULE 7: ICMP CONTROL
# =============================================================================

test_icmp_control_echo_request_blocked if {
    not allow with data.params as default_mock
        with input.packet as {"protocol": "ICMP", "icmp_type": 8}
}

test_icmp_control_echo_reply_allowed if {
    allow with data.params as default_mock
        with input.packet as {"protocol": "ICMP", "icmp_type": 0}
}

test_icmp_control_deny_reason_type if {
    allow == false with data.params as default_mock with input.packet as {"protocol": "ICMP", "icmp_type": 8, "icmp_code": 0}
    deny_reason == "blocked ICMP type=8 code=0" with data.params as default_mock with input.packet as {"protocol": "ICMP", "icmp_type": 8, "icmp_code": 0}
}

# =============================================================================
# RULE 8: CONNECTION STATE VIOLATION
# =============================================================================

test_state_violation_rst_no_flow if {
    not allow with data.params as stateful_params
        with input.packet as {"protocol": "TCP", "tcp_flags": {"rst": true}}
        with input.connection as {"established": false}
}

test_state_violation_rst_established_ok if {
    allow with data.params as stateful_params
        with input.packet as {"protocol": "TCP", "tcp_flags": {"rst": true}}
        with input.connection as {"established": true}
}

# =============================================================================
# RULE 9: PROTOCOL BLOCKING
# =============================================================================

test_protocol_blocking_icmp_blocked if {
    not allow with data.params as object.union(default_mock, {"blocked_protocols": {"ICMP"}})
        with input.packet as {"protocol": "ICMP"}
}

test_protocol_blocking_tcp_allowed if {
    allow with data.params as object.union(default_mock, {"blocked_protocols": {"ICMP"}})
        with input.packet as {"protocol": "TCP", "dst_port": 443}
}

# =============================================================================
# RULE 10: TRAFFIC RATE LIMIT
# =============================================================================

test_traffic_rate_allowed_low_pps if {
    allow with data.params as default_mock
        with input.rate as {"src_ip_pps": 100}
}

test_traffic_rate_blocked_high_pps if {
    not allow with data.params as default_mock
        with input.rate as {"src_ip_pps": 99999}
}

test_traffic_rate_deny_reason if {
    deny_reason == "rate limit exceeded: 99999 pps"
        with data.params as default_mock
        with input.rate as {"src_ip_pps": 99999}
}

# =============================================================================
# COMBINED: Multiple enabled features
# =============================================================================

test_combined_ssh_blocked_overrides_rate if {
    not allow with data.params as object.union(default_mock, {"enable_ip_spoofing_check": true, "allowed_subnets": {"10.0.0.0/8"}})
        with input.packet as {"src_ip": "10.0.1.100", "protocol": "TCP", "dst_port": 22}
}

# =============================================================================
# RULE 11: FRAGMENT ATTACK
# =============================================================================

test_fragment_attack_nonzero_offset_blocked if {
    not allow with data.params as object.union(default_mock, {"enable_fragment_attack_detection": true})
        with input.packet as {"protocol": "TCP", "dst_port": 80, "fragment": {"is_fragment": true, "offset": 100, "more_fragments": true}}
}

test_fragment_attack_zero_offset_allowed if {
    allow with data.params as object.union(default_mock, {"enable_fragment_attack_detection": true})
        with input.packet as {"protocol": "TCP", "dst_port": 80, "fragment": {"is_fragment": true, "offset": 0, "more_fragments": true}}
}

test_fragment_attack_disabled if {
    allow with data.params as default_mock
        with input.packet as {"protocol": "TCP", "dst_port": 80, "fragment": {"is_fragment": true, "offset": 100, "more_fragments": true}}
}

# =============================================================================
# PORT RANGES
# =============================================================================

test_port_range_single_port_blocked if {
    not allow with data.params as object.union(default_mock, {"blocked_ports": {22, "8000-9000"}})
        with input.packet as {"protocol": "TCP", "dst_port": 22}
}

test_port_range_lower_bound_blocked if {
    not allow with data.params as object.union(default_mock, {"blocked_ports": {22, "8000-9000"}})
        with input.packet as {"protocol": "TCP", "dst_port": 8000}
}

test_port_range_upper_bound_blocked if {
    not allow with data.params as object.union(default_mock, {"blocked_ports": {22, "8000-9000"}})
        with input.packet as {"protocol": "TCP", "dst_port": 9000}
}

test_port_range_midpoint_blocked if {
    not allow with data.params as object.union(default_mock, {"blocked_ports": {22, "8000-9000"}})
        with input.packet as {"protocol": "TCP", "dst_port": 8500}
}

test_port_range_outside_allowed if {
    allow with data.params as object.union(default_mock, {"blocked_ports": {22, "8000-9000"}})
        with input.packet as {"protocol": "TCP", "dst_port": 9090}
}

test_port_range_below_allowed if {
    allow with data.params as object.union(default_mock, {"blocked_ports": {22, "8000-9000"}})
        with input.packet as {"protocol": "TCP", "dst_port": 21}
}

# =============================================================================
# RULE 12: SOURCE PORT FILTERING
# =============================================================================

test_source_port_blocked_tcp if {
    not allow with data.params as object.union(default_mock, {"blocked_ports": {31337}})
        with input.packet as {"protocol": "TCP", "src_port": 31337, "dst_port": 443}
}

test_source_port_allowed_normal if {
    allow with data.params as object.union(default_mock, {"blocked_ports": {31337}})
        with input.packet as {"protocol": "TCP", "src_port": 44001, "dst_port": 443}
}

# =============================================================================
# RULE 13: NEW CONNECTION RATE LIMIT
# =============================================================================

test_new_conn_rate_under_limit if {
    allow with data.params as object.union(default_mock, {"max_new_connections_per_second": 100})
        with input.rate as {"new_conns_per_sec": 50}
}

test_new_conn_rate_over_limit if {
    not allow with data.params as object.union(default_mock, {"max_new_connections_per_second": 100})
        with input.rate as {"new_conns_per_sec": 200}
}

# =============================================================================
# RULE 14: PER-PORT RATE LIMIT
# =============================================================================

test_per_port_rate_under_limit if {
    allow with data.params as object.union(default_mock, {"max_port_pps": 100})
        with input.rate as {"src_port_pps": 50}
        with input.packet as {"protocol": "TCP", "dst_port": 80}
}

test_per_port_rate_over_limit if {
    not allow with data.params as object.union(default_mock, {"max_port_pps": 100})
        with input.rate as {"src_port_pps": 200}
        with input.packet as {"protocol": "TCP", "dst_port": 80}
}
