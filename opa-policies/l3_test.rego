package l3_firewall

import rego.v1

# =============================================================================
# DEFAULT ALLOW TEST
# =============================================================================

test_default_allow if { allow }

# =============================================================================
# RULE 1: CIDR SUBNET MATCHING
# =============================================================================

test_ip_in_subnets_cidr_match if { ip_in_subnets("10.0.1.100", {"10.0.0.0/8"}) }
test_ip_in_subnets_cidr_no_match if { not ip_in_subnets("10.0.1.100", {"192.168.0.0/16"}) }
test_ip_in_subnets_exact_ip if { ip_in_subnets("10.0.0.1", {"10.0.0.1"}) }
test_ip_in_subnets_exact_no_match if { not ip_in_subnets("10.0.0.2", {"10.0.0.1"}) }
test_ip_in_subnets_multiple if { ip_in_subnets("10.0.1.100", {"192.168.0.0/16", "10.0.0.0/8"}) }
test_ip_in_subnets_v6_loopback if { ip_in_subnets("::1", {"::1/128"}) }

# =============================================================================
# RULE 1: IP SPOOFING
# =============================================================================
# Default allowed_subnets is {"0.0.0.0/0"} which matches everything, so 1.2.3.4 is allowed.
# Override allowed_subnets to test blocking.

test_ip_spoofing_allowed if { allow with input.packet as {"src_ip": "10.0.1.100"} }
test_ip_spoofing_blocked if {
    not allow with allowed_subnets as {"10.0.0.0/8"}
        with input.packet as {"src_ip": "1.2.3.4"}
}
test_ip_spoofing_deny_reason if {
    deny_reason == "IP spoofing detected"
        with allowed_subnets as {"10.0.0.0/8"}
        with input.packet as {"src_ip": "1.2.3.4"}
}

# =============================================================================
# RULE 2: PORT SCAN
# =============================================================================

test_port_scan_allowed_low_ports if {
    allow with input.packet as {"tcp_flags": {"syn": true, "ack": false}}
        with input.connection as {"packets_in_flow": 1, "recent_ports": [22, 23]}
}
test_port_scan_blocked_when_exceeds if {
    not allow with input.packet as {"tcp_flags": {"syn": true, "ack": false}}
        with input.connection as {"packets_in_flow": 1, "recent_ports": [22, 23, 25, 80, 443, 8080, 3306, 5432, 6379, 27017, 587, 993, 995, 8443, 9000, 9090, 10000, 11211, 27018, 27019]}
}

# =============================================================================
# RULE 3: SYN FLOOD
# =============================================================================

test_syn_flood_allowed_low_rate if {
    allow with input.packet as {"protocol": "TCP", "tcp_flags": {"syn": true, "ack": false}}
        with input.rate as {"src_ip_pps": 5}
}
test_syn_flood_blocked_high_rate if {
    not allow with input.packet as {"protocol": "TCP", "tcp_flags": {"syn": true, "ack": false}}
        with input.rate as {"src_ip_pps": 200}
}

# =============================================================================
# RULE 4: PROTOCOL ANOMALY
# =============================================================================

test_protocol_anomaly_syn_rst if { not allow with input.packet as {"protocol": "TCP", "tcp_flags": {"syn": true, "rst": true}} }
test_protocol_anomaly_fin_rst if { not allow with input.packet as {"protocol": "TCP", "tcp_flags": {"fin": true, "rst": true}} }
test_protocol_anomaly_syn_fin if { not allow with input.packet as {"protocol": "TCP", "tcp_flags": {"syn": true, "fin": true}} }
test_protocol_anomaly_normal_syn if { allow with input.packet as {"protocol": "TCP", "tcp_flags": {"syn": true, "ack": false, "rst": false, "fin": false}} }

# =============================================================================
# RULE 5: INGRESS/EGRESS FILTERING
# =============================================================================
# Default allowed_subnets is {"0.0.0.0/0"} which allows everything.
# Override to test blocking.

test_ingress_egress_allowed if {
    allow with input.packet as {"src_ip": "10.0.1.100", "dst_ip": "10.0.2.50"}
}
test_ingress_egress_blocked if {
    not allow with allowed_subnets as {"10.0.0.0/8"}
        with input.packet as {"src_ip": "10.0.1.100", "dst_ip": "1.2.3.4"}
}

# =============================================================================
# RULE 6: PORT CONTROL
# =============================================================================
# Default blocked_ports contains {22, 23, 3389, 5900, 5901}

test_port_control_blocked_tcp_22 if { not allow with input.packet as {"protocol": "TCP", "dst_port": 22} }
test_port_control_blocked_udp_23 if { not allow with input.packet as {"protocol": "UDP", "dst_port": 23} }
test_port_control_blocked_tcp_3389 if { not allow with input.packet as {"protocol": "TCP", "dst_port": 3389} }
test_port_control_allowed_https if { allow with input.packet as {"protocol": "TCP", "dst_port": 443} }

test_port_control_deny_reason_tcp if {
    allow == false with input.packet as {"protocol": "TCP", "dst_port": 22}
    deny_reason == "blocked port 22 (TCP)" with input.packet as {"protocol": "TCP", "dst_port": 22}
}
test_port_control_deny_reason_udp if {
    allow == false with input.packet as {"protocol": "UDP", "dst_port": 23}
    deny_reason == "blocked port 23 (UDP)" with input.packet as {"protocol": "UDP", "dst_port": 23}
}

# =============================================================================
# RULE 7: ICMP CONTROL
# =============================================================================
# Default blocked_icmp_types contains {8}

test_icmp_control_echo_request_blocked if { not allow with input.packet as {"protocol": "ICMP", "icmp_type": 8, "icmp_code": 0} }
test_icmp_control_echo_reply_allowed if { allow with input.packet as {"protocol": "ICMP", "icmp_type": 0, "icmp_code": 0} }
test_icmp_control_deny_reason_type if {
    allow == false with input.packet as {"protocol": "ICMP", "icmp_type": 8, "icmp_code": 0}
    deny_reason == "blocked ICMP type=8 code=0" with input.packet as {"protocol": "ICMP", "icmp_type": 8, "icmp_code": 0}
}

# =============================================================================
# RULE 8: CONNECTION STATE VIOLATION
# =============================================================================

test_state_violation_rst_no_flow if {
    not allow with input.packet as {"protocol": "TCP", "tcp_flags": {"rst": true}}
        with input.connection as {"established": false}
}
test_state_violation_rst_established_ok if {
    allow with input.packet as {"protocol": "TCP", "tcp_flags": {"rst": true}}
        with input.connection as {"established": true}
}

# =============================================================================
# RULE 9: PROTOCOL BLOCKING
# =============================================================================

test_protocol_blocking_icmp_blocked if {
    not allow with blocked_protocols as {"ICMP"}
        with input.packet as {"protocol": "ICMP"}
}
test_protocol_blocking_tcp_allowed if {
    allow with blocked_protocols as {"ICMP"}
        with input.packet as {"protocol": "TCP", "dst_port": 443}
}

# =============================================================================
# RULE 10: TRAFFIC RATE LIMIT
# =============================================================================

test_traffic_rate_allowed_low_pps if { allow with input.rate as {"src_ip_pps": 100} }
test_traffic_rate_blocked_high_pps if { not allow with input.rate as {"src_ip_pps": 99999} }
test_traffic_rate_deny_reason if {
    deny_reason == "rate limit exceeded: 99999 pps" with input.rate as {"src_ip_pps": 99999}
}

# =============================================================================
# RULE 11: FRAGMENT ATTACK
# =============================================================================
# Default enable_fragment is false.

test_fragment_attack_nonzero_offset_blocked if {
    not allow with enable_fragment as true
        with input.packet as {"protocol": "TCP", "dst_port": 80, "fragment": {"is_fragment": true, "offset": 100, "more_fragments": true}}
}
test_fragment_attack_zero_offset_allowed if {
    allow with enable_fragment as true
        with input.packet as {"protocol": "TCP", "dst_port": 80, "fragment": {"is_fragment": true, "offset": 0, "more_fragments": true}}
}
test_fragment_attack_disabled if {
    allow with input.packet as {"protocol": "TCP", "dst_port": 80, "fragment": {"is_fragment": true, "offset": 100, "more_fragments": true}}
}

# =============================================================================
# RULE 11b: UNINSPECTABLE FRAGMENT (RFC 1858 tiny fragment) — R80
# =============================================================================
# internal/packet sets fragment.l4_incomplete when a packet must carry an L4
# header but does not (a first fragment short of its protocol's minimum header
# size). No L4-keyed rule can judge such a packet, while the destination
# reassembles the datagram and processes the segment — so it is denied
# fail-closed, with the reason visible in the log and the deny_reason document.

test_incomplete_fragment_blocked if {
    not allow with input.packet as {
        "protocol": "TCP", "dst_port": 0, "fragment": {
            "is_fragment": true, "offset": 0, "more_fragments": true, "l4_incomplete": true,
        },
    }
}
test_incomplete_fragment_reason if {
    deny_reason == "uninspectable fragment: incomplete L4 header (RFC 1858 tiny fragment)" with input.packet as {
        "protocol": "TCP", "dst_port": 0, "fragment": {
            "is_fragment": true, "offset": 0, "more_fragments": true, "l4_incomplete": true,
        },
    }
}
# A first fragment carrying its COMPLETE L4 header is judged by the ordinary
# port rules instead: it must NOT be dropped by the incompleteness rule, and a
# benign port has to stay allowed (legitimate fragmented traffic keeps working).
test_complete_header_fragment_not_marked_incomplete if {
    allow with input.packet as {
        "protocol": "TCP", "dst_port": 443, "fragment": {
            "is_fragment": true, "offset": 0, "more_fragments": true, "l4_incomplete": false,
        },
    }
}
test_complete_header_fragment_blocked_port_still_denied if {
    not allow with input.packet as {
        "protocol": "TCP", "dst_port": 22, "fragment": {
            "is_fragment": true, "offset": 0, "more_fragments": true, "l4_incomplete": false,
        },
    }
}
# A continuation fragment (offset > 0) is never marked incomplete: the header
# is judged in the datagram's first fragment.
test_continuation_fragment_not_blocked_by_incompleteness_rule if {
    allow with input.packet as {
        "protocol": "TCP", "dst_port": 443, "fragment": {
            "is_fragment": true, "offset": 5, "more_fragments": false, "l4_incomplete": false,
        },
    }
}
# Absent field (pre-R80 input shape) must not change any existing decision.
test_incomplete_fragment_absent_field_allows if {
    allow with input.packet as {
        "protocol": "TCP", "dst_port": 443, "fragment": {"is_fragment": true, "offset": 0, "more_fragments": true},
    }
}

# =============================================================================
# PORT RANGES
# =============================================================================

test_port_range_single_port_blocked if {
    not allow with blocked_ports as {22, "8000-9000"}
        with input.packet as {"protocol": "TCP", "dst_port": 22}
}
test_port_range_lower_bound_blocked if {
    not allow with blocked_ports as {22, "8000-9000"}
        with input.packet as {"protocol": "TCP", "dst_port": 8000}
}
test_port_range_upper_bound_blocked if {
    not allow with blocked_ports as {22, "8000-9000"}
        with input.packet as {"protocol": "TCP", "dst_port": 9000}
}
test_port_range_midpoint_blocked if {
    not allow with blocked_ports as {22, "8000-9000"}
        with input.packet as {"protocol": "TCP", "dst_port": 8500}
}
test_port_range_outside_allowed if {
    allow with blocked_ports as {22, "8000-9000"}
        with input.packet as {"protocol": "TCP", "dst_port": 9090}
}
test_port_range_below_allowed if {
    allow with blocked_ports as {22, "8000-9000"}
        with input.packet as {"protocol": "TCP", "dst_port": 21}
}

# =============================================================================
# RULE 12: SOURCE PORT FILTERING
# =============================================================================

test_source_port_blocked_tcp if {
    not allow with blocked_ports as {31337}
        with input.packet as {"protocol": "TCP", "src_port": 31337, "dst_port": 443}
}
test_source_port_allowed_normal if {
    allow with blocked_ports as {31337}
        with input.packet as {"protocol": "TCP", "src_port": 44001, "dst_port": 443}
}

# =============================================================================
# RULE 13: NEW CONNECTION RATE LIMIT
# =============================================================================

test_new_conn_rate_under_limit if { allow with input.rate as {"new_conns_per_sec": 50} }
test_new_conn_rate_over_limit if { not allow with input.rate as {"new_conns_per_sec": 2000} }

# =============================================================================
# RULE 14: PER-PORT RATE LIMIT
# =============================================================================

test_per_port_rate_under_limit if {
    allow with input.rate as {"src_port_pps": 50}
        with input.packet as {"protocol": "TCP", "dst_port": 80}
}
test_per_port_rate_over_limit if {
    not allow with input.rate as {"src_port_pps": 1000}
        with input.packet as {"protocol": "TCP", "dst_port": 80}
}

# =============================================================================
# COMBINED TESTS
# =============================================================================

test_combined_ssh_blocked if {
    not allow with input.packet as {"src_ip": "10.0.1.100", "protocol": "TCP", "dst_port": 22}
}

# =============================================================================
# RULE 15: TIME-BASED ACCESS CONTROL
# =============================================================================
# All tests override blocked_ports to {} to isolate from port control rules.

test_time_based_default_empty_rules_no_block if {
    allow with blocked_ports as {}
        with input.packet as {"protocol": "TCP", "dst_port": 22}
        with input.time as {"utc_hour": 3, "utc_day": 3}
}

test_time_based_deny_within_window if {
    not allow with time_based_rules as [{"ports": {22}, "days": {3}, "start_hour": 0, "end_hour": 23, "effect": "deny"}]
        with blocked_ports as {}
        with input.packet as {"protocol": "TCP", "dst_port": 22}
        with input.time as {"utc_hour": 14, "utc_day": 3}
}

test_time_based_deny_outside_window if {
    allow with time_based_rules as [{"ports": {22}, "days": {3}, "start_hour": 9, "end_hour": 17, "effect": "deny"}]
        with blocked_ports as {}
        with input.packet as {"protocol": "TCP", "dst_port": 22}
        with input.time as {"utc_hour": 20, "utc_day": 3}
}

test_time_based_deny_wrong_day_allowed if {
    allow with time_based_rules as [{"ports": {22}, "days": {1}, "start_hour": 0, "end_hour": 23, "effect": "deny"}]
        with blocked_ports as {}
        with input.packet as {"protocol": "TCP", "dst_port": 22}
        with input.time as {"utc_hour": 14, "utc_day": 3}
}

test_time_based_deny_wrong_port_allowed if {
    allow with time_based_rules as [{"ports": {22}, "days": {3}, "start_hour": 0, "end_hour": 23, "effect": "deny"}]
        with blocked_ports as {}
        with input.packet as {"protocol": "TCP", "dst_port": 443}
        with input.time as {"utc_hour": 14, "utc_day": 3}
}

test_time_based_deny_reason if {
    deny_reason == "time-based block: port=22 during restricted hours (UTC 0:00-23:00)"
        with time_based_rules as [{"ports": {22}, "days": {3}, "start_hour": 0, "end_hour": 23, "effect": "deny"}]
        with blocked_ports as {}
        with input.packet as {"protocol": "TCP", "dst_port": 22}
        with input.time as {"utc_hour": 14, "utc_day": 3}
}

test_time_based_allow_within_window if {
    allow with time_based_rules as [{"ports": {443}, "days": {3}, "start_hour": 9, "end_hour": 17, "effect": "allow"}]
        with blocked_ports as {}
        with input.packet as {"protocol": "TCP", "dst_port": 443}
        with input.time as {"utc_hour": 12, "utc_day": 3}
}

test_time_based_allow_outside_window_blocked if {
    not allow with time_based_rules as [{"ports": {443}, "days": {3}, "start_hour": 9, "end_hour": 17, "effect": "allow"}]
        with blocked_ports as {}
        with input.packet as {"protocol": "TCP", "dst_port": 443}
        with input.time as {"utc_hour": 20, "utc_day": 3}
}

test_time_based_allow_reason_outside_window if {
    deny_reason == "time-based block outside window: port=443 (only allowed UTC 9:00-17:00)"
        with time_based_rules as [{"ports": {443}, "days": {3}, "start_hour": 9, "end_hour": 17, "effect": "allow"}]
        with blocked_ports as {}
        with input.packet as {"protocol": "TCP", "dst_port": 443}
        with input.time as {"utc_hour": 20, "utc_day": 3}
}

test_time_based_deny_all_days_empty_set if {
    not allow with time_based_rules as [{"ports": {22}, "days": {}, "start_hour": 0, "end_hour": 23, "effect": "deny"}]
        with blocked_ports as {}
        with input.packet as {"protocol": "TCP", "dst_port": 22}
        with input.time as {"utc_hour": 14, "utc_day": 0}
}

test_time_based_deny_multiple_ports if {
    not allow with time_based_rules as [{"ports": {22, 23, 3389}, "days": {3}, "start_hour": 0, "end_hour": 23, "effect": "deny"}]
        with blocked_ports as {}
        with input.packet as {"protocol": "TCP", "dst_port": 23}
        with input.time as {"utc_hour": 14, "utc_day": 3}
}

test_time_based_deny_start_hour_edge_case if {
    not allow with time_based_rules as [{"ports": {22}, "days": {3}, "start_hour": 9, "end_hour": 17, "effect": "deny"}]
        with blocked_ports as {}
        with input.packet as {"protocol": "TCP", "dst_port": 22}
        with input.time as {"utc_hour": 9, "utc_day": 3}
}

test_time_based_deny_end_hour_edge_case if {
    allow with time_based_rules as [{"ports": {22}, "days": {3}, "start_hour": 9, "end_hour": 17, "effect": "deny"}]
        with blocked_ports as {}
        with input.packet as {"protocol": "TCP", "dst_port": 22}
        with input.time as {"utc_hour": 17, "utc_day": 3}
}

# =============================================================================
# RULE 16: GEOIP COUNTRY BLOCKING
# =============================================================================

test_geoip_blocked_src_default_kp if {
    not allow with input.geo as {"src_country": "KP", "dst_country": ""}
}

test_geoip_blocked_src_override_empty if {
    allow with blocked_src_countries as {}
        with input.geo as {"src_country": "KP", "dst_country": ""}
}

test_geoip_blocked_src_us_allowed if {
    allow with input.geo as {"src_country": "US", "dst_country": ""}
}

test_geoip_allowed_src_list_blocked if {
    not allow with allowed_src_countries as {"US", "CA"}
        with input.geo as {"src_country": "CN", "dst_country": ""}
}

test_geoip_allowed_src_list_allowed if {
    allow with allowed_src_countries as {"US", "CA"}
        with input.geo as {"src_country": "US", "dst_country": ""}
}

test_geoip_allowed_src_empty_not_blocked if {
    allow with allowed_src_countries as {"US", "CA"}
        with input.geo as {"src_country": "", "dst_country": ""}
}

test_geoip_allowed_dst_list_blocked if {
    not allow with allowed_dst_countries as {"US"}
        with input.geo as {"src_country": "", "dst_country": "CN"}
}

test_geoip_allowed_dst_list_allowed if {
    allow with allowed_dst_countries as {"US"}
        with input.geo as {"src_country": "", "dst_country": "US"}
}

test_geoip_blocked_src_reason if {
    deny_reason == "blocked source country: KP"
        with input.geo as {"src_country": "KP", "dst_country": ""}
}

test_geoip_allowed_src_reason if {
    deny_reason == "source country CN not in allowed list"
        with allowed_src_countries as {"US", "CA"}
        with input.geo as {"src_country": "CN", "dst_country": ""}
}

test_geoip_allowed_dst_reason if {
    deny_reason == "destination country CN not in allowed list"
        with allowed_dst_countries as {"US"}
        with input.geo as {"src_country": "", "dst_country": "CN"}
}

# =============================================================================
# R78: OVERLAPPING DENY RULES MUST NOT CONFLICT
# =============================================================================
# Several deny rules can match the same packet. deny_reasons is a partial set
# so all of them may contribute and the decision document still evaluates.
# Spelling them as repeated complete rules (`deny_reason := "..." if {...}`)
# makes OPA raise `eval_conflict_error: complete rules must not produce
# multiple outputs` for the WHOLE data.l3_firewall document as soon as two
# bodies are true — and the engine's default (non-fail-closed) error path
# turned that into an ALLOW, i.e. a two-rule packet bypassed every deny rule.
# These tests pin the conflict-free behavior for the overlapping cases an
# attacker can craft.

# Stealth probe: blocked port 22 AND invalid SYN+RST flags.
test_overlapping_blocked_port_and_anomaly_denies if {
    allow == false with input.packet as {"protocol": "TCP", "dst_port": 22, "tcp_flags": {"syn": true, "rst": true}}
}

test_overlapping_blocked_port_and_anomaly_both_reasons_match if {
    count(deny_reasons) == 2 with input.packet as {"protocol": "TCP", "dst_port": 22, "tcp_flags": {"syn": true, "rst": true}}
}

test_overlapping_blocked_port_and_anomaly_reason_is_single_string if {
    reason == "blocked port 22 (TCP)" with input.packet as {"protocol": "TCP", "dst_port": 22, "tcp_flags": {"syn": true, "rst": true}}
}

# Fast SYN scan: port-scan AND SYN-flood thresholds crossed by the same packet.
test_overlapping_port_scan_and_syn_flood_denies if {
    allow == false
        with input.packet as {"protocol": "TCP", "dst_port": 443, "tcp_flags": {"syn": true, "ack": false}}
        with input.connection as {"packets_in_flow": 1, "recent_ports": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]}
        with input.rate as {"src_ip_pps": 500}
}

test_overlapping_port_scan_and_syn_flood_reason_is_deterministic if {
    # sort() picks the lexicographically first matched reason ("SYN ..." < "port ...").
    reason == "SYN flood detected"
        with input.packet as {"protocol": "TCP", "dst_port": 443, "tcp_flags": {"syn": true, "ack": false}}
        with input.connection as {"packets_in_flow": 1, "recent_ports": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]}
        with input.rate as {"src_ip_pps": 500}
}

# ICMP echo flood: denied type 8 AND the ICMP flood rate threshold.
test_overlapping_icmp_type_and_flood_denies if {
    allow == false
        with input.packet as {"protocol": "ICMP", "icmp_type": 8, "icmp_code": 0}
        with input.rate as {"src_ip_pps": 50}
}

test_overlapping_icmp_type_and_flood_both_reasons_match if {
    count(deny_reasons) == 2
        with input.packet as {"protocol": "ICMP", "icmp_type": 8, "icmp_code": 0}
        with input.rate as {"src_ip_pps": 50}
}

# No deny rule matches: the partial set is empty and reason is undefined
# (the engine leaves its Reason field empty), never an error.
test_no_deny_rule_means_no_reason if {
    allow
    not deny_reason
        with input.packet as {"protocol": "TCP", "dst_port": 443, "tcp_flags": {"syn": true, "ack": false}}
}

# =============================================================================
# R79: IPv6 ADDRESS-FAMILY COVERAGE
# =============================================================================
# allowed_subnets defaulted to {"0.0.0.0/0"} — an IPv4-only wildcard.
# net.cidr_contains() is family-strict, so no IPv6 address is ever contained in
# an IPv4 CIDR: ip_in_subnets("2001:db8::1", {"0.0.0.0/0"}) is false. RULE 1
# (deny_ip_spoofing) and RULE 5 (deny_ingress_egress) are both enabled by
# default and both fire on that false, so EVERY IPv6 packet — benign TCP, UDP,
# ICMPv6, the lot — was denied with deny_reason == "IP spoofing detected".
# The deny-override model's documented contract ("traffic passes by default")
# was violated for an entire address family, and internal/packet parses IPv6
# (including extension headers), so the firewall silently dropped 100% of IPv6
# traffic in its shipped configuration.
#
# The default allowlist must therefore carry a wildcard for BOTH families.
# The helper itself is NOT made family-tolerant on purpose: an operator who
# configures a v4-only allowlist is keeping IPv6 fail-CLOSED (unlisted family
# = denied), which is the safe reading of an explicit restriction. Only the
# shipped default — whose intent is "allow everything" — was wrong.

test_ip_in_subnets_v6_wildcard if { ip_in_subnets("2001:db8::1", {"::/0"}) }

# A benign IPv6 packet must pass with the shipped default configuration.
test_default_allows_benign_ipv6_tcp if {
    allow with input.packet as {"protocol": "TCP", "src_ip": "2001:db8::1", "dst_ip": "2001:db8::2", "dst_port": 80, "tcp_flags": {"syn": true, "ack": false}}
}
test_default_allows_benign_ipv6_udp if {
    allow with input.packet as {"protocol": "UDP", "src_ip": "2001:db8::1", "dst_ip": "2001:db8::2", "dst_port": 53}
}
test_default_allows_benign_ipv6_icmpv6 if {
    allow with input.packet as {"protocol": "ICMPv6", "src_ip": "2001:db8::1", "dst_ip": "2001:db8::2", "icmp_type": 128, "icmp_code": 0}
}
test_default_ipv6_traffic_produces_no_deny_reason if {
    allow
    not deny_reason
        with input.packet as {"protocol": "TCP", "src_ip": "2001:db8::1", "dst_ip": "2001:db8::2", "dst_port": 80, "tcp_flags": {"syn": true, "ack": false}}
}

# The R79 fix must not blind the deny rules that DO apply to IPv6: a SYN to a
# blocked port from an IPv6 source is still denied — and now for the right
# reason (pre-fix the packet was denied as "IP spoofing detected", which masked
# the port rule entirely).
test_ipv6_blocked_port_denied_for_the_port_reason if {
    allow == false
        with input.packet as {"protocol": "TCP", "src_ip": "2001:db8::1", "dst_ip": "2001:db8::2", "dst_port": 22, "tcp_flags": {"syn": true, "ack": false}}
    deny_reason == "blocked port 22 (TCP)"
        with input.packet as {"protocol": "TCP", "src_ip": "2001:db8::1", "dst_ip": "2001:db8::2", "dst_port": 22, "tcp_flags": {"syn": true, "ack": false}}
}
test_ipv6_udp_blocked_port_denied if {
    allow == false
        with input.packet as {"protocol": "UDP", "src_ip": "2001:db8::1", "dst_ip": "2001:db8::2", "dst_port": 3389}
}

# An IPv6 allowlist still enforces IPv6 source authorization (anti-spoofing on
# the v6 side, the RULE 1 contract applied to a v6 prefix).
test_ipv6_source_outside_v6_allowlist_denied if {
    allow == false
        with allowed_subnets as {"2001:db8::/32"}
        with input.packet as {"protocol": "TCP", "src_ip": "2001:dead::1", "dst_ip": "2001:db8::2", "dst_port": 80, "tcp_flags": {"syn": true, "ack": false}}
}
test_ipv6_source_inside_v6_allowlist_allowed if {
    allow
        with allowed_subnets as {"2001:db8::/32"}
        with input.packet as {"protocol": "TCP", "src_ip": "2001:db8::9", "dst_ip": "2001:db8::2", "dst_port": 80, "tcp_flags": {"syn": true, "ack": false}}
}

# A v4-only operator allowlist keeps IPv6 fail-closed (documented semantics —
# the helper is deliberately family-strict, only the shipped default changed).
test_v4_only_allowlist_keeps_ipv6_denied if {
    not allow
        with allowed_subnets as {"10.0.0.0/8"}
        with input.packet as {"protocol": "TCP", "src_ip": "2001:db8::1", "dst_ip": "2001:db8::2", "dst_port": 80, "tcp_flags": {"syn": true, "ack": false}}
}

# Regression: the IPv4 default path is unchanged.
test_default_allows_benign_ipv4_tcp if {
    allow with input.packet as {"protocol": "TCP", "src_ip": "10.0.1.100", "dst_ip": "10.0.2.50", "dst_port": 80, "tcp_flags": {"syn": true, "ack": false}}
}
test_default_allows_benign_ipv4_udp if {
    allow with input.packet as {"protocol": "UDP", "src_ip": "10.0.1.100", "dst_ip": "10.0.2.50", "dst_port": 53}
}
test_ipv4_blocked_port_still_denied if {
    allow == false with input.packet as {"protocol": "TCP", "src_ip": "10.0.1.100", "dst_ip": "10.0.2.50", "dst_port": 22, "tcp_flags": {"syn": true, "ack": false}}
}
