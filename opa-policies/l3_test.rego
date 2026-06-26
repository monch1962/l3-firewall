package l3_firewall

import rego.v1

# Simulates OPA data.params injection — all checks disabled so traffic passes.
mock_params := {"enable_ip_spoofing_check": false}

test_default_allow if {
	allow with data.params as mock_params
}

test_ip_in_subnets_exact if {
	ip_in_subnets("10.0.0.1", {"10.0.0.1"})
}

test_ip_in_subnets_not_found if {
	not ip_in_subnets("10.0.0.2", {"10.0.0.1"})
}
