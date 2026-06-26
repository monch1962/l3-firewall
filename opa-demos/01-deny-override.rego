package demo01

import rego.v1

# =============================================================================
# Demo 01: Deny-Override Model
#
# The core security model of l3-firewall. Traffic passes by default (allow = true)
# and is blocked only by matching deny rules. This is safer than default-deny
# because a misconfigured policy still allows traffic through.
#
# Try it:
#   opa eval --data 01-deny-override.rego --input input_allow.json "data.demo01"
# =============================================================================

# DEFAULT: all traffic allowed
default allow := true

# Deny rules block specific traffic
deny_ssh if {
    input.packet.dst_port == 22
}

# When a deny rule fires, allow becomes false
allow := false if { deny_ssh }

# Provide a human-readable reason for the block
deny_reason := "SSH (port 22) is blocked" if { deny_ssh }
