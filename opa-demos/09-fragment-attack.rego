package demo09

import rego.v1

# =============================================================================
# Demo 09: Fragment Attack Detection
#
# IP fragments can be used to evade network security devices. An attacker can
# split malicious payload across multiple fragments to bypass signature-based
# detection. This rule blocks fragments with non-zero offset, which are often
# used in fragmentation overlap attacks.
#
# The packet parser extracts fragment info from the IPv4 header:
#   is_fragment: true when MF bit set OR offset > 0
#   more_fragments: true when MF bit set
#   offset: fragment offset in 8-byte units
#
# Try it:
#   echo '{"packet":{"protocol":"TCP","fragment":{"is_fragment":true,"offset":100,
#          "more_fragments":true}}}' | opa eval --data 09-fragment-attack.rego \
#     --input-file /dev/stdin "data.demo09"
# =============================================================================

default allow := true

enable_fragment := object.get(data.params, "enable_fragment_attack_detection", false)

deny_fragment if {
    enable_fragment == true
    input.packet.fragment.is_fragment == true
    input.packet.fragment.offset > 0
}

allow := false if { deny_fragment }
deny_reason := sprintf("fragment offset=%v", [input.packet.fragment.offset]) if { deny_fragment }

test_nonzero_offset_blocked if {
    not allow with data.params as {"enable_fragment_attack_detection": true}
        with input.packet as {"protocol": "TCP", "fragment": {"is_fragment": true, "offset": 100, "more_fragments": true}}
}

test_zero_offset_allowed if {
    allow with data.params as {"enable_fragment_attack_detection": true}
        with input.packet as {"protocol": "TCP", "fragment": {"is_fragment": true, "offset": 0, "more_fragments": true}}
}
