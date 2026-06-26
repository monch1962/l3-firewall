package demo03

import rego.v1

# =============================================================================
# Demo 03: Port Scan Detection
#
# Detects rapid connections to many different destination ports from a single
# source IP. The connection tracking module tracks recent destination ports
# per source IP and passes them to OPA via input.connection.recent_ports.
#
# Try it (simulate 20 recent ports):
#   echo '{"packet":{"protocol":"TCP","tcp_flags":{"syn":true,"ack":false}},
#          "connection":{"packets_in_flow":1,"recent_ports":[22,23,25,80,443,
#            8080,3306,5432,6379,27017,587,993,995,8443,9000,9090,10000,11211,
#            27018,27019]}}' | opa eval --data 03-port-scan.rego --input-file /dev/stdin "data.demo03"
# =============================================================================

default allow := true

port_scan_threshold := object.get(data.params, "port_scan_threshold", 20)
enable_port_scan := object.get(data.params, "enable_port_scan_detection", true)

deny_port_scan if {
    enable_port_scan == true
    input.connection.packets_in_flow == 1          # new connection
    input.packet.tcp_flags.syn == true             # SYN packet
    input.packet.tcp_flags.ack == false
    count(input.connection.recent_ports) >= port_scan_threshold
}

allow := false if { deny_port_scan }
deny_reason := "port scan detected" if { deny_port_scan }

test_no_scan if { allow }

test_scan_blocked if {
    not allow with data.params as {"enable_port_scan_detection": true, "port_scan_threshold": 3} with input.packet as {"tcp_flags": {"syn": true, "ack": false}}
        with input.connection as {"packets_in_flow": 1, "recent_ports": [
            22,23,25,80,443,8080,3306,5432,6379,27017,
            587,993,995,8443,9000,9090,10000,11211,27018,27019
        ]}
}
