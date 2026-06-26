package opa

import (
	"github.com/monch1962/l3-firewall/internal/packet"
)

// PacketInfo mirrors the packet fields fed into OPA evaluation.
// Uses packet.TCPFlags and packet.FragmentInfo directly (DRY — avoids duplicating
// identical type definitions from the packet package).
type PacketInfo struct {
	SrcIP      string             `json:"src_ip"`
	DstIP      string             `json:"dst_ip"`
	Protocol   string             `json:"protocol"`
	SrcPort    uint16             `json:"src_port"`
	DstPort    uint16             `json:"dst_port"`
	TCPFlags   packet.TCPFlags    `json:"tcp_flags"`
	ICMPType   *uint8             `json:"icmp_type"`
	ICMPCode   *uint8             `json:"icmp_code"`
	Fragment   packet.FragmentInfo `json:"fragment"`
	PacketSize int                `json:"packet_size"`
}

// ConnectionInfo holds connection tracking state for OPA input.
type ConnectionInfo struct {
	Established   bool     `json:"established"`
	TCPState      string   `json:"tcp_state"`
	PacketsInFlow int64    `json:"packets_in_flow"`
	AgeMs         int64    `json:"age_ms"`
	RecentPorts   []uint16 `json:"recent_ports"`
}

// RateInfo holds per-source rate tracking for OPA input.
type RateInfo struct {
	SrcIPpps      float64 `json:"src_ip_pps"`
	SrcIPbps      float64 `json:"src_ip_bps"`
	SrcPortPPS    float64 `json:"src_port_pps"`     // PPS to a specific destination port
	SrcPortBPS    float64 `json:"src_port_bps"`     // BPS to a specific destination port
	NewConnsPerSec float64 `json:"new_conns_per_sec"` // New connections/sec from this source
}

// Input is the complete OPA input document.
type Input struct {
	Packet     PacketInfo     `json:"packet"`
	Connection ConnectionInfo `json:"connection"`
	Rate       RateInfo       `json:"rate"`
}

// BuildInput constructs the OPA input from parsed packet info, rate data,
// connection state, TCP state string, per-port rate, new connection rate,
// and recent destination ports for port-scan detection.
func BuildInput(pi *packet.PacketInfo, pps, bps float64, established bool, tcpState string,
	portPPS, portBPS, newConnRate float64, recentPorts []uint16) *Input {
	input := &Input{
		Packet: PacketInfo{
			SrcIP:      pi.SrcIP,
			DstIP:      pi.DstIP,
			Protocol:   pi.Protocol,
			SrcPort:    pi.SrcPort,
			DstPort:    pi.DstPort,
			TCPFlags:   pi.TCPFlags,
			ICMPType:   pi.ICMPType,
			ICMPCode:   pi.ICMPCode,
			Fragment:   pi.Fragment,
			PacketSize: pi.PacketSize,
		},
		Connection: ConnectionInfo{
			Established:  established,
			TCPState:     tcpState,
			PacketsInFlow: 1,
		},
		Rate: RateInfo{
			SrcIPpps:      pps,
			SrcIPbps:      bps,
			SrcPortPPS:    portPPS,
			SrcPortBPS:    portBPS,
			NewConnsPerSec: newConnRate,
		},
	}

	if len(recentPorts) > 0 {
		input.Connection.RecentPorts = make([]uint16, len(recentPorts))
		copy(input.Connection.RecentPorts, recentPorts)
	}

	return input
}
