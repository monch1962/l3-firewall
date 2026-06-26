package opa

import (
	"github.com/monch1962/l3-firewall/internal/packet"
)

// PacketInfo mirrors the packet fields fed into OPA evaluation.
type PacketInfo struct {
	SrcIP      string   `json:"src_ip"`
	DstIP      string   `json:"dst_ip"`
	Protocol   string   `json:"protocol"`
	SrcPort    uint16   `json:"src_port"`
	DstPort    uint16   `json:"dst_port"`
	TCPFlags   TCPFlags `json:"tcp_flags"`
	ICMPType   *uint8   `json:"icmp_type"`
	ICMPCode   *uint8   `json:"icmp_code"`
	PacketSize int      `json:"packet_size"`
}

// TCPFlags mirrors the TCP control flags for OPA input.
type TCPFlags struct {
	SYN bool `json:"syn"`
	ACK bool `json:"ack"`
	RST bool `json:"rst"`
	FIN bool `json:"fin"`
}

// ConnectionInfo holds connection tracking state for OPA input.
type ConnectionInfo struct {
	Established  bool     `json:"established"`
	PacketsInFlow int64   `json:"packets_in_flow"`
	AgeMs        int64    `json:"age_ms"`
	RecentPorts  []uint16 `json:"recent_ports"`
}

// RateInfo holds per-source rate tracking for OPA input.
type RateInfo struct {
	SrcIPpps float64 `json:"src_ip_pps"`
	SrcIPbps float64 `json:"src_ip_bps"`
}

// Input is the complete OPA input document.
type Input struct {
	Packet     PacketInfo     `json:"packet"`
	Connection ConnectionInfo `json:"connection"`
	Rate       RateInfo       `json:"rate"`
}

// BuildInput constructs the OPA input from parsed packet info, rate data,
// connection state, and recent destination ports for port-scan detection.
func BuildInput(pi *packet.PacketInfo, pps, bps float64, established bool, recentPorts []uint16) *Input {
	input := &Input{
		Packet: PacketInfo{
			SrcIP:      pi.SrcIP,
			DstIP:      pi.DstIP,
			Protocol:   pi.Protocol,
			SrcPort:    pi.SrcPort,
			DstPort:    pi.DstPort,
			TCPFlags:   TCPFlags(pi.TCPFlags),
			ICMPType:   pi.ICMPType,
			ICMPCode:   pi.ICMPCode,
			PacketSize: pi.PacketSize,
		},
		Connection: ConnectionInfo{
			Established:  established,
			PacketsInFlow: 1,
		},
		Rate: RateInfo{
			SrcIPpps: pps,
			SrcIPbps: bps,
		},
	}

	if len(recentPorts) > 0 {
		input.Connection.RecentPorts = make([]uint16, len(recentPorts))
		copy(input.Connection.RecentPorts, recentPorts)
	}

	return input
}
