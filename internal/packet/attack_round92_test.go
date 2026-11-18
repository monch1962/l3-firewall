package packet

import (
	"encoding/binary"
	"testing"
)

// ── R92.1: AH (IPsec Authentication Header) hides the L4 header ──────────────
//
// R79 taught the parser to follow the four RFC 8200 extension headers it
// enumerated (HopByHop, Routing, Fragment, Destination Options) from the RAW
// bytes, and R80 gave IPv4 the same raw-bytes L4 reader. Both rounds keyed the
// walk on `extHeaderTypes`, and AH (protocol 51) is not in that map — so the
// walk TERMINATES at AH and reports it as the L4 protocol:
//
//	IPv6 → AH(next=6) → TCP SYN dport 22  ⇒  protocol "IP-51", ports 0,
//	                                          all flags false, l4_incomplete false
//
// AH is NOT encryption: the TCP/UDP header behind it is in the clear, and a
// destination holding the SA strips the 8-44 byte AH and delivers the unchanged
// segment. One attacker-prepended AH therefore makes every L4-keyed deny rule
// (blocked_ports, source-port filtering, SYN flood, port scan, protocol
// anomaly, state violation, per-port rate) inert — the R79.2/R80 class, one
// header shape over. AH has its OWN length formula (RFC 4302 §2.2: the Payload
// Len field counts 32-bit words *minus 2*), so it cannot be handled by the
// generic `(Hdr Ext Len + 1) * 8` used for the other extension headers.

const (
	// Extension-header protocol numbers with no gopacket constant. The
	// production parser declares these too (parser.go protoMobility etc.);
	// the test always refers to them through the shared names, so a drift in
	// the walked set fails this test rather than passing silently.
	r92Mobility = byte(protoMobility)
	r92HIP      = byte(protoHIP)
	r92Shim6    = byte(protoShim6)
)

var r92Src = []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
var r92Dst = []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

// r92TCP returns a 20-byte TCP header.
func r92TCP(dstPort uint16) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:2], 40000)
	binary.BigEndian.PutUint16(h[2:4], dstPort)
	h[12] = 0x50 // data offset 5
	h[13] = 0x02 // SYN
	return h
}

// r92UDP returns an 8-byte UDP header.
func r92UDP(dstPort uint16) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:2], 40000)
	binary.BigEndian.PutUint16(h[2:4], dstPort)
	binary.BigEndian.PutUint16(h[4:6], 8)
	return h
}

// r92AH returns an AH header whose total length is (payloadLen+2)*4 bytes,
// with 4 bytes of fixed fields + the remainder as ICV so the declared size is
// real bytes on the wire.
func r92AH(next byte, payloadLen byte) []byte {
	total := (int(payloadLen) + 2) * 4
	h := make([]byte, total)
	h[0] = next
	h[1] = payloadLen
	binary.BigEndian.PutUint32(h[4:8], 0x1000) // SPI
	binary.BigEndian.PutUint32(h[8:12], 1)     // Sequence
	return h
}

// r92Ext returns a generic extension header whose total length is
// (hdrExtLen+1)*8 bytes (HopByHop / Routing / DestOpt / Mobility / HIP / Shim6).
func r92Ext(next, hdrExtLen byte) []byte {
	total := (int(hdrExtLen) + 1) * 8
	h := make([]byte, total)
	h[0] = next
	h[1] = hdrExtLen
	return h
}

// r92IPv6 wraps payload in an IPv6 header with the given next header.
func r92IPv6(next byte, payload []byte) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(payload)))
	pkt[6] = next
	pkt[7] = 64
	copy(pkt[8:24], r92Src)
	copy(pkt[24:40], r92Dst)
	return append(pkt, payload...)
}

// r92IPv4 wraps payload in a 20-byte IPv4 header with the given protocol.
func r92IPv4(proto byte, payload []byte) []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(20+len(payload)))
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:16], []byte{203, 0, 113, 9})
	copy(pkt[16:20], []byte{198, 51, 100, 7})
	return append(pkt, payload...)
}

func r92Cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// TestAttack_AuthHeaderHidesL4Header proves the bypass at the parser layer: the
// L4 header behind an AH (or another length-bearing extension header R79's map
// omitted) must be read, exactly as R79 reads it behind HopByHop/Routing/DestOpt.
func TestAttack_AuthHeaderHidesL4Header(t *testing.T) {
	cases := []struct {
		name      string
		raw       []byte
		wantProto string
		wantDst   uint16
		wantSYN   bool
	}{
		{
			"ipv6_ah_tcp_22",
			r92IPv6(51, r92Cat(r92AH(6, 1), r92TCP(22))),
			"TCP", 22, true,
		},
		{
			// Payload Len 3 => 20-byte AH (8-byte ICV). Discriminates the AH
			// formula (len+2)*4 = 20 from the generic (len+1)*8 = 32: with the
			// wrong formula the reader lands 12 bytes into the TCP header and
			// reports ports 0 or garbage.
			"ipv6_ah_with_icv_tcp_23",
			r92IPv6(51, r92Cat(r92AH(6, 3), r92TCP(23))),
			"TCP", 23, true,
		},
		{
			"ipv6_hopbyhop_then_ah_tcp_3389",
			r92IPv6(0, r92Cat(r92Ext(51, 0), r92AH(6, 1), r92TCP(3389))),
			"TCP", 3389, true,
		},
		{
			"ipv6_ah_then_udp_3389",
			r92IPv6(51, r92Cat(r92AH(17, 1), r92UDP(3389))),
			"UDP", 3389, false,
		},
		{
			"ipv4_ah_tcp_22",
			r92IPv4(51, r92Cat(r92AH(6, 1), r92TCP(22))),
			"TCP", 22, true,
		},
		{
			"ipv6_mobility_tcp_22",
			r92IPv6(r92Mobility, r92Cat(r92Ext(6, 0), r92TCP(22))),
			"TCP", 22, true,
		},
		{
			"ipv6_hip_tcp_22",
			r92IPv6(r92HIP, r92Cat(r92Ext(6, 0), r92TCP(22))),
			"TCP", 22, true,
		},
		{
			"ipv6_shim6_tcp_22",
			r92IPv6(r92Shim6, r92Cat(r92Ext(6, 0), r92TCP(22))),
			"TCP", 22, true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pi, err := ParsePacket(tc.raw)
			if err != nil {
				t.Fatalf("ParsePacket: %v", err)
			}
			if pi.Protocol != tc.wantProto {
				t.Errorf("protocol = %q, want %q — the length-bearing header hid the L4 "+
					"protocol from the parser, so every L4-keyed policy rule is inert for "+
					"this packet while the destination processes the unchanged segment",
					pi.Protocol, tc.wantProto)
			}
			if pi.DstPort != tc.wantDst {
				t.Errorf("dst_port = %d, want %d (ports read from the wrong offset?)",
					pi.DstPort, tc.wantDst)
			}
			if pi.TCPFlags.SYN != tc.wantSYN {
				t.Errorf("syn = %v, want %v", pi.TCPFlags.SYN, tc.wantSYN)
			}
		})
	}
}

// TestAttack_TruncatedAuthHeaderIsNotFabricated pins the honest-reporting
// contract for a malformed AH: no panic, no invented ports.
//
//   - AH present but its declared next protocol has no bytes after it: the L4
//     header the AH promises is NOT on the wire ⇒ L4Incomplete must be set so
//     RULE 11b fails closed (the R80 contract).
//   - the AH header itself is truncated: protocol name only, no L4 fields.
func TestAttack_TruncatedAuthHeaderIsNotFabricated(t *testing.T) {
	t.Run("ah_promises_tcp_but_packet_ends", func(t *testing.T) {
		pi, err := ParsePacket(r92IPv6(51, r92AH(6, 1)))
		if err != nil {
			t.Fatalf("ParsePacket: %v", err)
		}
		if pi.SrcPort != 0 || pi.DstPort != 0 {
			t.Errorf("fabricated ports %d/%d from bytes that are not a TCP header",
				pi.SrcPort, pi.DstPort)
		}
		if !pi.Fragment.L4Incomplete {
			t.Errorf("l4_incomplete = false for an AH that declares TCP with no TCP "+
				"header on the wire (protocol %q): RULE 11b cannot fail closed on it",
				pi.Protocol)
		}
	})

	t.Run("ah_header_itself_truncated", func(t *testing.T) {
		// One byte of AH payload: next-header is readable, length is not.
		pi, err := ParsePacket(r92IPv6(51, []byte{6}))
		if err != nil {
			t.Fatalf("ParsePacket: %v", err)
		}
		if pi.SrcPort != 0 || pi.DstPort != 0 || pi.TCPFlags.SYN {
			t.Errorf("fabricated L4 fields from a truncated AH: proto=%q ports=%d/%d syn=%v",
				pi.Protocol, pi.SrcPort, pi.DstPort, pi.TCPFlags.SYN)
		}
	})

	t.Run("ah_declares_length_beyond_packet", func(t *testing.T) {
		// AH payload len 40 => 168 bytes declared, but only 12 are on the wire.
		ah := r92AH(6, 40)
		truncated := ah[:12]
		pi, err := ParsePacket(r92IPv6(51, truncated))
		if err != nil {
			t.Fatalf("ParsePacket: %v", err)
		}
		if pi.DstPort != 0 {
			t.Errorf("dst_port = %d read from past the end of the packet", pi.DstPort)
		}
	})
}

// TestAttack_EncapsulatedProtocolsAreNameableByPolicy documents and pins the
// remaining blind spot: a header that NULLS the L4 layer without a walkable
// length field (ESP is encrypted; IPIP/GRE/EtherIP carry an inner packet) is
// reported as "IP-<n>", which is exactly what RULE 9's blocked_protocols
// matches. The control exists — this test exists so a future change cannot
// silently rename these to something an operator's blocklist does not cover.
func TestAttack_EncapsulatedProtocolsAreNameableByPolicy(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{"esp", r92IPv6(50, make([]byte, 16)), "IP-50"},
		{"ipv4_in_ipv6", r92IPv6(41, r92IPv4(6, r92TCP(22))), "IP-41"},
		{"gre", r92IPv6(47, make([]byte, 16)), "IP-47"},
		{"ipip", r92IPv4(4, r92IPv4(6, r92TCP(22))), "IP-4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pi, err := ParsePacket(tc.raw)
			if err != nil {
				t.Fatalf("ParsePacket: %v", err)
			}
			if pi.Protocol != tc.want {
				t.Errorf("protocol = %q, want %q (RULE 9 blocked_protocols matches "+
					"this name; quoting the inner packet's L4 here would be a fabrication)",
					pi.Protocol, tc.want)
			}
		})
	}
}
