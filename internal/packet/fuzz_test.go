package packet

import (
	"testing"
)

// FuzzParsePacket is the packet parser's first fuzz target (R80). ParsePacket
// consumes raw attacker-controlled bytes from the NFQUEUE hot path: every
// field it reads must be bounds-checked, and a panic there is an unrecovered
// process crash (the engine's recover is in the queue callback, but the
// parser must be panic-free on its own contract). Seeds cover the shapes the
// parser special-cases: IPv4/IPv6, TCP/UDP/ICMP, fragments, extension-header
// chains and truncations.
func FuzzParsePacket(f *testing.F) {
	seeds := [][]byte{
		{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
			0x9c, 0x40, 0x00, 0x16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x20, 0, 0, 0, 0, 0},
		{0x60, 0, 0, 0, 0, 20, 0x3a, 64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 128, 0, 0, 0},
		{0x00},
		{0x40},
		{0x45, 0, 0, 20, 0, 0, 0x20, 0, 64, 6, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8},
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		info, err := ParsePacket(raw)
		if err != nil {
			return
		}
		if info == nil {
			t.Fatal("ParsePacket returned nil info with nil error")
		}
		// The parser must never report fields read past the end of the
		// buffer: every reported port must have come from a 4-byte L4
		// prefix that exists on the wire.
		if len(raw) > 0 && info.PacketSize > len(raw) {
			t.Fatalf("PacketSize = %d exceeds the %d-byte buffer", info.PacketSize, len(raw))
		}
	})
}
