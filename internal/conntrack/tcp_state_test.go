package conntrack

import (
	"testing"
)

func TestTCPStateInitial(t *testing.T) {
	ct := NewTable(DefaultConfig())
	f := ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP", 44001, 443)
	if f.TCPState != TCPSynSent {
		t.Errorf("initial state = %d (%s), want %d (SYN_SENT)", f.TCPState, f.TCPState, TCPSynSent)
	}
}

func TestTCPTransitionSynSentToEstablished(t *testing.T) {
	ct := NewTable(DefaultConfig())

	// Client sends SYN
	f := ct.UpdateTCPState("10.0.1.100", "10.0.2.50", "TCP", 44001, 443, true, true, false, false)
	if f.TCPState != TCPEstablished {
		t.Errorf("SYN+ACK state = %d (%s), want %d (ESTABLISHED)", f.TCPState, f.TCPState, TCPEstablished)
	}
	if !f.Established {
		t.Error("Established should be true after SYN+ACK")
	}
}

func TestTCPTransitionSynToSynAck(t *testing.T) {
	ct := NewTable(DefaultConfig())

	// First SYN from client
	f := ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP", 44001, 443)
	if f.TCPState != TCPSynSent {
		t.Errorf("after SYN = %d (%s), want %d (SYN_SENT)", f.TCPState, f.TCPState, TCPSynSent)
	}

	// Server responds with SYN+ACK (reverse 5-tuple)
	f2 := ct.UpdateTCPState("10.0.2.50", "10.0.1.100", "TCP", 443, 44001, true, true, false, false)
	if f2.TCPState != TCPEstablished {
		t.Errorf("after SYN+ACK = %d (%s), want %d (ESTABLISHED)", f2.TCPState, f2.TCPState, TCPEstablished)
	}
}

func TestTCPTransitionFinTeardown(t *testing.T) {
	ct := NewTable(DefaultConfig())

	// Establish connection
	f := ct.UpdateTCPState("10.0.1.100", "10.0.2.50", "TCP", 44001, 443, true, true, false, false)
	if f.TCPState != TCPEstablished {
		t.Fatalf("expected ESTABLISHED, got %s", f.TCPState)
	}

	// Client sends FIN
	ct.UpdateTCPState("10.0.1.100", "10.0.2.50", "TCP", 44001, 443, false, true, false, true)
	if f.TCPState != TCPFinWait1 {
		t.Errorf("after FIN = %d (%s), want %d (FIN_WAIT_1)", f.TCPState, f.TCPState, TCPFinWait1)
	}
}

func TestTCPTransitionRstCloses(t *testing.T) {
	ct := NewTable(DefaultConfig())

	f := ct.UpdateTCPState("10.0.1.100", "10.0.2.50", "TCP", 44001, 443, true, true, false, false)

	// RST
	ct.UpdateTCPState("10.0.1.100", "10.0.2.50", "TCP", 44001, 443, false, false, true, false)
	if f.TCPState != TCPClosed {
		t.Errorf("after RST = %d (%s), want %d (CLOSED)", f.TCPState, f.TCPState, TCPClosed)
	}
}

func TestTCPStateString(t *testing.T) {
	tests := []struct {
		state TCPState
		want  string
	}{
		{TCPSynSent, "SYN_SENT"},
		{TCPEstablished, "ESTABLISHED"},
		{TCPFinWait1, "FIN_WAIT_1"},
		{TCPClosed, "CLOSED"},
		{TCPState(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("TCPState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestTCPFinAckTransition(t *testing.T) {
	ct := NewTable(DefaultConfig())

	// Establish
	f := ct.UpdateTCPState("10.0.1.100", "10.0.2.50", "TCP", 44001, 443, true, true, false, false)

	// FIN from client
	ct.UpdateTCPState("10.0.1.100", "10.0.2.50", "TCP", 44001, 443, false, true, false, true)
	if f.TCPState != TCPFinWait1 {
		t.Fatalf("expected FIN_WAIT_1, got %s", f.TCPState)
	}

	// FIN+ACK from server side
	ct.UpdateTCPState("10.0.2.50", "10.0.1.100", "TCP", 443, 44001, false, true, false, true)
	if f2 := ct.LookupOrCreate("10.0.2.50", "10.0.1.100", "TCP", 443, 44001); f2.TCPState != TCPFinWait1 {
		t.Errorf("server FIN state = %s, want FIN_WAIT_1", f2.TCPState)
	}
}

func TestUDPNoTCPState(t *testing.T) {
	ct := NewTable(DefaultConfig())
	f := ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "UDP", 44001, 53)
	if f.TCPState != 0 {
		t.Error("UDP flows should have zero TCP state")
	}
}
