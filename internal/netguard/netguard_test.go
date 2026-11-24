// Package netguard — unit tests for the loopback predicate (R97).
//
// The predicate decides whether a channel is exempt from the "this credential
// travels in cleartext" warning. Both directions are security-relevant: a
// FALSE NEGATIVE (a routable host reported as loopback) silences the warning
// on the channel an on-path attacker can read, and a FALSE POSITIVE trains
// the operator to ignore the warning (R88.3). The hosts here are the shapes
// callers actually pass: url.URL.Hostname() output, a bare host:port, and
// bracketed IPv6 literals.
package netguard

import "testing"

func TestIsLoopbackHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		// Loopback, every spelling callers arrive with.
		{"127.0.0.1", true},
		{"127.0.0.1:2379", true},
		{"127.5.5.5", true}, // all of 127/8 is loopback
		{"::1", true},
		{"[::1]", true},
		{"[::1]:2379", true},
		{"::ffff:127.0.0.1", true},
		{"localhost", true},
		{"LOCALHOST", true},
		{"localhost.", true},
		{"localhost:8080", true},
		{"api.localhost", true}, // RFC 6761: *.localhost never leaves the host

		// Routable: must NOT be exempt.
		{"", false},
		{"   ", false},
		{"10.0.0.1", false},
		{"192.168.1.10:2379", false},
		{"0.0.0.0", false},
		{"::", false},
		{"[2001:db8::1]:443", false},
		{"etcd-0.internal", false},
		{"etcd-0.internal:2379", false},
		{"127.0.0.1.evil.example", false},
		{"localhost.evil.example", false},
		{"evil-localhost.example", false},
		{"[::1].evil.example", false},
	}
	for _, tc := range cases {
		if got := IsLoopbackHost(tc.host); got != tc.want {
			t.Errorf("IsLoopbackHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}
