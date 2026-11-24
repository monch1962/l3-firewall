// Package netguard provides small predicates about whether a host address can
// put bytes on a network.
//
// It exists so that every "is this channel observable by an on-path attacker?"
// decision in the tree uses ONE predicate (R85/R86 doctrine: a guard copied
// into two consumers drifts). Two consumers ask that question today — the
// outbound alert webhook (internal/alert, R88.3) and the etcd policy channel
// (internal/syncer, R97) — and both treat loopback as exempt: those bytes never
// leave the host, so a warning there would only train an operator to ignore it.
package netguard

import (
	"net"
	"strings"
)

// IsLoopbackHost reports whether host cannot put bytes on a network: a
// loopback IP literal, `localhost`, or a `*.localhost` name (which RFC 6761
// reserves for loopback).
//
// Both shapes callers arrive with are accepted — a bare hostname
// (`url.URL.Hostname()`) and `host:port` with an optional IPv4/IPv6 port
// suffix (`127.0.0.1:2379`, `[::1]:8082`). An empty host, or any name that is
// not a literal and not localhost, reports false: an unresolvable DNS name is
// still a name that will be resolved and dialled over the network.
func IsLoopbackHost(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if h == "" {
		return false
	}
	// Bracketed IPv6 literal: [::1] or [::1]:2379.
	//
	// The bracket form is only a literal when NOTHING but a numeric port
	// follows the closing bracket. Returning on the parsed address alone made
	// `[::1].evil.example` report loopback — a false NEGATIVE in the dangerous
	// direction (a routable name reported as loopback silences the cleartext
	// warning on the channel an on-path attacker can read), which is why the
	// suffix is validated before the address is judged.
	if strings.HasPrefix(h, "[") {
		end := strings.Index(h, "]")
		if end <= 0 {
			return false
		}
		rest := h[end+1:]
		if rest != "" && !(strings.HasPrefix(rest, ":") && isNumericPort(rest[1:])) {
			return false
		}
		ip := net.ParseIP(h[1:end])
		if ip == nil {
			return false
		}
		return ip.IsLoopback()
	}
	// Unbracketed literal (IPv4 or IPv6).
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	// host:port for a non-bracketed literal or a name.
	if hp, _, err := net.SplitHostPort(h); err == nil {
		if ip := net.ParseIP(hp); ip != nil {
			return ip.IsLoopback()
		}
		return hp == "localhost" || strings.HasSuffix(hp, ".localhost")
	}
	return h == "localhost" || strings.HasSuffix(h, ".localhost")
}

// isNumericPort reports whether s is a non-empty run of ASCII digits.
func isNumericPort(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
