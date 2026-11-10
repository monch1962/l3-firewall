// Red-team security hardening Round 84 — the admin Host guard must be WIRED.
//
// `internal/admin` installs the DNS-rebinding Host guard in StartServer and
// StartServerTLS, and `WithAllowedHosts` is the operator's escape hatch for a
// reverse proxy / service DNS name. A flag that is parsed but never passed to
// the constructor would be the R40.4 "silently dropped control" again: the
// operator believes the named host is allowed (or that the guard is
// configurable) while the binary ignores it.
//
// These static checks pin the wiring in main.go and the operator-facing
// documentation, matching the R83 deployment-parity style.
package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestAttack_AdminHostAllowlistFlagWired(t *testing.T) {
	src, err := os.ReadFile(mainSourcePath)
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	code := string(src)

	if !regexp.MustCompile(`flag\.String\("admin-allowed-hosts"`).MatchString(code) {
		t.Fatal("main.go no longer declares --admin-allowed-hosts: operators cannot allow a DNS name, so a reverse-proxy deployment would be refused by the R84 Host guard")
	}
	if !regexp.MustCompile(`WithAllowedHosts\(`).MatchString(code) {
		t.Fatal("main.go parses --admin-allowed-hosts but never calls WithAllowedHosts: a parsed-but-unwired flag is a silently dropped control (R40.4)")
	}
	// The value passed must be the flag, not a constant.
	if !regexp.MustCompile(`WithAllowedHosts\(allowed\.\.\.\)|WithAllowedHosts\(\*adminAllowedHosts`).MatchString(code) {
		t.Error("WithAllowedHosts is called, but not with the parsed --admin-allowed-hosts value")
	}
}

func TestAttack_AdminHostAllowlistDocumented(t *testing.T) {
	data, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("reading README: %v", err)
	}
	readme := string(data)

	if !strings.Contains(readme, "--admin-allowed-hosts") {
		t.Error("README flag table does not document --admin-allowed-hosts: an operator cannot discover how to allow a DNS name through the R84 Host guard")
	}
	// The hardening table must state the DNS-rebinding defence.
	if !strings.Contains(readme, "DNS rebinding") && !strings.Contains(readme, "DNS-rebinding") {
		t.Error("README hardening table does not mention the DNS-rebinding Host guard (R84)")
	}
}
