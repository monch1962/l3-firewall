// Red-team Round 97 — the etcd TLS flags must be WIRED into the policy channel.
//
// R97's library half added `syncer.Config.TLS`, the endpoint/TLS pairing
// validation and the plaintext warning — but `cmd/server` declared no
// `--etcd-tls-*` flag and never set `TLS:`, so from the shipped binary the
// hardened path was unreachable and the warning text named three flags that
// did not exist. That is the R87 admin-TLS finding exactly ("StartServerTLS
// existed since R56/R83 and was unreachable from the binary, so every
// deployment served the control plane in plaintext"), and the R90/R93 lesson
// that a control no one calls is documentation, not a control.
//
// main() is not unit-testable (it ends in eng.Run), so — like R90/R93/R94/R95
// — the assertion is structural: the flags must be declared, the TLS material
// must be resolved through the hardened loader, and the result must reach the
// syncer's Config.
package main

import (
	"os"
	"strings"
	"testing"
)

func TestAttack_EtcdTLSFlagsAreWiredIntoThePolicyChannel(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	text := string(src)

	for _, want := range []string{
		`flag.String("etcd-tls-ca"`,
		`flag.String("etcd-tls-cert"`,
		`flag.String("etcd-tls-key"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("main.go no longer declares %s: the policy channel that carries the "+
				"enforced Rego can only be encrypted by flags the binary exposes — without "+
				"them any on-path host can rewrite the policy and disable blocking", want)
		}
	}

	// The material must be resolved through syncer.TLSConfig, which is the one
	// place the hardened read + the pairing/TLS-version checks live.
	idx := strings.Index(text, "syncer.TLSConfig(")
	if idx < 0 {
		t.Fatal("main.go does not call syncer.TLSConfig: the CA / client identity would " +
			"never be loaded, so --etcd-tls-ca would be a silently inert flag")
	}
	if !strings.Contains(text[idx:], "etcdTLSCA") {
		t.Error("syncer.TLSConfig is called without the --etcd-tls-ca value")
	}

	// ...and the resolved *tls.Config must be handed to the syncer.
	newCfg := strings.Index(text, "syncer.New(syncer.Config{")
	if newCfg < 0 {
		t.Fatal("main.go no longer constructs syncer.Config; re-verify the wiring")
	}
	block := text[newCfg:]
	if end := strings.Index(block, "})"); end > 0 {
		block = block[:end]
	}
	if !strings.Contains(block, "TLS:") {
		t.Error("syncer.Config is built WITHOUT a TLS field: the client would ignore " +
			"--etcd-tls-ca/--etcd-tls-cert/--etcd-tls-key and connect with the scheme's " +
			"defaults, i.e. plaintext for the shipped http:// endpoints")
	}

	// A configuration that can never work must stop the process; only an
	// unreachable cluster may be warned about (the syncer retries it in the
	// background). Otherwise the firewall runs with a policy plane that is
	// silently dead while /admin/health reports a healthy process.
	if !strings.Contains(text, "errors.Is(err, syncer.ErrConfig)") {
		t.Error("main.go does not distinguish a syncer CONFIG error (ErrConfig) from an " +
			"unreachable cluster: a TLS/endpoint mismatch would be warned about once and the " +
			"firewall would then run forever without the policy channel it was told to use")
	}
	if !strings.Contains(text, `log.Fatalf("etcd configuration:`) {
		t.Error("main.go does not refuse to start on an etcd configuration error")
	}
}
