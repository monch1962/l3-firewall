// Red-team security hardening Round 91 — admin TLS key material.
//
// StartServerTLS loads the control plane's certificate and private key with
// tls.LoadX509KeyPair, which is two bare os.ReadFile calls. Every OTHER
// credential-bearing reader in this tree was hardened across R42/R62/R70/R85
// (readPolicyFile, geoip.NewReader, persist.LoadState, audit.openAuditFile):
// ".." rejected on the RAW path, O_NOFOLLOW, O_NONBLOCK, regular-file check on
// the opened fd, size cap enforced before the content reaches memory.
//
// The TLS pair never got the class, and it is the most sensitive file in the
// process: its content IS the control-plane identity. R83 already named the
// threat — "a certificate planted/removed by an attacker with write access to
// the configured path (the standing R42/R45/R62/R70 model)" — but fixed only
// the FAILURE direction (an unloadable pair must not downgrade to cleartext).
// A planted pair that parses is not a failure: it loads, and the admin API
// then speaks TLS with a private key the attacker knows, on the same channel
// that carries the bearer token and POST /admin/policy/reload.
//
// Same reader, three shapes:
//   - symlink (final or directory component) -> attacker-chosen key pair
//     serves the authenticated control plane; the attacker can impersonate it
//     to a supervisor/proxy and decrypt captured admin sessions;
//   - FIFO -> os.ReadFile blocks forever, so main() never reaches eng.Run():
//     the whole firewall fails to start (R14/R15/R38/R55 class);
//   - oversized file -> os.ReadFile buffers the whole thing before any check
//     (R42 check-before-allocate doctrine), so a multi-GB "certificate"
//     exhausts memory at startup.
package admin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// genKeyPairForCN builds a self-signed certificate (with a fresh ECDSA key)
// whose subject CN is cn, and returns both halves as PEM.
func genKeyPairForCN(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// writePair writes a cert/key pair into dir under the given file names.
func writePair(t *testing.T, dir, certName, keyName string, certPEM, keyPEM []byte) (string, string) {
	t.Helper()
	certPath := filepath.Join(dir, certName)
	keyPath := filepath.Join(dir, keyName)
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("writing cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	return certPath, keyPath
}

// servedCertCN establishes a TLS connection to addr and returns the CN of the
// certificate the listener presented. "" when the handshake fails.
func servedCertCN(t *testing.T, addr string) string {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // the point of the test is which cert is served
	})
	if err != nil {
		return ""
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return ""
	}
	return certs[0].Subject.CommonName
}

// ── R91.1: symlinked TLS material must not become the control plane identity ─
// An attacker with write access to the configured path (the standing threat
// model — a writable secret mount, a shared volume, /tmp) plants links at the
// configured cert and key. tls.LoadX509KeyPair follows them, so the admin API
// comes up healthy and authenticated against a key pair the attacker owns.
func TestAttack_AdminTLSPlantedSymlinkServesAttackerKeyPair(t *testing.T) {
	attackerDir := t.TempDir()
	attackerCert, attackerKey := genKeyPairForCN(t, "evil.example")
	evilCert, evilKey := writePair(t, attackerDir, "evil.crt", "evil.key", attackerCert, attackerKey)

	cases := []struct {
		name string
		// arrange returns the (cert, key) paths handed to StartServerTLS.
		arrange func(t *testing.T, dir string) (string, string)
	}{
		{
			name: "final-component symlink",
			arrange: func(t *testing.T, dir string) (string, string) {
				certPath := filepath.Join(dir, "tls.crt")
				keyPath := filepath.Join(dir, "tls.key")
				if err := os.Symlink(evilCert, certPath); err != nil {
					t.Fatalf("planting cert symlink: %v", err)
				}
				if err := os.Symlink(evilKey, keyPath); err != nil {
					t.Fatalf("planting key symlink: %v", err)
				}
				return certPath, keyPath
			},
		},
		{
			name: "directory-component symlink",
			arrange: func(t *testing.T, dir string) (string, string) {
				// dir/certs -> attackerDir; cert/key live inside the linked dir.
				if err := os.Symlink(attackerDir, filepath.Join(dir, "certs")); err != nil {
					t.Fatalf("planting dir symlink: %v", err)
				}
				return filepath.Join(dir, "certs", "evil.crt"), filepath.Join(dir, "certs", "evil.key")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			certPath, keyPath := tc.arrange(t, dir)

			api := newTestAPI(t)
			srv, addr, err := api.StartServerTLS("127.0.0.1:0", certPath, keyPath)
			if err != nil {
				// Desired: the planted material is refused outright.
				return
			}
			defer srv.Close()

			if cn := servedCertCN(t, addr); cn == "evil.example" {
				t.Fatalf("admin control plane serves the attacker's certificate (CN=evil.example): "+
					"the TLS key material was read through a planted symlink at %s / %s", certPath, keyPath)
			}
		})
	}
}

// ── R91.2: FIFO at --admin-tls-cert must not hang startup ───────────────────
// os.ReadFile on a FIFO blocks until a writer appears. StartServerTLS runs
// synchronously in main() BEFORE eng.Run(), so a FIFO at either path means the
// firewall never starts at all — a startup DoS with no listener, no engine and
// no error (R14/R15/R38 class, which every other reader already closes).
func TestAttack_AdminTLSCertFIFOBlocksStartup(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := genKeyPairForCN(t, "fifo.example")
	_, keyPath := writePair(t, dir, "unused.crt", "tls.key", nil, keyPEM)

	fifoPath := filepath.Join(dir, "tls.crt")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Skipf("mkfifo unsupported here: %v", err)
	}

	api := newTestAPI(t)
	type result struct {
		srv  interface{ Close() error }
		addr string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		srv, addr, err := api.StartServerTLS("127.0.0.1:0", fifoPath, keyPath)
		var c interface{ Close() error }
		if srv != nil {
			c = srv
		}
		done <- result{srv: c, addr: addr, err: err}
	}()

	select {
	case r := <-done:
		if r.srv != nil {
			defer r.srv.Close()
		}
		if r.err == nil {
			t.Fatalf("StartServerTLS accepted a FIFO certificate and started a listener on %s", r.addr)
		}
		// Desired: named pipe rejected, no listener.
	case <-time.After(3 * time.Second):
		t.Fatalf("StartServerTLS blocked for over 3s on a FIFO --admin-tls-cert: "+
			"startup hangs forever and the firewall never reaches eng.Run() (path %s)", fifoPath)
	}
	_ = certPEM
}

// ── R91.3: oversized key material must be rejected before it is buffered ────
// A certificate file is a few KB. Reading a multi-GB "certificate" buffers the
// whole thing (os.ReadFile) before any parsing/validation, so the size cap has
// to be enforced on the read, not after it (R42 check-before-allocate).
func TestAttack_AdminTLSOversizedCertRejected(t *testing.T) {
	dir := t.TempDir()
	attackerCert, attackerKey := genKeyPairForCN(t, "big.example")
	// A valid certificate followed by trailing padding: tls.X509KeyPair scans
	// for PEM blocks and ignores the rest, so without a size cap this loads.
	padded := append(append([]byte{}, attackerCert...), []byte(strings.Repeat("A", 2*1024*1024))...)
	certPath, keyPath := writePair(t, dir, "tls.crt", "tls.key", padded, attackerKey)

	api := newTestAPI(t)
	srv, addr, err := api.StartServerTLS("127.0.0.1:0", certPath, keyPath)
	if err == nil {
		defer srv.Close()
		t.Fatalf("StartServerTLS accepted a %d-byte certificate file (started %s): "+
			"there is no size cap on the TLS key material read", len(padded), addr)
	}
}

// ── R91.4: regression — ordinary key material still loads ──────────────────
// The hardening must not reject a normal pair (including a chains-of-trust
// PEM, which is just concatenated CERTIFICATE blocks).
func TestAttack_AdminTLSOrdinaryPairStillWorks(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := genKeyPairForCN(t, "localhost")
	// Cert chain shape: the same block twice — still a plain regular file.
	chain := append(append([]byte{}, certPEM...), certPEM...)
	certPath, keyPath := writePair(t, dir, "tls.crt", "tls.key", chain, keyPEM)

	api := newTestAPI(t)
	srv, addr, err := api.StartServerTLS("127.0.0.1:0", certPath, keyPath)
	if err != nil {
		t.Fatalf("StartServerTLS rejected a legitimate pair: %v", err)
	}
	defer srv.Close()

	if cn := servedCertCN(t, addr); cn != "localhost" {
		t.Fatalf("served certificate CN = %q, want localhost", cn)
	}
	if _, err := net.ResolveTCPAddr("tcp", addr); err != nil {
		t.Fatalf("listener address %q not usable: %v", addr, err)
	}
}
