// Red-team Round 97 (part 2) — etcd TLS material: the control that did not
// exist, and the reader it must not use.
//
// Round 97's first half taught `syncer.New` to carry a `*tls.Config`, to
// refuse a TLS config paired with a plaintext endpoint, and to warn when the
// policy channel is plaintext. It stopped one link short of the deployment
// (R90/R93 "the wiring is the finding"): `cmd/server` declared no
// `--etcd-tls-*` flag, so `Config.TLS` could never be set from the shipped
// binary — the `plaintextWarning` text even named three flags that did not
// exist. The admin control plane got exactly this treatment in R87.
//
// Wiring the flags then creates the second half: the CA bundle and the client
// identity are ATTACKER-INFLUENCED FILE PATHS (the standing R42/R45/R62/R70/
// R91 model: write access to the configured path). Read with a bare
// os.ReadFile they are the three shapes R91 found in the admin key pair:
//   - a symlink serves an attacker-chosen CA -> the firewall trusts an
//     attacker-controlled etcd, which then rewrites the policy that governs
//     every packet (the R97.1 harm with a valid TLS handshake on top, so
//     nothing looks wrong from the inside);
//   - a FIFO blocks the read forever -> main() never reaches eng.Run()
//     (startup DoS, R14/R15/R38/R55 class);
//   - an oversized "bundle" is buffered whole before any check is made
//     (R42 check-before-allocate).
//
// A CA bundle that parses to ZERO certificates is a fourth shape: silently
// falling back to the system pool makes an operator's pinned CA do nothing.
package syncer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// genSyncerCerts returns a self-signed CA (IsCA, usable as a root) and a
// client certificate/key pair signed by it, all as PEM.
func genSyncerCerts(t *testing.T, cn string) (caPEM, certPEM, keyPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn + "-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{cn},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating client certificate: %v", err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(leafKey)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
}

func writePEM(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("writing %s: %v", p, err)
	}
	return p
}

// ── R97.11: the operator's CA and client identity must actually load ───────
// (positive control for every refusal below — a guard that rejects everything
// would pass them all while making the control unusable).
func TestAttack_EtcdTLSMaterialLoadsFromFiles(t *testing.T) {
	dir := t.TempDir()
	caPEM, certPEM, keyPEM := genSyncerCerts(t, "etcd-0.internal")
	ca := writePEM(t, dir, "ca.pem", caPEM)
	cert := writePEM(t, dir, "client.pem", certPEM)
	key := writePEM(t, dir, "client-key.pem", keyPEM)

	cfg, err := TLSConfig(ca, cert, key)
	if err != nil {
		t.Fatalf("TLSConfig with valid material: %v", err)
	}
	if cfg == nil {
		t.Fatal("TLSConfig returned nil for configured material")
	}
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs is nil: the operator's CA was dropped, so the client would trust the system pool instead")
	}
	// Prove the pinned CA is the one in force: the client certificate must
	// chain to it (and to nothing else — the pool holds only this root).
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("decoding client certificate PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing client certificate: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     cfg.RootCAs,
		DNSName:   "etcd-0.internal",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("the loaded RootCAs does not verify the certificate issued by the configured CA: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("client identity has %d certificates, want 1 (mTLS would be anonymous)", len(cfg.Certificates))
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want >= TLS 1.2", cfg.MinVersion)
	}

	// No material configured at all = the scheme decides (nil, nil).
	empty, err := TLSConfig("", "", "")
	if err != nil || empty != nil {
		t.Errorf("TLSConfig(\"\",\"\",\"\") = (%v, %v), want (nil, nil)", empty, err)
	}
}

// ── R97.12: symlinked TLS material must be refused (final + directory) ─────
func TestAttack_EtcdTLSSymlinkedMaterialRejected(t *testing.T) {
	dir := t.TempDir()
	caPEM, _, _ := genSyncerCerts(t, "etcd-0.internal")
	real := writePEM(t, dir, "real-ca.pem", caPEM)

	// Final component.
	finalLink := filepath.Join(dir, "ca-link.pem")
	if err := os.Symlink(real, finalLink); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := TLSConfig(finalLink, "", ""); err == nil {
		t.Error("a symlinked CA bundle was accepted: a planted link serves an attacker-chosen " +
			"trust root, so the firewall trusts an attacker's etcd and accepts its policy")
	}

	// Directory component (the kernel resolves it before O_NOFOLLOW sees the file).
	realDir := filepath.Join(dir, "realdir")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	inner := writePEM(t, realDir, "ca.pem", caPEM)
	dirLink := filepath.Join(dir, "dirlink")
	if err := os.Symlink(realDir, dirLink); err != nil {
		t.Fatalf("symlink dir: %v", err)
	}
	escape := filepath.Join(dirLink, filepath.Base(inner))
	if _, err := TLSConfig(escape, "", ""); err == nil {
		t.Error("a CA bundle reached through a symlinked DIRECTORY was accepted: O_NOFOLLOW " +
			"only protects the final component, and the kernel resolves directory links first")
	}
}

// ── R97.13: a FIFO planted at the CA path must not hang startup ────────────
// TLSConfig runs synchronously in main() before eng.Run(), so a blocking open
// is a startup DoS: the firewall never filters a single packet.
func TestAttack_EtcdTLSFIFODoesNotBlockStartup(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "ca.pem")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := TLSConfig(fifo, "", "")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a FIFO at the CA path was accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("TLSConfig blocked on a FIFO at the CA path: main() never reaches eng.Run(), " +
			"so the firewall does not filter a single packet (R14/R15/R38/R55 class)")
	}
}

// ── R97.14: oversized material is refused before it reaches memory ─────────
func TestAttack_EtcdTLSOversizedMaterialRejected(t *testing.T) {
	dir := t.TempDir()
	_, certPEM, keyPEM := genSyncerCerts(t, "etcd-0.internal")
	big := filepath.Join(dir, "huge-ca.pem")
	if err := os.WriteFile(big, []byte(strings.Repeat("A", 2<<20)), 0o600); err != nil {
		t.Fatalf("writing oversized file: %v", err)
	}
	if _, err := TLSConfig(big, "", ""); err == nil {
		t.Error("a 2 MiB 'CA bundle' was accepted: the check-before-allocate cap (R42) is missing")
	}
	_ = certPEM
	_ = keyPEM
}

// ── R97.15: a CA bundle with no certificate must not fall back to system roots ──
func TestAttack_EtcdTLSCAWithoutCertificatesRejected(t *testing.T) {
	dir := t.TempDir()
	empty := writePEM(t, dir, "ca.pem", []byte("not a certificate\n"))
	if _, err := TLSConfig(empty, "", ""); err == nil {
		t.Error("a CA bundle containing no certificate was accepted: the pinned trust root " +
			"silently becomes the system pool, so the operator's CA does nothing")
	}
}

// ── R97.16: half a client identity must fail closed ────────────────────────
func TestAttack_EtcdTLSHalfClientIdentityRejected(t *testing.T) {
	dir := t.TempDir()
	_, certPEM, keyPEM := genSyncerCerts(t, "etcd-0.internal")
	cert := writePEM(t, dir, "client.pem", certPEM)
	key := writePEM(t, dir, "client-key.pem", keyPEM)

	if _, err := TLSConfig("", cert, ""); err == nil {
		t.Error("a client certificate with no key was accepted: mTLS silently off")
	}
	if _, err := TLSConfig("", "", key); err == nil {
		t.Error("a client key with no certificate was accepted: mTLS silently off")
	}
}
