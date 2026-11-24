package admin

import (
	"crypto/tls"
	"fmt"

	"github.com/monch1962/l3-firewall/internal/securepath"
)

// maxKeyFileSize caps each PEM file read for the admin control plane (R91).
// A certificate chain plus its private key is a few KB; 1MB is a generous
// upper bound and still far below anything that would matter for memory.
const maxKeyFileSize = 1 << 20

// readKeyFile reads one PEM file of the admin TLS key pair.
//
// R91 wrote this reader here; R97 needed the same requirements for the etcd
// policy channel's CA bundle and client identity, so the implementation moved
// to securepath.ReadCredentialFile — one place that can be found, extended and
// tested, instead of a second copy in a third package (R85/R89: a guard that
// exists twice drifts). The reader enforces, in order: ".." rejected on the RAW
// path (R85), a symlink at any directory component rejected (R45/R62),
// O_NOFOLLOW for the final component (R42), O_NONBLOCK plus a regular-file
// check on the opened fd so a FIFO cannot block startup (R14/R15/R38), and the
// size cap through fstat AND io.LimitReader (R42 check-before-allocate).
//
// The TLS pair is the most sensitive file in the process: its content IS the
// control-plane identity (R91 — R83 named "a certificate planted by an
// attacker with write access to the configured path" but only fixed the
// load-FAILURE direction; a planted pair that parses loads happily and the
// admin API then serves the attacker's key).
func readKeyFile(path string) ([]byte, error) {
	return securepath.ReadCredentialFile(path, maxKeyFileSize)
}

// loadKeyPair reads the certificate and key through readKeyFile and parses
// them. It replaces the bare tls.LoadX509KeyPair call, which was two
// os.ReadFile calls with none of the hardening above.
func loadKeyPair(certFile, keyFile string) (tls.Certificate, error) {
	certPEM, err := readKeyFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := readKeyFile(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parsing admin TLS key pair: %w", err)
	}
	return cert, nil
}
