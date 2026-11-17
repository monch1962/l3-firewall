package admin

import (
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/monch1962/l3-firewall/internal/securepath"
)

// maxKeyFileSize caps each PEM file read for the admin control plane (R91).
// A certificate chain plus its private key is a few KB; 1MB is a generous
// upper bound and still far below anything that would matter for memory.
const maxKeyFileSize = 1 << 20

// readKeyFile reads one PEM file of the admin TLS key pair with the same
// hardening every other credential-bearing reader in this tree uses
// (readPolicyFile R42/R70/R85, geoip.NewReader R38/R71, persist.LoadState
// R62, audit.openAuditFile R15/R43):
//
//   - ".." components rejected on the RAW path (filepath.Dir/Clean consume
//     them before a walk could see them, while the kernel resolves the raw
//     string) — R85;
//   - symlinks at every DIRECTORY component rejected (the kernel resolves
//     them before the open, so O_NOFOLLOW alone cannot help) — R45/R62;
//   - O_NOFOLLOW: a symlink at the FINAL component refused — R42;
//   - O_NONBLOCK + regular-file check on the already-opened fd: a FIFO planted
//     at the path would otherwise block the open forever (startup DoS — this
//     read runs synchronously in main() before eng.Run()), and the type check
//     on the open descriptor leaves no Stat/Open TOCTOU window — R14/R15/R38;
//   - size cap enforced through fstat AND io.LimitReader, so a multi-GB
//     "certificate" is refused before its content is buffered — R42's
//     check-before-allocate doctrine.
//
// The TLS pair was the LAST reader without this class, and it is the most
// sensitive file in the process: its content IS the control-plane identity
// (R91 — R83 named "a certificate planted by an attacker with write access to
// the configured path" but only fixed the load-FAILURE direction; a planted
// pair that parses loads happily and the admin API then serves the attacker's
// key).
func readKeyFile(path string) ([]byte, error) {
	if err := securepath.RejectUnsafePath(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("opening TLS key material %s: %w", path, err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stating TLS key material %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("TLS key material is not a regular file: %s", path)
	}
	if fi.Size() > maxKeyFileSize {
		return nil, fmt.Errorf("TLS key material %s too large: %d bytes (max %d)", path, fi.Size(), maxKeyFileSize)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxKeyFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading TLS key material %s: %w", path, err)
	}
	if len(data) > maxKeyFileSize {
		return nil, fmt.Errorf("TLS key material %s grew beyond %d bytes while reading", path, maxKeyFileSize)
	}
	return data, nil
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
