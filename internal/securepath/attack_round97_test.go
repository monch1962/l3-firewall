// Red-team Round 97 — the shared credential-file reader.
//
// R91 found that `tls.LoadX509KeyPair` is two bare `os.ReadFile` calls and
// gave the admin control plane a hardened reader. R97 wires etcd TLS material
// (CA bundle, client certificate, client key) through the same requirements,
// so the class is centralised here once instead of copied into a third
// package (R85/R89: a guard copied into consumers drifts). These tests pin the
// four shapes at the helper level so every future consumer inherits them:
// '..' components, a symlink at the final or a directory component, a FIFO
// (blocking open = startup DoS), and an oversized file (check-before-allocate).
package securepath

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReadCredentialFile_RegularFileWorks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ca.pem")
	want := []byte("-----BEGIN CERTIFICATE-----\nnot really\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(p, want, 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	got, err := ReadCredentialFile(p, 1<<20)
	if err != nil {
		t.Fatalf("ReadCredentialFile: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("content = %q, want %q", got, want)
	}
}

func TestReadCredentialFile_RejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	// Raw string: filepath.Join would CLEAN the '..' away in the test itself.
	raw := dir + "/../anything/ca.pem"
	if _, err := ReadCredentialFile(raw, 1<<20); err == nil {
		t.Errorf("a path containing '..' was accepted: %q", raw)
	}
}

func TestReadCredentialFile_RejectsSymlinkFinalAndDirectory(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.pem")
	if err := os.WriteFile(real, []byte("x"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := ReadCredentialFile(link, 1<<20); err == nil {
		t.Error("a symlinked credential file was read: a planted link serves an attacker-chosen " +
			"TLS identity / trust root")
	}

	realDir := filepath.Join(dir, "realdir")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "f.pem"), []byte("x"), 0o600); err != nil {
		t.Fatalf("writing inner: %v", err)
	}
	dirLink := filepath.Join(dir, "dirlink")
	if err := os.Symlink(realDir, dirLink); err != nil {
		t.Fatalf("symlink dir: %v", err)
	}
	if _, err := ReadCredentialFile(filepath.Join(dirLink, "f.pem"), 1<<20); err == nil {
		t.Error("a credential file behind a symlinked DIRECTORY was read: O_NOFOLLOW only " +
			"protects the final component and the kernel resolves directory links first")
	}
}

func TestReadCredentialFile_FIFODoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo.pem")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadCredentialFile(fifo, 1<<20)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a FIFO was accepted as credential material")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ReadCredentialFile blocked on a FIFO: a caller reading credential material " +
			"at startup never returns (R14/R15/R38/R55 class)")
	}
}

func TestReadCredentialFile_RejectsOversized(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.pem")
	if err := os.WriteFile(p, []byte(strings.Repeat("A", 64*1024)), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if _, err := ReadCredentialFile(p, 32*1024); err == nil {
		t.Error("a file larger than the caller's cap was read: the cap must be enforced " +
			"before the content is buffered (R42 check-before-allocate)")
	}
}

func TestReadCredentialFile_RejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadCredentialFile(dir, 1<<20); err == nil {
		t.Error("a directory was accepted as credential material")
	}
}
