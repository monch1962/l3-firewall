package admin

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestStartServerTLS(t *testing.T) {
	api := newTestAPI(t)
	srv, addr, err := api.StartServerTLS(":0", "testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Fatalf("StartServerTLS: %v", err)
	}
	defer srv.Close()

	if addr == "" || addr == ":0" {
		t.Fatalf("expected real listening address, got %q", addr)
	}
	// TLS is handled at the listener level when using StartServerTLS.
	// Verify by making a TLS connection.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get("https://" + addr + "/admin/health")
	if err != nil {
		t.Fatalf("TLS connection failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestStartServerPlain(t *testing.T) {
	api := newTestAPI(t)
	srv := api.StartServer(":0")
	if srv == nil {
		t.Fatal("StartServer returned nil")
	}
	defer srv.Close()
	if srv.TLSConfig != nil {
		t.Fatal("expected TLSConfig to be nil for plain HTTP")
	}
}

func TestStartServerTLSWithEmptyPaths(t *testing.T) {
	api := newTestAPI(t)
	srv, addr, err := api.StartServerTLS(":0", "", "")
	if err != nil {
		t.Fatalf("StartServerTLS: %v", err)
	}
	defer srv.Close()
	if addr == "" {
		t.Fatal("expected non-empty address")
	}
	if srv.TLSConfig != nil {
		t.Fatal("expected TLSConfig to be nil when cert paths are empty")
	}
}

func TestHealthEndpointOverTLS(t *testing.T) {
	api := newTestAPI(t)
	srv, addr, err := api.StartServerTLS(":0", "testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Fatalf("StartServerTLS: %v", err)
	}
	defer srv.Close()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get("https://" + addr + "/admin/health")
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}
