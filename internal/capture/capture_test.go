package capture

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewWriterNilDir(t *testing.T) {
	w, err := NewWriter(Config{Dir: ""})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if w != nil {
		t.Error("expected nil writer for empty dir")
	}
}

func TestNewWriterCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pcaps")
	w, err := NewWriter(Config{Dir: dir, MaxPackets: 10})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("directory was not created")
	}
}

func TestWriteBlockCreatesFile(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir, MaxPackets: 10})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	// Write an IPv4 packet (minimal ethernet + IPv4 header)
	raw := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // dst MAC
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // src MAC
		0x08, 0x00, // EtherType IPv4
		0x45, 0x00, 0x00, 0x14, // IPv4 header...
	}
	if err := w.WriteBlock(raw); err != nil {
		t.Fatalf("WriteBlock: %v", err)
	}

	files, _ := filepath.Glob(filepath.Join(dir, "*.pcap"))
	if len(files) != 1 {
		t.Errorf("expected 1 pcap file, got %d", len(files))
	}
}

func TestRotation(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir, MaxPackets: 2, MaxFiles: 3})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	raw := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x08, 0x00,
		0x45, 0x00, 0x00, 0x14,
	}

	for i := 0; i < 5; i++ {
		if err := w.WriteBlock(raw); err != nil {
			t.Fatalf("WriteBlock %d: %v", i, err)
		}
	}

	files, _ := filepath.Glob(filepath.Join(dir, "*.pcap"))
	if len(files) > 3 {
		t.Errorf("expected <= 3 pcap files after rotation, got %d", len(files))
	}
}

func TestWriteBlockNilWriter(t *testing.T) {
	var w *Writer
	if err := w.WriteBlock([]byte{0x00}); err != nil {
		t.Errorf("nil writer should not error, got %v", err)
	}
}

func TestClose(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestCloseNilWriter(t *testing.T) {
	var w *Writer
	if err := w.Close(); err != nil {
		t.Errorf("Close nil writer: %v", err)
	}
}
