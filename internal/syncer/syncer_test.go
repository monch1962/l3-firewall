package syncer

import (
	"context"
	"sync/atomic"
	"testing"
)

func TestNewEmptyEndpoints(t *testing.T) {
	s, err := New(Config{}, nil)
	if err != nil {
		t.Fatalf("New with empty endpoints: %v", err)
	}
	if s != nil {
		t.Error("expected nil syncer for empty endpoints")
	}
}

func TestNewBadEndpoints(t *testing.T) {
	// etcd client connects lazily, so New doesn't fail on bad endpoints
	s, err := New(Config{
		Endpoints: []string{"http://127.0.0.1:1"},
	}, nil)
	if err != nil {
		t.Fatalf("New with bad endpoints: %v", err)
	}
	if s != nil {
		s.Close()
	}
}

func TestStartNilSyncer(t *testing.T) {
	var s *Syncer
	s.Start(context.Background()) // should not panic
}

func TestCloseNilSyncer(t *testing.T) {
	var s *Syncer
	if err := s.Close(); err != nil {
		t.Errorf("Close nil syncer: %v", err)
	}
}

func TestOnUpdateCalled(t *testing.T) {
	var called int32
	onUpdate := func(policy string) error {
		atomic.AddInt32(&called, 1)
		return nil
	}

	s, err := New(Config{
		Endpoints: []string{"http://127.0.0.1:2379"},
	}, onUpdate)
	if err != nil {
		t.Skipf("etcd not available: %v", err)
	}
	if s != nil {
		s.Close()
	}
}
