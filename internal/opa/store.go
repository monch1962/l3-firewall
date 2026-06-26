package opa

import (
	"encoding/json"
	"sync"
)

// DataStore manages OPA data parameters that are injected as data.params.
// Thread-safe for concurrent read/write from the engine and admin API.
type DataStore struct {
	mu     sync.RWMutex
	params map[string]interface{}
}

// NewDataStore creates a DataStore initialized with an empty params map.
func NewDataStore() *DataStore {
	return &DataStore{
		params: make(map[string]interface{}),
	}
}

// GetParams returns a copy of the current parameters.
func (s *DataStore) GetParams() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]interface{}, len(s.params))
	for k, v := range s.params {
		result[k] = v
	}
	return result
}

// SetParams replaces all parameters atomically.
func (s *DataStore) SetParams(params map[string]interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.params = make(map[string]interface{}, len(params))
	for k, v := range params {
		s.params[k] = v
	}
}

// LoadParamsFromJSON parses JSON bytes and merges them into the store.
func (s *DataStore) LoadParamsFromJSON(data []byte) error {
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range parsed {
		s.params[k] = v
	}
	return nil
}
