package main

import (
	"encoding/json"
	"os"
	"sync"
)

type ModuleStatus int

const (
	StatusPending ModuleStatus = iota
	StatusRunning
	StatusDone
	StatusFailed
	StatusSkipped
)

type ModuleState struct {
	Status ModuleStatus `json:"status"`
	Count  int          `json:"count"`
	Error  string       `json:"error,omitempty"`
}

type ScanState struct {
	mu      sync.RWMutex
	path    string
	Modules map[string]*ModuleState `json:"modules"`
}

func NewScanState(path string) *ScanState {
	s := &ScanState{
		path:    path,
		Modules: make(map[string]*ModuleState),
	}
	data, err := os.ReadFile(path)
	if err == nil {
		json.Unmarshal(data, s) //nolint:errcheck
	}
	return s
}

func (s *ScanState) IsDone(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.Modules[id]
	return ok && m.Status == StatusDone
}

func (s *ScanState) GetCount(id string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if m, ok := s.Modules[id]; ok {
		return m.Count
	}
	return 0
}

func (s *ScanState) SetRunning(id string) {
	s.set(id, StatusRunning, 0, "")
}

func (s *ScanState) SetDone(id string, count int) {
	s.set(id, StatusDone, count, "")
}

func (s *ScanState) SetFailed(id string, errStr string) {
	s.set(id, StatusFailed, 0, errStr)
}

func (s *ScanState) set(id string, status ModuleStatus, count int, errStr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Modules[id] = &ModuleState{Status: status, Count: count, Error: errStr}
	data, _ := json.MarshalIndent(s, "", "  ")
	os.WriteFile(s.path, data, 0644) //nolint:errcheck
}
