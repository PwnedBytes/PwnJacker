package checkpoint

import (
    "encoding/json"
    "os"
    "sync"
    "time"
)

type ScanState struct {
    CompletedDomains []string               `json:"completed_domains"`
    PendingDomains   []string               `json:"pending_domains"`
    Findings         []*Finding              `json:"findings,omitempty"`
    Timestamp        time.Time               `json:"timestamp"`
    Metadata         map[string]interface{}  `json:"metadata,omitempty"`
}

type Finding struct {
    Domain      string    `json:"domain"`
    Type        string    `json:"type"`
    Service     string    `json:"service"`
    Severity    string    `json:"severity"`
    Discovered  time.Time `json:"discovered"`
}

type Manager struct {
    checkpointFile string
    mu             sync.RWMutex
    autoSave       bool
    saveInterval   int
}

func NewManager(checkpointFile string) *Manager {
    return &Manager{
        checkpointFile: checkpointFile,
        autoSave:       true,
        saveInterval:   100,
    }
}

func (m *Manager) Save(filename string, state *ScanState) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    data, err := json.MarshalIndent(state, "", "  ")
    if err != nil {
        return err
    }

    return os.WriteFile(filename, data, 0644)
}

func (m *Manager) Load(filename string, state *ScanState) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    data, err := os.ReadFile(filename)
    if err != nil {
        return err
    }

    return json.Unmarshal(data, state)
}

func (m *Manager) AutoSave(completed []string, pending []string, findings []*Finding) {
    if !m.autoSave {
        return
    }

    state := &ScanState{
        CompletedDomains: completed,
        PendingDomains:   pending,
        Findings:         findings,
        Timestamp:        time.Now(),
        Metadata: map[string]interface{}{
            "total":     len(completed) + len(pending),
            "completed": len(completed),
            "pending":   len(pending),
            "findings":  len(findings),
        },
    }

    m.Save(m.checkpointFile, state)
}

func (m *Manager) GetLatest() (*ScanState, error) {
    var state ScanState
    err := m.Load(m.checkpointFile, &state)
    if err != nil {
        return nil, err
    }
    return &state, nil
}

func (m *Manager) Clear() error {
    m.mu.Lock()
    defer m.mu.Unlock()

    return os.Remove(m.checkpointFile)
}

func (m *Manager) Exists() bool {
    _, err := os.Stat(m.checkpointFile)
    return err == nil
}