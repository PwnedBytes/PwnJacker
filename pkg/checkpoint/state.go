package checkpoint

import (
    "time"
)

// ScanState represents the state of a scan at a point in time.
type ScanState struct {
    CompletedDomains []string               `json:"completed_domains"`
    PendingDomains   []string               `json:"pending_domains"`
    Findings         []*Finding              `json:"findings,omitempty"`
    Timestamp        time.Time               `json:"timestamp"`
    Metadata         map[string]interface{}  `json:"metadata,omitempty"`
}

// Finding is a lightweight representation for checkpointing.
type Finding struct {
    Domain      string    `json:"domain"`
    Type        string    `json:"type"`
    Service     string    `json:"service"`
    Severity    string    `json:"severity"`
    Discovered  time.Time `json:"discovered"`
}