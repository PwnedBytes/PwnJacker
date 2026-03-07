package models

import "time"

// Report represents a scan report.
type Report struct {
    ID          string          `json:"id"`
    ScanID      string          `json:"scan_id"`
    CreatedAt   time.Time       `json:"created_at"`
    Format      string          `json:"format"` // json, html, pdf, etc.
    Path        string          `json:"path"`
    Findings    []Vulnerability `json:"findings"`
    Summary     ScanSummary     `json:"summary"`
}