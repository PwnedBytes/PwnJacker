package dashboard

import (
    "sync"
    "time"

    "PwnJacker/internal/models"
)

// Stats holds real-time scan statistics.
type Stats struct {
    DomainsScanned   int            `json:"domains_scanned"`
    Vulnerabilities  int            `json:"vulnerabilities"`
    BySeverity       map[string]int `json:"by_severity"`
    ByService        map[string]int `json:"by_service"`
    StartTime        time.Time      `json:"start_time"`
    CriticalCount    int            `json:"critical_count"`
    HighCount        int            `json:"high_count"`
    MediumCount      int            `json:"medium_count"`
    LowCount         int            `json:"low_count"`
    mu               sync.RWMutex
}

// NewStats creates a new Stats instance.
func NewStats() *Stats {
    return &Stats{
        BySeverity: make(map[string]int),
        ByService:  make(map[string]int),
        StartTime:  time.Now(),
    }
}

// AddFinding updates stats with a new finding.
func (s *Stats) AddFinding(finding *models.Vulnerability) {
    s.mu.Lock()
    defer s.mu.Unlock()

    s.Vulnerabilities++
    s.BySeverity[string(finding.Severity)]++
    s.ByService[finding.Service]++

    switch finding.Severity {
    case models.SeverityCritical:
        s.CriticalCount++
    case models.SeverityHigh:
        s.HighCount++
    case models.SeverityMedium:
        s.MediumCount++
    case models.SeverityLow:
        s.LowCount++
    }
}

// SetDomainsScanned updates the count of scanned domains.
func (s *Stats) SetDomainsScanned(count int) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.DomainsScanned = count
}