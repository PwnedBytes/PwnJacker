package models

import "time"

type ScanConfig struct {
    ID              string        `json:"id"`
    Name            string        `json:"name"`
    Domains         []string      `json:"domains"`
    Threads         int           `json:"threads"`
    Timeout         time.Duration `json:"timeout"`
    CheckEmail      bool          `json:"check_email"`
    DeepScan        bool          `json:"deep_scan"`
    FingerprintOnly []string      `json:"fingerprint_only,omitempty"`
    ExcludeServices []string      `json:"exclude_services,omitempty"`
    CreatedAt       time.Time     `json:"created_at"`
    UpdatedAt       time.Time     `json:"updated_at"`
}

type ScanResult struct {
    ScanID        string           `json:"scan_id"`
    StartTime     time.Time        `json:"start_time"`
    EndTime       time.Time        `json:"end_time"`
    DomainsScanned int             `json:"domains_scanned"`
    Vulnerabilities []Vulnerability `json:"vulnerabilities"`
    Errors        []string         `json:"errors,omitempty"`
    Summary       ScanSummary      `json:"summary"`
}

type ScanSummary struct {
    TotalVulnerabilities int               `json:"total_vulnerabilities"`
    BySeverity          map[Severity]int   `json:"by_severity"`
    ByService           map[string]int     `json:"by_service"`
    ByType              map[string]int     `json:"by_type"`
    ScanDuration        time.Duration      `json:"scan_duration"`
    DomainsPerSecond    float64            `json:"domains_per_second"`
}