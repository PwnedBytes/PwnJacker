package output

import (
    "encoding/json"
    "os"
    "time"

    "PwnJacker/internal/models"
)

type JSONWriter struct{}

func NewJSONWriter() *JSONWriter {
    return &JSONWriter{}
}

func (w *JSONWriter) Write(findings []*models.Vulnerability, filename string) error {
    output := struct {
        ScanTime    time.Time                    `json:"scan_time"`
        Total       int                           `json:"total_vulnerabilities"`
        Findings    []*models.Vulnerability       `json:"findings"`
        Summary     map[string]interface{}        `json:"summary"`
    }{
        ScanTime: time.Now(),
        Total:    len(findings),
        Findings: findings,
        Summary:  generateSummary(findings),
    }

    data, err := json.MarshalIndent(output, "", "  ")
    if err != nil {
        return err
    }

    return os.WriteFile(filename, data, 0644)
}

func generateSummary(findings []*models.Vulnerability) map[string]interface{} {
    summary := map[string]interface{}{
        "by_severity": make(map[string]int),
        "by_service":  make(map[string]int),
        "by_type":     make(map[string]int),
    }

    for _, f := range findings {
        bySeverity := summary["by_severity"].(map[string]int)
        byService := summary["by_service"].(map[string]int)
        byType := summary["by_type"].(map[string]int)

        bySeverity[string(f.Severity)]++
        byService[f.Service]++
        byType[f.Type]++
    }

    return summary
}