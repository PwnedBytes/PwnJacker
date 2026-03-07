package output

import (
    "fmt"
    "os"
    "strings"
    "time"

    "PwnJacker/internal/models"
)

type MarkdownWriter struct{}

func NewMarkdownWriter() *MarkdownWriter {
    return &MarkdownWriter{}
}

func (w *MarkdownWriter) Write(findings []*models.Vulnerability, filename string) error {
    var content strings.Builder

    // Header
    content.WriteString("# PwnJacker Security Scan Report\n\n")
    content.WriteString(fmt.Sprintf("**Scan Date:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
    content.WriteString(fmt.Sprintf("**Total Vulnerabilities Found:** %d\n\n", len(findings)))

    // Summary Table
    content.WriteString("## Summary\n\n")
    content.WriteString("| Severity | Count |\n")
    content.WriteString("|----------|-------|\n")

    severityCount := map[models.Severity]int{
        models.SeverityCritical: 0,
        models.SeverityHigh:     0,
        models.SeverityMedium:   0,
        models.SeverityLow:      0,
        models.SeverityInfo:     0,
    }

    for _, f := range findings {
        severityCount[f.Severity]++
    }

    for severity, count := range severityCount {
        if count > 0 {
            content.WriteString(fmt.Sprintf("| %s | %d |\n", severity, count))
        }
    }

    // Findings
    content.WriteString("\n## Detailed Findings\n\n")

    for i, finding := range findings {
        content.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, finding.Domain))
        content.WriteString(fmt.Sprintf("- **Type:** %s\n", finding.Type))
        content.WriteString(fmt.Sprintf("- **Service:** %s\n", finding.Service))
        content.WriteString(fmt.Sprintf("- **Severity:** %s\n", finding.Severity))
        content.WriteString(fmt.Sprintf("- **Discovered:** %s\n", finding.Discovered.Format("2006-01-02 15:04:05")))
        
        if finding.Description != "" {
            content.WriteString(fmt.Sprintf("- **Description:** %s\n", finding.Description))
        }

        // Evidence
        if len(finding.Evidence) > 0 {
            content.WriteString("- **Evidence:**\n")
            for k, v := range finding.Evidence {
                content.WriteString(fmt.Sprintf("  - %s: %s\n", k, v))
            }
        }

        // DNS Records
        if len(finding.DNSRecords) > 0 {
            content.WriteString("- **DNS Records:**\n")
            for _, record := range finding.DNSRecords {
                content.WriteString(fmt.Sprintf("  - %s: %s → %s\n", record.Type, record.Name, record.Value))
            }
        }

        // Remediation
        if finding.Remediation != "" {
            content.WriteString(fmt.Sprintf("- **Remediation:** %s\n", finding.Remediation))
        }

        // References
        if len(finding.References) > 0 {
            content.WriteString("- **References:**\n")
            for _, ref := range finding.References {
                content.WriteString(fmt.Sprintf("  - %s\n", ref))
            }
        }

        // Proof of Concept
        if finding.ProofOfConcept != "" {
            content.WriteString(fmt.Sprintf("- **Proof of Concept:** `%s`\n", finding.ProofOfConcept))
        }

        content.WriteString("\n---\n\n")
    }

    return os.WriteFile(filename, []byte(content.String()), 0644)
}