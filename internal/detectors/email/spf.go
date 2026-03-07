package email

import (
    "context"
    "fmt"
    "net"
    "strings"
    "time"

    "PwnJacker/internal/models"
)

type SPFDetector struct {
    name    string
    enabled bool
}

func NewSPFDetector() *SPFDetector {
    return &SPFDetector{
        name:    "SPF Detector",
        enabled: true,
    }
}

func (d *SPFDetector) Name() string {
    return d.name
}

func (d *SPFDetector) IsEnabled() bool {
    return d.enabled
}

func (d *SPFDetector) Detect(ctx context.Context, domain string) *models.Vulnerability {
    // Get SPF record
    spfRecord, err := d.getSPFRecord(domain)
    if err != nil {
        return nil
    }

    issues := d.analyzeSPF(spfRecord)
    if len(issues) == 0 {
        return nil
    }

    return &models.Vulnerability{
        Domain:      domain,
        Type:        "Email Security - SPF Misconfiguration",
        Service:     "SPF",
        Severity:    d.calculateSeverity(issues),
        Description: fmt.Sprintf("SPF record has security issues: %s", strings.Join(issues, ", ")),
        Evidence: map[string]string{
            "spf_record": spfRecord,
            "issues":     strings.Join(issues, "\n"),
        },
        Remediation: d.getRemediation(issues),
        Discovered:  time.Now(),
        Verified:    true,
    }
}

func (d *SPFDetector) getSPFRecord(domain string) (string, error) {
    txtRecords, err := net.LookupTXT(domain)
    if err != nil {
        return "", err
    }

    for _, record := range txtRecords {
        if strings.HasPrefix(record, "v=spf1") {
            return record, nil
        }
    }

    return "", fmt.Errorf("no SPF record found")
}

func (d *SPFDetector) analyzeSPF(record string) []string {
    var issues []string

    // Check for overly permissive mechanisms
    if strings.Contains(record, "+all") {
        issues = append(issues, "Overly permissive: +all allows any server to send email")
    }
    
    if strings.Contains(record, "?all") {
        issues = append(issues, "Neutral policy: ?all provides no enforcement")
    }
    
    if !strings.Contains(record, "-all") && !strings.Contains(record, "~all") {
        issues = append(issues, "Missing hard/soft fail: consider using -all or ~all")
    }

    // Check for includes that might be vulnerable
    parts := strings.Fields(record)
    for _, part := range parts {
        if strings.HasPrefix(part, "include:") {
            includedDomain := strings.TrimPrefix(part, "include:")
            if d.isDomainVulnerable(includedDomain) {
                issues = append(issues, fmt.Sprintf("Included domain %s may be vulnerable", includedDomain))
            }
        }
    }

    // Check for missing SPF
    if record == "" {
        issues = append(issues, "No SPF record found")
    }

    // Check for multiple SPF records
    // This would need to be handled at a higher level

    return issues
}

func (d *SPFDetector) isDomainVulnerable(domain string) bool {
    // Check if the included domain has SPF issues
    // This is a simplified check
    _, err := d.getSPFRecord(domain)
    return err != nil
}

func (d *SPFDetector) calculateSeverity(issues []string) models.Severity {
    for _, issue := range issues {
        if strings.Contains(issue, "+all") || strings.Contains(issue, "vulnerable") {
            return models.SeverityCritical
        }
    }
    return models.SeverityMedium
}

func (d *SPFDetector) getRemediation(issues []string) string {
    remediation := "SPF Configuration Issues:\n"
    for i, issue := range issues {
        remediation += fmt.Sprintf("%d. %s\n", i+1, issue)
    }
    
    remediation += "\nRecommended fixes:\n"
    remediation += "- Use '-all' to hard-fail unauthorized senders\n"
    remediation += "- Remove any '+all' or '?all' mechanisms\n"
    remediation += "- Regularly audit included domains\n"
    remediation += "- Keep SPF records under the 10 DNS lookup limit\n"
    
    return remediation
}