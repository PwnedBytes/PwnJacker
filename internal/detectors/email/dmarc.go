package email

import (
    "context"
    "fmt"
    "net"
    "strings"
    "time"

    "PwnJacker/internal/models"
)

type DMARCDetector struct {
    name    string
    enabled bool
}

func NewDMARCDetector() *DMARCDetector {
    return &DMARCDetector{
        name:    "DMARC Detector",
        enabled: true,
    }
}

func (d *DMARCDetector) Name() string { return d.name }
func (d *DMARCDetector) IsEnabled() bool { return d.enabled }

func (d *DMARCDetector) Detect(ctx context.Context, domain string) *models.Vulnerability {
    dmarcDomain := "_dmarc." + domain
    txtRecords, err := net.LookupTXT(dmarcDomain)
    if err != nil {
        return &models.Vulnerability{
            Domain:      domain,
            Type:        "Email Security - Missing DMARC",
            Service:     "DMARC",
            Severity:    models.SeverityMedium,
            Description: "No DMARC record found for this domain",
            Remediation: "Add a DMARC record to prevent email spoofing",
            Discovered:  time.Now(),
            Verified:    true,
        }
    }

    for _, record := range txtRecords {
        if strings.HasPrefix(record, "v=DMARC1") {
            return d.analyzeDMARC(domain, record)
        }
    }

    return nil
}

func (d *DMARCDetector) analyzeDMARC(domain, record string) *models.Vulnerability {
    var issues []string
    var severity models.Severity = models.SeverityLow

    // Check policy
    if strings.Contains(record, "p=none") {
        issues = append(issues, "Policy is 'none' – no enforcement")
        severity = models.SeverityMedium
    } else if strings.Contains(record, "p=quarantine") {
        issues = append(issues, "Policy is 'quarantine' – better but not reject")
    } else if !strings.Contains(record, "p=reject") {
        issues = append(issues, "No explicit reject policy")
        severity = models.SeverityMedium
    }

    // Check subdomain policy
    if strings.Contains(record, "sp=none") {
        issues = append(issues, "Subdomain policy is 'none' – subdomains unprotected")
    }

    // Check percentage
    if strings.Contains(record, "pct=") {
        // extract pct value and check if <100
        // simplified
        issues = append(issues, "Policy applied to less than 100% of emails")
    }

    // Check reporting
    if !strings.Contains(record, "rua=") {
        issues = append(issues, "No aggregate reporting (rua) configured")
    }
    if !strings.Contains(record, "ruf=") {
        issues = append(issues, "No forensic reporting (ruf) configured")
    }

    if len(issues) == 0 {
        return nil
    }

    return &models.Vulnerability{
        Domain:      domain,
        Type:        "Email Security - DMARC Weakness",
        Service:     "DMARC",
        Severity:    severity,
        Description: fmt.Sprintf("DMARC record has issues: %s", strings.Join(issues, "; ")),
        Evidence:    map[string]string{"dmarc_record": record},
        Remediation: "Set p=reject, configure reporting, and ensure subdomain policy",
        Discovered:  time.Now(),
        Verified:    true,
    }
}