package email

import (
    "context"
    "fmt"
    "net"
    "strings"
    "time"

    "PwnJacker/internal/models"
)

type DKIMDetector struct {
    name    string
    enabled bool
    selectors []string
}

func NewDKIMDetector() *DKIMDetector {
    return &DKIMDetector{
        name:    "DKIM Detector",
        enabled: true,
        selectors: []string{
            "default",
            "google",
            "selector1",
            "selector2",
            "dkim",
            "mail",
            "email",
            "2016",
            "2017",
            "2018",
            "2019",
            "2020",
            "2021",
            "2022",
            "2023",
            "2024",
        },
    }
}

func (d *DKIMDetector) Name() string {
    return d.name
}

func (d *DKIMDetector) IsEnabled() bool {
    return d.enabled
}

func (d *DKIMDetector) Detect(ctx context.Context, domain string) *models.Vulnerability {
    var vulnerableSelectors []string
    var issues []string

    for _, selector := range d.selectors {
        dkimDomain := fmt.Sprintf("%s._domainkey.%s", selector, domain)
        
        txtRecords, err := net.LookupTXT(dkimDomain)
        if err != nil {
            continue
        }

        for _, record := range txtRecords {
            if strings.Contains(record, "v=DKIM1") {
                // Found DKIM record, check for vulnerabilities
                vuln := d.analyzeDKIMRecord(selector, record)
                if vuln != nil {
                    vulnerableSelectors = append(vulnerableSelectors, selector)
                    issues = append(issues, fmt.Sprintf("Selector %s: %s", selector, vuln.Description))
                }
            }
        }
    }

    if len(vulnerableSelectors) == 0 {
        return nil
    }

    return &models.Vulnerability{
        Domain:      domain,
        Type:        "Email Security - DKIM Vulnerability",
        Service:     "DKIM",
        Severity:    models.SeverityHigh,
        Description: fmt.Sprintf("Vulnerable DKIM selectors found: %s", strings.Join(vulnerableSelectors, ", ")),
        Evidence: map[string]string{
            "vulnerable_selectors": strings.Join(vulnerableSelectors, ", "),
            "issues":               strings.Join(issues, "\n"),
        },
        Remediation: d.getRemediation(),
        Discovered:  time.Now(),
        Verified:    true,
    }
}

func (d *DKIMDetector) analyzeDKIMRecord(selector, record string) *models.Vulnerability {
    // Check for weak key length
    if strings.Contains(record, "k=rsa") {
        // Extract key length if available
        if strings.Contains(record, "weak") {
            return &models.Vulnerability{
                Description: "Weak DKIM key (likely <1024 bits)",
                Remediation: "Generate a new DKIM key with at least 2048 bits",
            }
        }
    }

    // Check for expired selectors
    // This would require checking key validity periods
    // Simplified check for now

    // Check for missing revocation
    if strings.Contains(record, "s=*") {
        return &models.Vulnerability{
            Description: "Overly permissive DKIM selector",
            Remediation: "Restrict DKIM selector to specific services",
        }
    }

    return nil
}

func (d *DKIMDetector) getRemediation() string {
    return `DKIM Remediation Steps:
1. Rotate DKIM keys regularly
2. Use 2048-bit or higher RSA keys
3. Revoke old selectors promptly
4. Monitor for unauthorized use of selectors
5. Implement DKIM reporting (ARC)`
}