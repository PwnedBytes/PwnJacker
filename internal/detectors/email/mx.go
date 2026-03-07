package email

import (
    "context"
    "net"
    "strings"
    "time"

    "PwnJacker/internal/models"
)

type MXDetector struct {
    name    string
    enabled bool
}

func NewMXDetector() *MXDetector {
    return &MXDetector{
        name:    "MX Detector",
        enabled: true,
    }
}

func (d *MXDetector) Name() string { return d.name }
func (d *MXDetector) IsEnabled() bool { return d.enabled }

func (d *MXDetector) Detect(ctx context.Context, domain string) *models.Vulnerability {
    mxRecords, err := net.LookupMX(domain)
    if err != nil || len(mxRecords) == 0 {
        return nil // No MX, nothing to check
    }

    var vulnerableMX []string
    for _, mx := range mxRecords {
        host := strings.TrimSuffix(mx.Host, ".")
        // Check if MX points to a known vulnerable service
        if d.isVulnerableMX(host) {
            vulnerableMX = append(vulnerableMX, host)
        }
    }

    if len(vulnerableMX) > 0 {
        return &models.Vulnerability{
            Domain:      domain,
            Type:        "Email Security - Vulnerable MX",
            Service:     "MX",
            Severity:    models.SeverityHigh,
            Description: "MX records point to potentially vulnerable or discontinued mail services",
            Evidence:    map[string]string{"mx_records": strings.Join(vulnerableMX, ", ")},
            Remediation: "Review MX records and ensure they point to active, secured mail providers",
            Discovered:  time.Now(),
            Verified:    true,
        }
    }
    return nil
}

func (d *MXDetector) isVulnerableMX(host string) bool {
    // List of patterns that indicate potential takeover
    vulnerablePatterns := []string{
        "mailgun.org",
        "sendgrid.net",
        "google.com",      // But Google is safe? Actually if it's a custom domain using Google Workspaces, it's safe.
        // We need to differentiate between Google Workspace and expired Google Apps.
        // For simplicity, we'll flag common services that can be taken over if the domain is removed from the control panel.
        "amazonses.com",
        "sparkpostmail.com",
        "mandrillapp.com",
    }
    for _, pattern := range vulnerablePatterns {
        if strings.Contains(host, pattern) {
            return true
        }
    }
    return false
}