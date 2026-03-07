package wildcard

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "net"
    "strings"
    "time"

    "PwnJacker/internal/models"
)

type Detector struct {
    name     string
    enabled  bool
    resolver *net.Resolver
}

func NewDetector() *Detector {
    return &Detector{
        name:     "Wildcard Detector",
        enabled:  true,
        resolver: net.DefaultResolver,
    }
}

func (d *Detector) Name() string {
    return d.name
}

func (d *Detector) IsEnabled() bool {
    return d.enabled
}

func (d *Detector) Detect(ctx context.Context, domain string) *models.Vulnerability {
    // Generate random subdomain
    randomSub := d.generateRandomSub() + "." + domain

    // Check if random subdomain resolves
    ips, err := d.resolver.LookupIPAddr(ctx, randomSub)
    if err != nil {
        return nil // No wildcard detected
    }

    if len(ips) == 0 {
        return nil
    }

    // Get IPs of actual domain for comparison
    actualIPs, _ := d.resolver.LookupIPAddr(ctx, domain)

    // Check if wildcard returns same IPs
    if d.compareIPs(ips, actualIPs) {
        return &models.Vulnerability{
            Domain:      domain,
            Type:        "Wildcard DNS",
            Service:     "DNS Wildcard",
            Severity:    models.SeverityMedium,
            Description: "Domain uses wildcard DNS - all subdomains resolve",
            Evidence: map[string]string{
                "test_subdomain": randomSub,
                "resolved_ips":   d.formatIPs(ips),
                "base_domain_ips": d.formatIPs(actualIPs),
            },
            Remediation: "Review wildcard usage - ensure it's intentional and properly configured",
            References: []string{
                "https://hackerone.com/reports/1699437",
                "https://cwe.mitre.org/data/definitions/350.html",
            },
            Discovered: time.Now(),
            Verified:   true,
        }
    }

    return nil
}

func (d *Detector) generateRandomSub() string {
    bytes := make([]byte, 8)
    rand.Read(bytes)
    return hex.EncodeToString(bytes)
}

func (d *Detector) compareIPs(ips1, ips2 []net.IPAddr) bool {
    if len(ips1) != len(ips2) {
        return false
    }

    ipMap := make(map[string]bool)
    for _, ip := range ips1 {
        ipMap[ip.IP.String()] = true
    }

    for _, ip := range ips2 {
        if !ipMap[ip.IP.String()] {
            return false
        }
    }

    return true
}

func (d *Detector) formatIPs(ips []net.IPAddr) string {
    var strs []string
    for _, ip := range ips {
        strs = append(strs, ip.IP.String())
    }
    return strings.Join(strs, ", ")
}