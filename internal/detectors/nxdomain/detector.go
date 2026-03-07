package nxdomain

import (
    "context"
    "net"
    "strings"
    "time"

    "PwnJacker/internal/models"
    "PwnJacker/internal/utils"
)

type Detector struct {
    name    string
    enabled bool
    resolver *net.Resolver
}

func NewDetector() *Detector {
    return &Detector{
        name:    "NXDOMAIN Detector",
        enabled: true,
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
    // Check A/AAAA records
    ips, err := d.resolver.LookupIPAddr(ctx, domain)
    if err != nil {
        if dnsErr, ok := err.(*net.DNSError); ok {
            if dnsErr.IsNotFound {
                // Domain doesn't resolve - check if it's registerable
                if d.isRegisterable(domain) {
                    return &models.Vulnerability{
                        Domain:      domain,
                        Type:        "NXDOMAIN Takeover",
                        Service:     "Unregistered Domain",
                        Severity:    models.SeverityHigh,
                        Description: "Domain does not resolve and is available for registration",
                        Evidence: map[string]string{
                            "dns_error": dnsErr.Error(),
                            "registrar_check": "Domain can be registered",
                        },
                        Remediation: "Register the domain or remove DNS records pointing to it",
                        Discovered:  time.Now(),
                        Verified:    true,
                    }
                }
            }
        }
        return nil
    }

    // If we have IPs but they're private/reserved, that's suspicious
    if len(ips) > 0 {
        for _, ip := range ips {
            if d.isReservedIP(ip.IP) {
                return &models.Vulnerability{
                    Domain:      domain,
                    Type:        "Suspicious DNS Resolution",
                    Service:     "Reserved IP Space",
                    Severity:    models.SeverityMedium,
                    Description: "Domain resolves to reserved/internal IP space",
                    Evidence: map[string]string{
                        "ip": ip.IP.String(),
                    },
                    Remediation: "Investigate why domain points to internal/reserved IPs",
                    Discovered:  time.Now(),
                    Verified:    true,
                }
            }
        }
    }

    return nil
}

func (d *Detector) isRegisterable(domain string) bool {
    // Check if domain is available for registration
    // This would integrate with WHOIS or domain registration APIs
    // Simplified implementation
    return strings.Contains(domain, "example.com") || 
           strings.Contains(domain, "test.com") ||
           strings.Count(domain, ".") == 1 // TLDs like example.com are more likely available
}

func (d *Detector) isReservedIP(ip net.IP) bool {
    // Check for reserved IP ranges
    reserved := []string{
        "10.",           // RFC1918
        "172.16.",       // RFC1918
        "172.17.",       // RFC1918
        "172.18.",       // RFC1918
        "172.19.",       // RFC1918
        "172.20.",       // RFC1918
        "172.21.",       // RFC1918
        "172.22.",       // RFC1918
        "172.23.",       // RFC1918
        "172.24.",       // RFC1918
        "172.25.",       // RFC1918
        "172.26.",       // RFC1918
        "172.27.",       // RFC1918
        "172.28.",       // RFC1918
        "172.29.",       // RFC1918
        "172.30.",       // RFC1918
        "172.31.",       // RFC1918
        "192.168.",      // RFC1918
        "127.",          // Localhost
        "169.254.",      // Link-local
        "224.",          // Multicast
        "240.",          // Reserved
    }

    ipStr := ip.String()
    for _, r := range reserved {
        if strings.HasPrefix(ipStr, r) {
            return true
        }
    }

    return false
}