package nxdomain

import (
    "net"
    "strings"
)

// AnalyzeRegistration checks if an NXDOMAIN domain is available for registration.
func AnalyzeRegistration(domain string) (bool, error) {
    // This would integrate with WHOIS or domain registration APIs.
    // For now, return true if it's a common TLD and not a subdomain of a known registered domain.
    // Simplified implementation:
    if strings.Count(domain, ".") == 1 {
        // It's a second-level domain, potentially registerable.
        return true, nil
    }
    return false, nil
}

// AnalyzeReservedIP checks if IPs are in reserved ranges.
func AnalyzeReservedIP(ips []net.IP) []string {
    var reserved []string
    for _, ip := range ips {
        if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
            reserved = append(reserved, ip.String())
        }
    }
    return reserved
}