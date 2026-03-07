package http

import (
    "strings"

    "PwnJacker/internal/models"
)

// AnalyzeSecurityHeaders checks for missing or misconfigured security headers
func AnalyzeSecurityHeaders(headers map[string]string) []models.Misconfiguration {
    var issues []models.Misconfiguration

    // Check HSTS
    if hsts, ok := headers["strict-transport-security"]; !ok {
        issues = append(issues, models.Misconfiguration{
            Type:        "Missing HSTS",
            Severity:    "MEDIUM",
            Description: "HTTP Strict Transport Security header not set",
            Remediation: "Add Strict-Transport-Security header with appropriate max-age",
        })
    } else if !strings.Contains(hsts, "includeSubDomains") {
        issues = append(issues, models.Misconfiguration{
            Type:        "HSTS Without includeSubDomains",
            Severity:    "LOW",
            Description: "HSTS does not cover subdomains",
            Remediation: "Add 'includeSubDomains' directive",
        })
    }

    // Check CSP
    if _, ok := headers["content-security-policy"]; !ok {
        issues = append(issues, models.Misconfiguration{
            Type:        "Missing CSP",
            Severity:    "MEDIUM",
            Description: "Content Security Policy header not set",
            Remediation: "Implement a CSP to mitigate XSS and data injection",
        })
    }

    // Check X-Frame-Options
    if _, ok := headers["x-frame-options"]; !ok {
        issues = append(issues, models.Misconfiguration{
            Type:        "Missing X-Frame-Options",
            Severity:    "MEDIUM",
            Description: "Page can be embedded in iframes (clickjacking risk)",
            Remediation: "Set X-Frame-Options: DENY or SAMEORIGIN",
        })
    }

    // Check X-Content-Type-Options
    if xcto, ok := headers["x-content-type-options"]; !ok || xcto != "nosniff" {
        issues = append(issues, models.Misconfiguration{
            Type:        "Missing X-Content-Type-Options",
            Severity:    "LOW",
            Description: "Browser may MIME-sniff responses, leading to security issues",
            Remediation: "Set X-Content-Type-Options: nosniff",
        })
    }

    // Check Referrer-Policy
    if _, ok := headers["referrer-policy"]; !ok {
        issues = append(issues, models.Misconfiguration{
            Type:        "Missing Referrer-Policy",
            Severity:    "LOW",
            Description: "Referrer information may leak in cross-origin requests",
            Remediation: "Set a strict Referrer-Policy like 'no-referrer' or 'same-origin'",
        })
    }

    // Check Permissions-Policy
    if _, ok := headers["permissions-policy"]; !ok {
        issues = append(issues, models.Misconfiguration{
            Type:        "Missing Permissions-Policy",
            Severity:    "INFO",
            Description: "No feature policy set, potentially allowing unused permissions",
            Remediation: "Consider setting Permissions-Policy to restrict sensitive features",
        })
    }

    return issues
}