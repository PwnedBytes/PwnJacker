package http

import (
    "regexp"
    "strings"

    "PwnJacker/internal/models"
)

type JSAnalyzer struct {
    domainRegex *regexp.Regexp
    urlRegex    *regexp.Regexp
}

func NewJSAnalyzer() *JSAnalyzer {
    return &JSAnalyzer{
        domainRegex: regexp.MustCompile(`([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}`),
        urlRegex:    regexp.MustCompile(`https?://[^\s"'<>]+`),
    }
}

func (j *JSAnalyzer) Analyze(jsContent string, baseDomain string) []*models.OrphanedResource {
    var findings []*models.OrphanedResource

    // Extract all domains from JS
    domains := j.extractDomains(jsContent)
    
    // Extract hardcoded URLs
    urls := j.extractURLs(jsContent)

    // Check for API endpoints
    apiEndpoints := j.extractAPIEndpoints(jsContent)

    for _, domain := range domains {
        if domain != baseDomain && !strings.HasSuffix(domain, "."+baseDomain) {
            findings = append(findings, &models.OrphanedResource{
                Type:        "External Domain Reference",
                Resource:    domain,
                Context:     "hardcoded in JavaScript",
                RiskLevel:   "MEDIUM",
                Description: "JavaScript references external domain that could become vulnerable",
            })
        }
    }

    for _, url := range urls {
        if strings.Contains(url, "api.") || strings.Contains(url, "cdn.") {
            findings = append(findings, &models.OrphanedResource{
                Type:        "Hardcoded URL",
                Resource:    url,
                Context:     "JavaScript contains hardcoded URL",
                RiskLevel:   "HIGH",
                Description: "Hardcoded URLs can lead to dependency hijacking",
            })
        }
    }

    for _, endpoint := range apiEndpoints {
        findings = append(findings, &models.OrphanedResource{
            Type:        "API Endpoint",
            Resource:    endpoint,
            Context:     "JavaScript makes API calls",
            RiskLevel:   "CRITICAL",
            Description: "API endpoints in JavaScript could expose internal services",
        })
    }

    return findings
}

func (j *JSAnalyzer) extractDomains(content string) []string {
    matches := j.domainRegex.FindAllString(content, -1)
    
    // Deduplicate
    seen := make(map[string]bool)
    var domains []string
    
    for _, match := range matches {
        if !seen[match] {
            seen[match] = true
            domains = append(domains, match)
        }
    }
    
    return domains
}

func (j *JSAnalyzer) extractURLs(content string) []string {
    matches := j.urlRegex.FindAllString(content, -1)
    
    // Deduplicate
    seen := make(map[string]bool)
    var urls []string
    
    for _, match := range matches {
        if !seen[match] {
            seen[match] = true
            urls = append(urls, match)
        }
    }
    
    return urls
}

func (j *JSAnalyzer) extractAPIEndpoints(content string) []string {
    var endpoints []string
    
    // Common API patterns
    patterns := []string{
        `fetch\(['"]([^'"]+)['"]\)`,
        `axios\.(?:get|post|put|delete)\(['"]([^'"]+)['"]\)`,
        `\$\.[a-z]+\(['"]([^'"]+)['"]\)`,
        `XMLHttpRequest.*open\(['"][A-Z]+['"],\s*['"]([^'"]+)['"]`,
        `http\.(?:get|post)\(['"]([^'"]+)['"]\)`,
        `api\.call\(['"]([^'"]+)['"]\)`,
    }

    for _, pattern := range patterns {
        re := regexp.MustCompile(pattern)
        matches := re.FindAllStringSubmatch(content, -1)
        for _, match := range matches {
            if len(match) > 1 {
                endpoints = append(endpoints, match[1])
            }
        }
    }

    return endpoints
}