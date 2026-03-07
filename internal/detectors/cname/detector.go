package cname

import (
    "context"
    "fmt"
    "net"
    "net/http"
    "strings"
    "sync"
    "time"

    "PwnJacker/internal/models"
    "PwnJacker/internal/scanner/fingerprints"
    "PwnJacker/internal/utils"
)

type Detector struct {
    name         string
    enabled      bool
    fingerprintDB *fingerprints.Manager
    httpClient   *http.Client
    cache        sync.Map
}

func NewDetector() *Detector {
    return &Detector{
        name:    "CNAME Takeover Detector",
        enabled: true,
        fingerprintDB: fingerprints.NewManager(),
        httpClient: &http.Client{
            Timeout: 10 * time.Second,
            CheckRedirect: func(req *http.Request, via []*http.Request) error {
                return http.ErrUseLastResponse // Don't follow redirects
            },
        },
    }
}

func (d *Detector) Name() string {
    return d.name
}

func (d *Detector) IsEnabled() bool {
    return d.enabled
}

func (d *Detector) Detect(ctx context.Context, domain string) *models.Vulnerability {
    // Check cache first
    if cached, ok := d.cache.Load(domain); ok {
        if vuln, ok := cached.(*models.Vulnerability); ok {
            return vuln
        }
        return nil
    }

    // Get CNAME records
    cnames, err := d.getCNAMERecords(domain)
    if err != nil || len(cnames) == 0 {
        return nil
    }

    // Check each CNAME against fingerprints
    for _, cname := range cnames {
        if vuln := d.checkCNAME(ctx, domain, cname); vuln != nil {
            d.cache.Store(domain, vuln)
            return vuln
        }
    }

    d.cache.Store(domain, nil)
    return nil
}

func (d *Detector) getCNAMERecords(domain string) ([]string, error) {
    var cnames []string
    
    // Follow CNAME chain
    current := domain
    for {
        records, err := net.LookupCNAME(current)
        if err != nil {
            break
        }
        
        // Clean the record (remove trailing dot)
        record := strings.TrimSuffix(records, ".")
        
        // Check if it's a CNAME (not A/AAAA)
        if record != current {
            cnames = append(cnames, record)
            current = record
        } else {
            break
        }
        
        // Prevent infinite loops
        if len(cnames) > 10 {
            break
        }
    }
    
    return cnames, nil
}

func (d *Detector) checkCNAME(ctx context.Context, domain, cname string) *models.Vulnerability {
    // Find matching service by CNAME pattern
    service := d.fingerprintDB.MatchCNAME(cname)
    if service == nil {
        return nil
    }

    // Perform HTTP verification
    httpResp, err := d.checkHTTP(ctx, domain)
    if err != nil {
        return nil
    }

    // Verify response matches service fingerprint
    if !d.fingerprintDB.MatchResponse(service, httpResp) {
        return nil
    }

    // Create vulnerability
    vuln := &models.Vulnerability{
        Domain:      domain,
        Type:        "CNAME Takeover",
        Service:     service.Name,
        Severity:    models.SeverityHigh,
        Description: fmt.Sprintf("Subdomain points to unclaimed %s service", service.Name),
        Discovered:  time.Now(),
        Verified:    true,
        DNSRecords: []models.DNSRecord{
            {
                Type:    "CNAME",
                Name:    domain,
                Value:   cname,
                Service: service.Name,
            },
        },
        HTTPResponse: httpResp,
        Remediation:  service.Remediation,
        References:   service.References,
        ProofOfConcept: fmt.Sprintf("curl -H 'Host: %s' http://%s", domain, service.ClaimURL),
    }

    // Check if it's critical
    if strings.Contains(service.Name, "AWS") || strings.Contains(service.Name, "Azure") {
        vuln.Severity = models.SeverityCritical
    }

    return vuln
}

func (d *Detector) checkHTTP(ctx context.Context, domain string) (*models.HTTPResponse, error) {
    // Try HTTPS first, then HTTP
    schemes := []string{"https://", "http://"}
    
    for _, scheme := range schemes {
        url := scheme + domain
        
        req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
        if err != nil {
            continue
        }
        
        // Add common headers to avoid blocking
        req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; PwnJacker/1.0; +https://github.com/PwnedBytes/PwnJacker)")
        req.Header.Set("Accept", "*/*")
        
        resp, err := d.httpClient.Do(req)
        if err != nil {
            continue
        }
        defer resp.Body.Close()
        
        // Read first 1024 bytes of body for fingerprinting
        body := make([]byte, 1024)
        n, _ := resp.Body.Read(body)
        
        return &models.HTTPResponse{
            StatusCode: resp.StatusCode,
            Headers:    utils.HeadersToMap(resp.Header),
            Body:       string(body[:n]),
            Server:     resp.Header.Get("Server"),
            ContentType: resp.Header.Get("Content-Type"),
        }, nil
    }
    
    return nil, fmt.Errorf("no response from %s", domain)
}