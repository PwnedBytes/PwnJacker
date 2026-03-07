package cloud

import (
    "context"
    "fmt"
    "net/http"
    "strings"
    "time"

    "PwnJacker/internal/models"
)

type DigitalOceanDetector struct {
    name       string
    enabled    bool
    httpClient *http.Client
}

func NewDigitalOceanDetector() *DigitalOceanDetector {
    return &DigitalOceanDetector{
        name:    "DigitalOcean Detector",
        enabled: true,
        httpClient: &http.Client{Timeout: 10 * time.Second},
    }
}

func (d *DigitalOceanDetector) Name() string { return d.name }
func (d *DigitalOceanDetector) IsEnabled() bool { return d.enabled }

func (d *DigitalOceanDetector) Detect(ctx context.Context, domain string) *models.Vulnerability {
    if strings.Contains(domain, ".ondigitalocean.app") {
        return d.checkAppPlatform(ctx, domain)
    }
    if strings.Contains(domain, ".digitaloceanspaces.com") {
        return d.checkSpaces(ctx, domain)
    }
    return nil
}

func (d *DigitalOceanDetector) checkAppPlatform(ctx context.Context, domain string) *models.Vulnerability {
    url := fmt.Sprintf("https://%s", domain)
    req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
    resp, err := d.httpClient.Do(req)
    if err != nil {
        return nil
    }
    defer resp.Body.Close()

    if resp.StatusCode == 404 {
        return &models.Vulnerability{
            Domain:      domain,
            Type:        "DigitalOcean App Platform Takeover",
            Service:     "DO App Platform",
            Severity:    models.SeverityHigh,
            Description: "App does not exist",
            Evidence:    map[string]string{"status": "404"},
            Remediation: "Recreate the app or remove DNS",
            Discovered:  time.Now(),
            Verified:    true,
        }
    }
    return nil
}

func (d *DigitalOceanDetector) checkSpaces(ctx context.Context, domain string) *models.Vulnerability {
    // Spaces: bucketname.region.digitaloceanspaces.com
    parts := strings.Split(domain, ".")
    if len(parts) < 2 {
        return nil
    }
    bucket := parts[0]
    url := fmt.Sprintf("https://%s.digitaloceanspaces.com/%s", bucket, bucket)
    req, _ := http.NewRequestWithContext(ctx, "HEAD", url, nil)
    resp, err := d.httpClient.Do(req)
    if err != nil {
        return nil
    }
    defer resp.Body.Close()

    if resp.StatusCode == 404 {
        return &models.Vulnerability{
            Domain:      domain,
            Type:        "DigitalOcean Spaces Takeover",
            Service:     "DO Spaces",
            Severity:    models.SeverityCritical,
            Description: "Spaces bucket does not exist",
            Evidence:    map[string]string{"status": "404"},
            Remediation: "Create the bucket or remove DNS",
            Discovered:  time.Now(),
            Verified:    true,
        }
    }
    return nil
}