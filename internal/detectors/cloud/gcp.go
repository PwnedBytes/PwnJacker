package cloud

import (
    "context"
    "fmt"
    "net/http"
    "strings"
    "time"

    "PwnJacker/internal/models"
)

type GCPDetector struct {
    name       string
    enabled    bool
    httpClient *http.Client
}

func NewGCPDetector() *GCPDetector {
    return &GCPDetector{
        name:    "Google Cloud Detector",
        enabled: true,
        httpClient: &http.Client{Timeout: 10 * time.Second},
    }
}

func (d *GCPDetector) Name() string { return d.name }
func (d *GCPDetector) IsEnabled() bool { return d.enabled }

func (d *GCPDetector) Detect(ctx context.Context, domain string) *models.Vulnerability {
    // GCS bucket via CNAME to c.storage.googleapis.com
    if strings.Contains(domain, "storage.googleapis.com") || strings.HasSuffix(domain, ".storage.googleapis.com") {
        return d.checkGCS(ctx, domain)
    }
    // App Engine
    if strings.Contains(domain, "appspot.com") {
        return d.checkAppEngine(ctx, domain)
    }
    // Firebase
    if strings.Contains(domain, "firebaseapp.com") {
        return d.checkFirebase(ctx, domain)
    }
    return nil
}

func (d *GCPDetector) checkGCS(ctx context.Context, domain string) *models.Vulnerability {
    // Extract bucket name from domain (first part)
    parts := strings.Split(domain, ".")
    bucket := parts[0]
    url := fmt.Sprintf("https://storage.googleapis.com/%s", bucket)
    req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
    resp, err := d.httpClient.Do(req)
    if err != nil {
        return nil
    }
    defer resp.Body.Close()

    if resp.StatusCode == 404 {
        return &models.Vulnerability{
            Domain:      domain,
            Type:        "Google Cloud Storage Takeover",
            Service:     "GCS",
            Severity:    models.SeverityCritical,
            Description: "GCS bucket does not exist",
            Evidence:    map[string]string{"status": "404"},
            Remediation: "Create the bucket or remove DNS",
            Discovered:  time.Now(),
            Verified:    true,
        }
    }
    return nil
}

func (d *GCPDetector) checkAppEngine(ctx context.Context, domain string) *models.Vulnerability {
    url := fmt.Sprintf("https://%s", domain)
    req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
    resp, err := d.httpClient.Do(req)
    if err != nil {
        return nil
    }
    defer resp.Body.Close()

    if resp.StatusCode == 404 {
        // App Engine returns a specific 404 page
        return &models.Vulnerability{
            Domain:      domain,
            Type:        "Google App Engine Takeover",
            Service:     "App Engine",
            Severity:    models.SeverityHigh,
            Description: "App Engine app not found",
            Evidence:    map[string]string{"status": "404"},
            Remediation: "Recreate the app or remove DNS",
            Discovered:  time.Now(),
            Verified:    true,
        }
    }
    return nil
}

func (d *GCPDetector) checkFirebase(ctx context.Context, domain string) *models.Vulnerability {
    url := fmt.Sprintf("https://%s", domain)
    req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
    resp, err := d.httpClient.Do(req)
    if err != nil {
        return nil
    }
    defer resp.Body.Close()

    if resp.StatusCode == 404 {
        // Firebase hosting returns a 404 for missing projects
        return &models.Vulnerability{
            Domain:      domain,
            Type:        "Firebase Hosting Takeover",
            Service:     "Firebase",
            Severity:    models.SeverityHigh,
            Description: "Firebase site does not exist",
            Evidence:    map[string]string{"status": "404"},
            Remediation: "Create the Firebase project or remove DNS",
            Discovered:  time.Now(),
            Verified:    true,
        }
    }
    return nil
}