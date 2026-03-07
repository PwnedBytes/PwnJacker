package cloud

import (
    "context"
    "fmt"
    "net/http"
    "strings"
    "time"

    "PwnJacker/internal/models"
)

type AzureDetector struct {
    name       string
    enabled    bool
    httpClient *http.Client
}

func NewAzureDetector() *AzureDetector {
    return &AzureDetector{
        name:    "Azure Cloud Detector",
        enabled: true,
        httpClient: &http.Client{
            Timeout: 10 * time.Second,
            CheckRedirect: func(req *http.Request, via []*http.Request) error {
                return http.ErrUseLastResponse
            },
        },
    }
}

func (d *AzureDetector) Name() string { return d.name }
func (d *AzureDetector) IsEnabled() bool { return d.enabled }

func (d *AzureDetector) Detect(ctx context.Context, domain string) *models.Vulnerability {
    // Check Azure App Service
    if vuln := d.checkAppService(ctx, domain); vuln != nil {
        return vuln
    }
    // Check Azure CDN
    if vuln := d.checkCDN(ctx, domain); vuln != nil {
        return vuln
    }
    // Check Azure Blob Storage
    if vuln := d.checkBlobStorage(ctx, domain); vuln != nil {
        return vuln
    }
    return nil
}

func (d *AzureDetector) checkAppService(ctx context.Context, domain string) *models.Vulnerability {
    url := fmt.Sprintf("https://%s", domain)
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return nil
    }
    resp, err := d.httpClient.Do(req)
    if err != nil {
        return nil
    }
    defer resp.Body.Close()

    if resp.StatusCode == 404 {
        // Look for Azure specific signature
        server := resp.Header.Get("Server")
        if strings.Contains(server, "Microsoft-IIS") || strings.Contains(server, "Azure") {
            return &models.Vulnerability{
                Domain:      domain,
                Type:        "Azure App Service Takeover",
                Service:     "Azure App Service",
                Severity:    models.SeverityCritical,
                Description: "Azure App Service returns 404 – the app may be deleted",
                Evidence: map[string]string{
                    "status": fmt.Sprintf("%d", resp.StatusCode),
                    "server": server,
                },
                Remediation: "Recreate the App Service or remove the DNS record",
                Discovered:  time.Now(),
                Verified:    true,
            }
        }
    }
    return nil
}

func (d *AzureDetector) checkCDN(ctx context.Context, domain string) *models.Vulnerability {
    // Azure CDN endpoints often have .azureedge.net
    if !strings.Contains(domain, ".azureedge.net") {
        return nil
    }
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
            Type:        "Azure CDN Takeover",
            Service:     "Azure CDN",
            Severity:    models.SeverityHigh,
            Description: "Azure CDN endpoint does not exist",
            Evidence:    map[string]string{"status": "404"},
            Remediation: "Recreate the CDN endpoint or remove DNS",
            Discovered:  time.Now(),
            Verified:    true,
        }
    }
    return nil
}

func (d *AzureDetector) checkBlobStorage(ctx context.Context, domain string) *models.Vulnerability {
    // Azure Blob Storage: *.blob.core.windows.net
    if !strings.Contains(domain, ".blob.core.windows.net") {
        return nil
    }
    // Extract container name
    parts := strings.Split(domain, ".")
    if len(parts) < 1 {
        return nil
    }
    container := parts[0]
    url := fmt.Sprintf("https://%s.blob.core.windows.net/%s", container, container)
    req, _ := http.NewRequestWithContext(ctx, "HEAD", url, nil)
    resp, err := d.httpClient.Do(req)
    if err != nil {
        return nil
    }
    defer resp.Body.Close()

    if resp.StatusCode == 404 {
        return &models.Vulnerability{
            Domain:      domain,
            Type:        "Azure Blob Storage Takeover",
            Service:     "Azure Blob",
            Severity:    models.SeverityCritical,
            Description: "Blob container does not exist",
            Evidence:    map[string]string{"status": "404"},
            Remediation: "Create the blob container or remove DNS",
            Discovered:  time.Now(),
            Verified:    true,
        }
    }
    return nil
}