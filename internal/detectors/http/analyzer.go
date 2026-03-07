package http

import (
    "context"
    "crypto/md5"
    "encoding/hex"
    "fmt"
    "io"
    "net/http"
    "strings"
    "time"

    "PwnJacker/internal/models"
)

type Analyzer struct {
    client *http.Client
}

func NewAnalyzer() *Analyzer {
    return &Analyzer{
        client: &http.Client{
            Timeout: 10 * time.Second,
            CheckRedirect: func(req *http.Request, via []*http.Request) error {
                return http.ErrUseLastResponse
            },
        },
    }
}

func (a *Analyzer) Analyze(ctx context.Context, domain string) (*models.HTTPResponse, error) {
    // Try HTTPS first, then HTTP
    schemes := []string{"https://", "http://"}
    
    for _, scheme := range schemes {
        url := scheme + domain
        
        req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
        if err != nil {
            continue
        }

        req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; PwnJacker/1.0)")
        req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        req.Header.Set("Accept-Language", "en-US,en;q=0.5")
        req.Header.Set("Connection", "close")

        resp, err := a.client.Do(req)
        if err != nil {
            continue
        }
        defer resp.Body.Close()

        // Read body (limit to first 10KB)
        body, err := io.ReadAll(io.LimitReader(resp.Body, 10240))
        if err != nil {
            continue
        }

        // Calculate body hash for fingerprinting
        hash := md5.Sum(body)
        bodyHash := hex.EncodeToString(hash[:])

        // Extract title if HTML
        title := a.extractTitle(string(body))

        return &models.HTTPResponse{
            StatusCode:  resp.StatusCode,
            Headers:     a.headersToMap(resp.Header),
            Body:        string(body),
            BodyHash:    bodyHash,
            Title:       title,
            Server:      resp.Header.Get("Server"),
            ContentType: resp.Header.Get("Content-Type"),
        }, nil
    }

    return nil, fmt.Errorf("no response from %s", domain)
}

func (a *Analyzer) headersToMap(headers http.Header) map[string]string {
    result := make(map[string]string)
    for k, v := range headers {
        result[strings.ToLower(k)] = strings.Join(v, ", ")
    }
    return result
}

func (a *Analyzer) extractTitle(body string) string {
    // Simple title extraction
    lower := strings.ToLower(body)
    titleStart := strings.Index(lower, "<title>")
    if titleStart == -1 {
        return ""
    }
    titleStart += 7 // len("<title>")

    titleEnd := strings.Index(lower[titleStart:], "</title>")
    if titleEnd == -1 {
        return ""
    }

    title := body[titleStart : titleStart+titleEnd]
    return strings.TrimSpace(title)
}