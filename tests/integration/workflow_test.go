package integration

import (
    "bytes"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "PwnJacker/internal/dashboard"
    "PwnJacker/internal/models"
)

func TestFullScanWorkflow(t *testing.T) {
    // Setup test server
    results := make(chan *models.Vulnerability, 10)
    srv := dashboard.NewServer(":0", results)
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Route to dashboard handlers (simplified)
        switch r.URL.Path {
        case "/api/stats":
            srv.handleStats(w, r)
        case "/api/findings":
            srv.handleFindings(w, r)
        default:
            http.NotFound(w, r)
        }
    }))
    defer ts.Close()

    // Simulate a finding
    go func() {
        results <- &models.Vulnerability{
            Domain:   "test.example.com",
            Type:     "CNAME Takeover",
            Service:  "AWS S3",
            Severity: models.SeverityCritical,
        }
        close(results)
    }()

    // Test API endpoints
    resp, err := http.Get(ts.URL + "/api/stats")
    if err != nil {
        t.Fatal(err)
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        t.Errorf("expected 200, got %d", resp.StatusCode)
    }

    var stats dashboard.Stats
    if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
        t.Fatal(err)
    }
    if stats.Vulnerabilities != 1 {
        t.Errorf("expected 1 vuln, got %d", stats.Vulnerabilities)
    }
}