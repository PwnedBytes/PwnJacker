package dashboard

import (
    "encoding/json"
    "fmt"
    "html/template"
    "net/http"

    "PwnJacker/internal/models"
)

// handleIndex serves the main dashboard page.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
    tmpl, err := template.ParseFS(content, "templates/base.html", "templates/dashboard.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    s.mu.RLock()
    data := struct {
        Stats      *Stats
        Findings   []*models.Vulnerability
        TotalScanned int
    }{
        Stats:      s.stats,
        Findings:   s.findings,
        TotalScanned: s.stats.DomainsScanned,
    }
    s.mu.RUnlock()

    tmpl.Execute(w, data)
}

// handleResults serves the results page.
func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
    tmpl, err := template.ParseFS(content, "templates/base.html", "templates/results.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    tmpl.Execute(w, nil)
}

// handleScan serves the scan configuration page.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
    tmpl, err := template.ParseFS(content, "templates/base.html", "templates/scan.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    tmpl.Execute(w, nil)
}

// handleSettings serves the settings page.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
    tmpl, err := template.ParseFS(content, "templates/base.html", "templates/settings.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    tmpl.Execute(w, nil)
}

// handleReports serves the reports list page.
func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
    tmpl, err := template.ParseFS(content, "templates/base.html", "templates/reports.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    // In a real implementation, you'd fetch reports from a database.
    tmpl.Execute(w, nil)
}

// handleAPIExportCSV exports findings as CSV.
func (s *Server) handleAPIExportCSV(w http.ResponseWriter, r *http.Request) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    w.Header().Set("Content-Type", "text/csv")
    w.Header().Set("Content-Disposition", "attachment;filename=findings.csv")
    // Write CSV header
    fmt.Fprintln(w, "Domain,Type,Service,Severity,Discovered")
    for _, f := range s.findings {
        fmt.Fprintf(w, "%s,%s,%s,%s,%s\n",
            f.Domain, f.Type, f.Service, f.Severity,
            f.Discovered.Format("2006-01-02 15:04:05"))
    }
}