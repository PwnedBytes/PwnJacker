package dashboard

import (
    "embed"
    "encoding/json"
    "fmt"
    "html/template"
    "net/http"
    "sync"
    "time"

    "PwnJacker/internal/models"
    "github.com/gorilla/websocket"
)

//go:embed ../../web/templates/* ../../web/static/*
var content embed.FS

type Server struct {
    port       string
    results    <-chan *models.Vulnerability
    findings   []*models.Vulnerability
    mu         sync.RWMutex
    stats      *Stats
    clients    map[*websocket.Conn]bool
    clientsMu  sync.Mutex
    upgrader   websocket.Upgrader
}

type Stats struct {
    DomainsScanned   int            `json:"domains_scanned"`
    Vulnerabilities  int            `json:"vulnerabilities"`
    BySeverity       map[string]int `json:"by_severity"`
    ByService        map[string]int `json:"by_service"`
    StartTime        time.Time      `json:"start_time"`
    CriticalCount    int            `json:"critical_count"`
    HighCount        int            `json:"high_count"`
    MediumCount      int            `json:"medium_count"`
    LowCount         int            `json:"low_count"`
}

func NewServer(port string, results <-chan *models.Vulnerability) *Server {
    return &Server{
        port:     port,
        results:  results,
        findings: make([]*models.Vulnerability, 0),
        stats: &Stats{
            BySeverity: make(map[string]int),
            ByService:  make(map[string]int),
            StartTime:  time.Now(),
        },
        clients: make(map[*websocket.Conn]bool),
        upgrader: websocket.Upgrader{
            CheckOrigin: func(r *http.Request) bool {
                return true
            },
        },
    }
}

func (s *Server) Start() error {
    go s.processResults()

    http.HandleFunc("/", s.handleIndex)
    http.HandleFunc("/api/stats", s.handleStats)
    http.HandleFunc("/api/findings", s.handleFindings)
    http.HandleFunc("/api/finding/", s.handleFinding)
    http.HandleFunc("/ws", s.handleWebSocket)
    http.Handle("/static/", http.FileServer(http.FS(content)))

    return http.ListenAndServe(s.port, nil)
}

func (s *Server) processResults() {
    for vuln := range s.results {
        s.mu.Lock()
        s.findings = append(s.findings, vuln)
        s.stats.Vulnerabilities++
        s.stats.BySeverity[string(vuln.Severity)]++
        s.stats.ByService[vuln.Service]++
        switch vuln.Severity {
        case models.SeverityCritical:
            s.stats.CriticalCount++
        case models.SeverityHigh:
            s.stats.HighCount++
        case models.SeverityMedium:
            s.stats.MediumCount++
        case models.SeverityLow:
            s.stats.LowCount++
        }
        s.mu.Unlock()
        s.broadcastFinding(vuln)
    }
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
    tmpl, err := template.ParseFS(content, "web/templates/base.html", "web/templates/dashboard.html")
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

func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
    tmpl, err := template.ParseFS(content, "web/templates/base.html", "web/templates/results.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    tmpl.Execute(w, nil)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
    tmpl, err := template.ParseFS(content, "web/templates/base.html", "web/templates/scan.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    tmpl.Execute(w, nil)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
    tmpl, err := template.ParseFS(content, "web/templates/base.html", "web/templates/settings.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    tmpl.Execute(w, nil)
}

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
    tmpl, err := template.ParseFS(content, "web/templates/base.html", "web/templates/reports.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    tmpl.Execute(w, nil)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(s.stats)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    severity := r.URL.Query().Get("severity")
    service := r.URL.Query().Get("service")
    var filtered []*models.Vulnerability
    for _, f := range s.findings {
        if severity != "" && string(f.Severity) != severity {
            continue
        }
        if service != "" && f.Service != service {
            continue
        }
        filtered = append(filtered, f)
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(filtered)
}

func (s *Server) handleFinding(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Path[len("/api/finding/"):]
    s.mu.RLock()
    defer s.mu.RUnlock()
    for _, f := range s.findings {
        if f.ID == id {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(f)
            return
        }
    }
    http.NotFound(w, r)
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
    conn, err := s.upgrader.Upgrade(w, r, nil)
    if err != nil {
        return
    }
    defer conn.Close()

    s.clientsMu.Lock()
    s.clients[conn] = true
    s.clientsMu.Unlock()

    s.mu.RLock()
    for _, finding := range s.findings {
        conn.WriteJSON(finding)
    }
    s.mu.RUnlock()

    for {
        _, _, err := conn.ReadMessage()
        if err != nil {
            break
        }
    }

    s.clientsMu.Lock()
    delete(s.clients, conn)
    s.clientsMu.Unlock()
}

func (s *Server) broadcastFinding(finding *models.Vulnerability) {
    s.clientsMu.Lock()
    defer s.clientsMu.Unlock()
    for client := range s.clients {
        if err := client.WriteJSON(finding); err != nil {
            client.Close()
            delete(s.clients, client)
        }
    }
}