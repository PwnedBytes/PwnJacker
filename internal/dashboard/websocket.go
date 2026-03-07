package dashboard

import (
    "log"
    "net/http"

    "github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool { return true },
}

// handleWebSocket upgrades HTTP to WebSocket and manages client connections.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Print("WebSocket upgrade failed:", err)
        return
    }
    defer conn.Close()

    s.clientsMu.Lock()
    s.clients[conn] = true
    s.clientsMu.Unlock()

    // Send existing findings
    s.mu.RLock()
    for _, f := range s.findings {
        if err := conn.WriteJSON(f); err != nil {
            break
        }
    }
    s.mu.RUnlock()

    // Keep connection alive until client disconnects
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

// broadcastFinding sends a new finding to all connected WebSocket clients.
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
