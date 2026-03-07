package dashboard

import (
    "time"
)

// RealtimeManager handles live updates via channels.
type RealtimeManager struct {
    updateChan chan interface{}
    clients    map[chan interface{}]bool
}

func NewRealtimeManager() *RealtimeManager {
    return &RealtimeManager{
        updateChan: make(chan interface{}, 100),
        clients:    make(map[chan interface{}]bool),
    }
}

// Start begins broadcasting updates to all registered client channels.
func (rm *RealtimeManager) Start() {
    go func() {
        for update := range rm.updateChan {
            for clientCh := range rm.clients {
                select {
                case clientCh <- update:
                default:
                    // Client channel full, skip
                }
            }
        }
    }()
}

// Subscribe returns a channel for receiving real-time updates.
func (rm *RealtimeManager) Subscribe() chan interface{} {
    ch := make(chan interface{}, 10)
    rm.clients[ch] = true
    return ch
}

// Unsubscribe removes a client channel.
func (rm *RealtimeManager) Unsubscribe(ch chan interface{}) {
    delete(rm.clients, ch)
    close(ch)
}

// Publish sends an update to all subscribers.
func (rm *RealtimeManager) Publish(update interface{}) {
    select {
    case rm.updateChan <- update:
    default:
        // Update channel full, drop update
    }
}