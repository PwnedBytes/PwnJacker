package scanner

import (
    "fmt"
    "strings"
    "sync"
    "time"
)

type Progress struct {
    total     int
    current   int
    mu        sync.RWMutex
    startTime time.Time
    done      chan bool
}

func NewProgress(total int) *Progress {
    return &Progress{
        total:     total,
        startTime: time.Now(),
        done:      make(chan bool),
    }
}

func (p *Progress) Start() {
    ticker := time.NewTicker(100 * time.Millisecond)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            p.print()
        case <-p.done:
            p.print()
            fmt.Println()
            return
        }
    }
}

func (p *Progress) Update(current, total int) {
    p.mu.Lock()
    defer p.mu.Unlock()
    p.current = current
    p.total = total
}

func (p *Progress) Stop() {
    close(p.done)
}

func (p *Progress) print() {
    p.mu.RLock()
    defer p.mu.RUnlock()

    if p.total == 0 {
        return
    }

    percentage := float64(p.current) / float64(p.total) * 100
    elapsed := time.Since(p.startTime)

    var eta time.Duration
    if p.current > 0 {
        totalEstimated := time.Duration(float64(elapsed) / (float64(p.current) / float64(p.total)))
        eta = totalEstimated - elapsed
    }

    barLength := 50
    filled := int(float64(barLength) * float64(p.current) / float64(p.total))
    bar := strings.Repeat("=", filled) + strings.Repeat(" ", barLength-filled)

    fmt.Printf("\r[%s] %d/%d (%.1f%%) | Elapsed: %v | ETA: %v",
        bar, p.current, p.total, percentage,
        formatDuration(elapsed),
        formatDuration(eta))
}

func formatDuration(d time.Duration) string {
    d = d.Round(time.Second)
    h := d / time.Hour
    d -= h * time.Hour
    m := d / time.Minute
    d -= m * time.Minute
    s := d / time.Second

    if h > 0 {
        return fmt.Sprintf("%dh%dm%ds", h, m, s)
    }
    if m > 0 {
        return fmt.Sprintf("%dm%ds", m, s)
    }
    return fmt.Sprintf("%ds", s)
}