package ratelimit

import (
    "sync"
    "time"
)

type Limiter struct {
    rate      int
    interval  time.Duration
    tokens    int
    lastRefill time.Time
    mu        sync.Mutex
}

func NewLimiter(rate int, interval time.Duration) *Limiter {
    return &Limiter{
        rate:      rate,
        interval:  interval,
        tokens:    rate,
        lastRefill: time.Now(),
    }
}

func (l *Limiter) Wait() {
    l.mu.Lock()
    defer l.mu.Unlock()

    l.refill()

    if l.tokens <= 0 {
        sleepTime := l.interval/time.Duration(l.rate) - time.Since(l.lastRefill)
        if sleepTime > 0 {
            time.Sleep(sleepTime)
        }
        l.refill()
    }

    l.tokens--
}

func (l *Limiter) refill() {
    now := time.Now()
    elapsed := now.Sub(l.lastRefill)
    
    if elapsed >= l.interval {
        l.tokens = l.rate
        l.lastRefill = now
        return
    }

    // Calculate tokens to add based on elapsed time
    tokensToAdd := int(float64(elapsed) / float64(l.interval) * float64(l.rate))
    if tokensToAdd > 0 {
        l.tokens += tokensToAdd
        if l.tokens > l.rate {
            l.tokens = l.rate
        }
        l.lastRefill = l.lastRefill.Add(time.Duration(float64(l.interval) * float64(tokensToAdd) / float64(l.rate)))
    }
}

func (l *Limiter) Allow() bool {
    l.mu.Lock()
    defer l.mu.Unlock()

    l.refill()

    if l.tokens > 0 {
        l.tokens--
        return true
    }

    return false
}

func (l *Limiter) SetRate(rate int) {
    l.mu.Lock()
    defer l.mu.Unlock()
    
    l.rate = rate
    l.refill()
}