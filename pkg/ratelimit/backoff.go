package ratelimit

import (
    "math"
    "time"
)

type Backoff struct {
    min     time.Duration
    max     time.Duration
    factor  float64
    attempt int
}

func NewBackoff(min, max time.Duration, factor float64) *Backoff {
    return &Backoff{
        min:    min,
        max:    max,
        factor: factor,
    }
}

// Duration returns the next backoff duration
func (b *Backoff) Duration() time.Duration {
    d := float64(b.min) * math.Pow(b.factor, float64(b.attempt))
    b.attempt++
    if d > float64(b.max) {
        return b.max
    }
    return time.Duration(d)
}

// Reset resets the attempt counter
func (b *Backoff) Reset() {
    b.attempt = 0
}