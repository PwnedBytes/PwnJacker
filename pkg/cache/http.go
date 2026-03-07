package cache

import (
    "sync"
    "time"

    "PwnJacker/internal/models"
)

type HTTPCache struct {
    responses map[string]httpCacheEntry
    mu        sync.RWMutex
    ttl       time.Duration
    maxSize   int
}

type httpCacheEntry struct {
    response  *models.HTTPResponse
    timestamp time.Time
}

func NewHTTPCache(ttl time.Duration, maxSize int) *HTTPCache {
    c := &HTTPCache{
        responses: make(map[string]httpCacheEntry),
        ttl:       ttl,
        maxSize:   maxSize,
    }

    go c.cleanup()
    return c
}

func (c *HTTPCache) Get(domain string) (*models.HTTPResponse, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()

    entry, exists := c.responses[domain]
    if !exists {
        return nil, false
    }

    if time.Since(entry.timestamp) > c.ttl {
        return nil, false
    }

    return entry.response, true
}

func (c *HTTPCache) Set(domain string, response *models.HTTPResponse) {
    c.mu.Lock()
    defer c.mu.Unlock()

    if len(c.responses) >= c.maxSize {
        c.evictOldest()
    }

    c.responses[domain] = httpCacheEntry{
        response:  response,
        timestamp: time.Now(),
    }
}

func (c *HTTPCache) Clear() {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    c.responses = make(map[string]httpCacheEntry)
}

func (c *HTTPCache) Delete(domain string) {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    delete(c.responses, domain)
}

func (c *HTTPCache) cleanup() {
    ticker := time.NewTicker(c.ttl)
    for range ticker.C {
        c.mu.Lock()
        for domain, entry := range c.responses {
            if time.Since(entry.timestamp) > c.ttl {
                delete(c.responses, domain)
            }
        }
        c.mu.Unlock()
    }
}

func (c *HTTPCache) evictOldest() {
    var oldestDomain string
    var oldestTime time.Time

    for domain, entry := range c.responses {
        if oldestTime.IsZero() || entry.timestamp.Before(oldestTime) {
            oldestDomain = domain
            oldestTime = entry.timestamp
        }
    }

    if oldestDomain != "" {
        delete(c.responses, oldestDomain)
    }
}

func (c *HTTPCache) Size() int {
    c.mu.RLock()
    defer c.mu.RUnlock()
    
    return len(c.responses)
}