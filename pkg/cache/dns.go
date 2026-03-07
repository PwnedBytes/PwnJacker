package cache

import (
    "net"
    "sync"
    "time"
)

type DNSCache struct {
    records map[string]cacheEntry
    mu      sync.RWMutex
    ttl     time.Duration
    maxSize int
}

type cacheEntry struct {
    ips       []net.IP
    cname     string
    txt       []string
    mx        []*net.MX
    ns        []*net.NS
    timestamp time.Time
}

func NewDNSCache(ttl time.Duration, maxSize int) *DNSCache {
    c := &DNSCache{
        records: make(map[string]cacheEntry),
        ttl:     ttl,
        maxSize: maxSize,
    }

    // Start cleanup goroutine
    go c.cleanup()

    return c
}

func (c *DNSCache) Get(domain string) (cacheEntry, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()

    entry, exists := c.records[domain]
    if !exists {
        return cacheEntry{}, false
    }

    if time.Since(entry.timestamp) > c.ttl {
        return cacheEntry{}, false
    }

    return entry, true
}

func (c *DNSCache) Set(domain string, entry cacheEntry) {
    c.mu.Lock()
    defer c.mu.Unlock()

    // Check if we need to evict
    if len(c.records) >= c.maxSize {
        c.evictOldest()
    }

    entry.timestamp = time.Now()
    c.records[domain] = entry
}

func (c *DNSCache) SetA(domain string, ips []net.IP) {
    entry, _ := c.Get(domain)
    entry.ips = ips
    c.Set(domain, entry)
}

func (c *DNSCache) SetCNAME(domain, cname string) {
    entry, _ := c.Get(domain)
    entry.cname = cname
    c.Set(domain, entry)
}

func (c *DNSCache) SetTXT(domain string, txt []string) {
    entry, _ := c.Get(domain)
    entry.txt = txt
    c.Set(domain, entry)
}

func (c *DNSCache) SetMX(domain string, mx []*net.MX) {
    entry, _ := c.Get(domain)
    entry.mx = mx
    c.Set(domain, entry)
}

func (c *DNSCache) SetNS(domain string, ns []*net.NS) {
    entry, _ := c.Get(domain)
    entry.ns = ns
    c.Set(domain, entry)
}

func (c *DNSCache) Clear() {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    c.records = make(map[string]cacheEntry)
}

func (c *DNSCache) Delete(domain string) {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    delete(c.records, domain)
}

func (c *DNSCache) cleanup() {
    ticker := time.NewTicker(c.ttl)
    for range ticker.C {
        c.mu.Lock()
        for domain, entry := range c.records {
            if time.Since(entry.timestamp) > c.ttl {
                delete(c.records, domain)
            }
        }
        c.mu.Unlock()
    }
}

func (c *DNSCache) evictOldest() {
    var oldestDomain string
    var oldestTime time.Time

    for domain, entry := range c.records {
        if oldestTime.IsZero() || entry.timestamp.Before(oldestTime) {
            oldestDomain = domain
            oldestTime = entry.timestamp
        }
    }

    if oldestDomain != "" {
        delete(c.records, oldestDomain)
    }
}

func (c *DNSCache) Size() int {
    c.mu.RLock()
    defer c.mu.RUnlock()
    
    return len(c.records)
}