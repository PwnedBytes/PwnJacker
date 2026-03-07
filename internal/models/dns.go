package models

// DNSRecord represents a DNS record.
type DNSRecord struct {
    Type    string `json:"type"`    // A, AAAA, CNAME, MX, TXT, NS
    Name    string `json:"name"`    // Record name (e.g., sub.example.com)
    Value   string `json:"value"`   // Record value (IP, target)
    TTL     int    `json:"ttl"`      // Time to live in seconds
    Service string `json:"service,omitempty"` // Associated service if any
}