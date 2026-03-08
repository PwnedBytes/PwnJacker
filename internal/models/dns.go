package models

type DNSRecord struct {
    Type    string `json:"type"`
    Name    string `json:"name"`
    Value   string `json:"value"`
    TTL     int    `json:"ttl"`
    Service string `json:"service,omitempty"`
}