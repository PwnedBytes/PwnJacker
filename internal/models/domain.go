package models

import "time"

// Domain represents a domain to be scanned.
type Domain struct {
    Name       string    `json:"name"`
    BaseDomain string    `json:"base_domain,omitempty"`
    AddedAt    time.Time `json:"added_at"`
    Tags       []string  `json:"tags,omitempty"`
}