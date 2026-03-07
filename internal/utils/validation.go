package utils

import (
    "net"
    "net/url"
    "regexp"
    "strings"
)

var domainRegex = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

func IsValidDomain(domain string) bool {
    return domainRegex.MatchString(domain)
}

func IsValidURL(raw string) bool {
    u, err := url.Parse(raw)
    return err == nil && u.Scheme != "" && u.Host != ""
}

func IsIP(host string) bool {
    return net.ParseIP(host) != nil
}

func SanitizeDomain(input string) string {
    // Remove protocol, port, path
    input = strings.TrimPrefix(input, "http://")
    input = strings.TrimPrefix(input, "https://")
    if idx := strings.Index(input, "/"); idx != -1 {
        input = input[:idx]
    }
    if idx := strings.Index(input, ":"); idx != -1 {
        input = input[:idx]
    }
    return input
}