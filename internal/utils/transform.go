package utils

import (
    "encoding/base64"
    "net"
    "strings"
    "unicode"
)

// ToASCII converts domain to ASCII (Punycode) if needed
func ToASCII(domain string) (string, error) {
    // Using golang.org/x/net/idna is better, but for simplicity:
    if !strings.Contains(domain, "xn--") && isASCII(domain) {
        return domain, nil
    }
    // Placeholder – in real code use idna.ToASCII
    return domain, nil
}

func isASCII(s string) bool {
    for i := 0; i < len(s); i++ {
        if s[i] > unicode.MaxASCII {
            return false
        }
    }
    return true
}

// ReverseString returns the reversed string
func ReverseString(s string) string {
    runes := []rune(s)
    for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
        runes[i], runes[j] = runes[j], runes[i]
    }
    return string(runes)
}

// JoinIPs joins a slice of net.IP with commas
func JoinIPs(ips []net.IP) string {
    strs := make([]string, len(ips))
    for i, ip := range ips {
        strs[i] = ip.String()
    }
    return strings.Join(strs, ", ")
}

// EncodeBase64 encodes data to base64
func EncodeBase64(data []byte) string {
    return base64.StdEncoding.EncodeToString(data)
}