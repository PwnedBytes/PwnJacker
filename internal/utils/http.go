package utils

import (
    "crypto/tls"
    "net/http"
    "strings"
    "time"
)

func NewHTTPClient(timeout time.Duration, followRedirects bool) *http.Client {
    client := &http.Client{
        Timeout: timeout,
        Transport: &http.Transport{
            MaxIdleConns:        100,
            MaxIdleConnsPerHost: 10,
            IdleConnTimeout:     90 * time.Second,
            TLSClientConfig: &tls.Config{
                InsecureSkipVerify: true,
            },
        },
    }

    if !followRedirects {
        client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        }
    }

    return client
}

func HeadersToMap(headers http.Header) map[string]string {
    result := make(map[string]string)
    for k, v := range headers {
        if len(v) > 0 {
            result[strings.ToLower(k)] = v[0]
        }
    }
    return result
}

func IsHTTPS(domain string) bool {
    client := NewHTTPClient(5*time.Second, false)
    resp, err := client.Get("https://" + domain)
    if err != nil {
        return false
    }
    defer resp.Body.Close()
    return resp.TLS != nil
}