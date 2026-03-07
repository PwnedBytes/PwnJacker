package utils

import (
    "context"
    "net"
    "strings"
    "time"
)

type DNSResolver struct {
    resolver *net.Resolver
    cache    map[string]dnsResult
}

type dnsResult struct {
    records   interface{}
    err       error
    timestamp time.Time
}

func NewDNSResolver() *DNSResolver {
    return &DNSResolver{
        resolver: net.DefaultResolver,
        cache:    make(map[string]dnsResult),
    }
}

func (r *DNSResolver) LookupA(ctx context.Context, domain string) ([]net.IP, error) {
    ips, err := r.resolver.LookupIP(ctx, "ip4", domain)
    return ips, err
}

func (r *DNSResolver) LookupCNAME(ctx context.Context, domain string) (string, error) {
    cname, err := r.resolver.LookupCNAME(ctx, domain)
    return cname, err
}

func (r *DNSResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
    txt, err := r.resolver.LookupTXT(ctx, domain)
    return txt, err
}

func (r *DNSResolver) LookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
    mx, err := r.resolver.LookupMX(ctx, domain)
    return mx, err
}

func (r *DNSResolver) LookupNS(ctx context.Context, domain string) ([]*net.NS, error) {
    ns, err := r.resolver.LookupNS(ctx, domain)
    return ns, err
}

func (r *DNSResolver) GetAllRecords(ctx context.Context, domain string) (map[string]interface{}, error) {
    results := make(map[string]interface{})

    // A records
    if ips, err := r.LookupA(ctx, domain); err == nil {
        results["a"] = ips
    }

    // CNAME
    if cname, err := r.LookupCNAME(ctx, domain); err == nil && cname != domain+"." {
        results["cname"] = strings.TrimSuffix(cname, ".")
    }

    // TXT
    if txt, err := r.LookupTXT(ctx, domain); err == nil {
        results["txt"] = txt
    }

    // MX
    if mx, err := r.LookupMX(ctx, domain); err == nil {
        results["mx"] = mx
    }

    // NS
    if ns, err := r.LookupNS(ctx, domain); err == nil {
        results["ns"] = ns
    }

    return results, nil
}

func ExtractDomain(input string) string {
    // Remove protocol
    input = strings.TrimPrefix(input, "http://")
    input = strings.TrimPrefix(input, "https://")
    
    // Remove path
    if idx := strings.Index(input, "/"); idx != -1 {
        input = input[:idx]
    }
    
    // Remove port
    if idx := strings.Index(input, ":"); idx != -1 {
        input = input[:idx]
    }
    
    return input
}

func IsSubdomain(domain, parent string) bool {
    return strings.HasSuffix(domain, "."+parent) && domain != parent
}

func GetBaseDomain(domain string) string {
    parts := strings.Split(domain, ".")
    if len(parts) < 2 {
        return domain
    }
    return strings.Join(parts[len(parts)-2:], ".")
}