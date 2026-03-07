package wildcard

import (
    "context"
    "net"
    "sync"
)

// DeepWildcardCheck tests multiple random subdomains to confirm wildcard.
func DeepWildcardCheck(ctx context.Context, domain string, count int) (bool, error) {
    var wg sync.WaitGroup
    results := make(chan bool, count)
    for i := 0; i < count; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            sub := generateRandomSub() + "." + domain
            ips, err := net.LookupIP(sub)
            if err == nil && len(ips) > 0 {
                results <- true
            } else {
                results <- false
            }
        }()
    }
    wg.Wait()
    close(results)

    positives := 0
    for r := range results {
        if r {
            positives++
        }
    }
    // If more than 80% resolve, consider it a wildcard.
    return positives > count*8/10, nil
}