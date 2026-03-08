package wildcard

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "net"
    "sync"
)

func generateRandomSub() string {
    bytes := make([]byte, 8)
    rand.Read(bytes)
    return hex.EncodeToString(bytes)
}

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
    return positives > count*8/10, nil
}