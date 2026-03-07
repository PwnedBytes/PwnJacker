package scanner

import (
    "context"
    "fmt"
    "sync"
    "sync/atomic"
    "time"

    "PwnJacker/internal/detectors/registry"
    "PwnJacker/internal/models"
    "PwnJacker/internal/utils"
    "PwnJacker/pkg/checkpoint"
    "PwnJacker/pkg/ratelimit"
)

type Config struct {
    Domains       []string
    Threads       int
    Timeout       time.Duration
    CheckEmail    bool
    DeepScan      bool
    Verbose       bool
    CheckpointMgr *checkpoint.Manager
    TotalDomains  int
}

type Scanner struct {
    config        *Config
    detectors     []registry.Detector
    limiter       *ratelimit.Limiter
    results       chan *models.Vulnerability
    wg            sync.WaitGroup
    domainsScanned int32
    mu            sync.RWMutex
    checkpoint    *checkpoint.ScanState
}

func New(config *Config) *Scanner {
    return &Scanner{
        config:    config,
        detectors: registry.InitializeDetectors(config.DeepScan, config.CheckEmail),
        limiter:   ratelimit.NewLimiter(100, time.Second), // 100 requests per second max
    }
}

func (s *Scanner) Run(ctx context.Context, results chan *models.Vulnerability) error {
    s.results = results
    
    // Create domain channel
    domainChan := make(chan string, len(s.config.Domains))
    for _, domain := range s.config.Domains {
        domainChan <- domain
    }
    close(domainChan)

    // Initialize progress tracking
    progress := utils.NewProgress(s.config.TotalDomains)
    go progress.Start()

    // Start workers
    for i := 0; i < s.config.Threads; i++ {
        s.wg.Add(1)
        go s.worker(ctx, domainChan, progress)
    }

    // Wait for all workers to finish
    s.wg.Wait()
    progress.Stop()

    return nil
}

func (s *Scanner) worker(ctx context.Context, domains <-chan string, progress *utils.Progress) {
    defer s.wg.Done()

    for domain := range domains {
        select {
        case <-ctx.Done():
            return
        default:
            s.scanDomain(domain)
            
            // Update progress
            scanned := atomic.AddInt32(&s.domainsScanned, 1)
            progress.Update(int(scanned), int(s.config.TotalDomains))
            
            // Save checkpoint every 100 domains
            if scanned%100 == 0 {
                s.saveCheckpoint()
            }
        }
    }
}

func (s *Scanner) scanDomain(domain string) {
    // Rate limiting
    s.limiter.Wait()
    
    // Create context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), s.config.Timeout)
    defer cancel()

    // Check each detector
    for _, detector := range s.detectors {
        select {
        case <-ctx.Done():
            return
        default:
            if vuln := detector.Detect(ctx, domain); vuln != nil {
                s.results <- vuln
                if s.config.Verbose {
                    fmt.Printf("[+] Found: %s - %s\n", domain, vuln.Type)
                }
            }
        }
    }
}

func (s *Scanner) saveCheckpoint() {
    s.mu.RLock()
    defer s.mu.RUnlock()

    state := &checkpoint.ScanState{
        CompletedDomains: s.config.Domains[:s.domainsScanned],
        PendingDomains:   s.config.Domains[s.domainsScanned:],
        Timestamp:        time.Now(),
    }
    
    if err := s.config.CheckpointMgr.Save("autosave.json", state); err != nil {
        fmt.Printf("Warning: Failed to save checkpoint: %v\n", err)
    }
}