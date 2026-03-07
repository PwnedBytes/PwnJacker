package main

import (
    "context"
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "runtime"
    "syscall"
    "time"

    "PwnJacker/internal/dashboard"
    "PwnJacker/internal/models"
    "PwnJacker/internal/output"
    "PwnJacker/internal/scanner"
    "PwnJacker/internal/utils"
    "PwnJacker/pkg/checkpoint"
)

var (
    version = "dev"
    commit  = "none"
    date    = "unknown"
)

func main() {
    // Parse command line flags
    var (
        listFile      = flag.String("l", "", "File containing list of subdomains")
        outputFile    = flag.String("o", "results.json", "Output file for results")
        threads       = flag.Int("t", runtime.NumCPU(), "Number of concurrent threads")
        timeout       = flag.Int("timeout", 10, "HTTP timeout in seconds")
        dashboardPort = flag.String("dashboard", "", "Enable dashboard on specified port (e.g., :8080)")
        resumeFrom    = flag.String("resume", "", "Resume scan from checkpoint file")
        checkEmail    = flag.Bool("check-email", false, "Enable email security checks (SPF/DKIM/DMARC)")
        deepScan      = flag.Bool("deep", false, "Enable deep scanning (more requests, thorough checks)")
        format        = flag.String("format", "json", "Output format: json, html, markdown, csv, hackerone, bugcrowd")
        verbose       = flag.Bool("v", false, "Verbose output")
        versionFlag   = flag.Bool("version", false, "Show version information")
    )

    flag.Parse()

    if *versionFlag {
        fmt.Printf("PwnJacker %s (commit: %s, built: %s)\n", version, commit, date)
        os.Exit(0)
    }

    if *listFile == "" {
        log.Fatal("Please provide a list file with -l flag")
    }

    // Load domains from file
    domains, err := utils.LoadDomainsFromFile(*listFile)
    if err != nil {
        log.Fatalf("Failed to load domains: %v", err)
    }

    log.Printf("Loaded %d domains for scanning", len(domains))

    // Create context with cancellation
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Handle interrupt signals
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        <-sigChan
        log.Println("\nReceived interrupt, saving checkpoint...")
        cancel()
    }()

    // Initialize checkpoint manager
    checkpointMgr := checkpoint.NewManager("pwnjacker_checkpoint.json")
    
    var scanDomains []string
    if *resumeFrom != "" {
        var state checkpoint.ScanState
        if err := checkpointMgr.Load(*resumeFrom, &state); err == nil {
            scanDomains = state.PendingDomains
            log.Printf("Resuming scan from checkpoint. %d domains remaining", len(scanDomains))
        } else {
            log.Printf("Could not load checkpoint: %v, starting fresh", err)
            scanDomains = domains
        }
    } else {
        scanDomains = domains
    }

    // Initialize scanner
    scannerConfig := &scanner.Config{
        Domains:        scanDomains,
        Threads:        *threads,
        Timeout:        time.Duration(*timeout) * time.Second,
        CheckEmail:     *checkEmail,
        DeepScan:       *deepScan,
        Verbose:        *verbose,
        CheckpointMgr:  checkpointMgr,
        TotalDomains:   len(domains),
    }

    s := scanner.New(scannerConfig)

    // Initialize results channel
    results := make(chan *models.Vulnerability, 1000)

    // Start dashboard if enabled
    if *dashboardPort != "" {
        dash := dashboard.NewServer(*dashboardPort, results)
        go func() {
            if err := dash.Start(); err != nil {
                log.Printf("Dashboard error: %v", err)
            }
        }()
        log.Printf("Dashboard available at http://localhost%s", *dashboardPort)
    }

    // Run scan
    go func() {
        if err := s.Run(ctx, results); err != nil {
            log.Printf("Scan error: %v", err)
        }
        close(results)
    }()

    // Collect results
    var findings []*models.Vulnerability
    for result := range results {
        findings = append(findings, result)
        if *verbose {
            log.Printf("Found: %s - %s (%s)", result.Domain, result.Type, result.Service)
        }
    }

    // Save results
    writer := output.NewWriter(*format)
    if err := writer.Write(findings, *outputFile); err != nil {
        log.Fatalf("Failed to write results: %v", err)
    }

    // Save final checkpoint
    finalState := &checkpoint.ScanState{
        CompletedDomains: domains,
        PendingDomains:   []string{},
        Findings:         findings,
        Timestamp:        time.Now(),
    }
    checkpointMgr.Save("final_checkpoint.json", finalState)

    log.Printf("Scan complete! Found %d vulnerabilities", len(findings))
    log.Printf("Results saved to %s", *outputFile)
}
