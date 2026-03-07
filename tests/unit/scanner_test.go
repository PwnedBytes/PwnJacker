package unit

import (
    "testing"
    "PwnJacker/internal/scanner"
)

func TestScannerConfig(t *testing.T) {
    cfg := &scanner.Config{
        Threads: 5,
        Timeout: 10,
    }
    if cfg.Threads != 5 {
        t.Errorf("expected 5 threads, got %d", cfg.Threads)
    }
}