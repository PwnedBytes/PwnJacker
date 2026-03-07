package scanner

import (
    "context"
    "sync"
)

// Scheduler manages work distribution among workers
type Scheduler struct {
    jobs      chan string
    results   chan *models.Vulnerability
    workers   int
    wg        sync.WaitGroup
    ctx       context.Context
    cancel    context.CancelFunc
}

func NewScheduler(workers int, bufferSize int) *Scheduler {
    ctx, cancel := context.WithCancel(context.Background())
    return &Scheduler{
        jobs:    make(chan string, bufferSize),
        results: make(chan *models.Vulnerability, bufferSize),
        workers: workers,
        ctx:     ctx,
        cancel:  cancel,
    }
}

func (s *Scheduler) Start(workerFunc func(context.Context, string) *models.Vulnerability) {
    for i := 0; i < s.workers; i++ {
        s.wg.Add(1)
        go func() {
            defer s.wg.Done()
            for {
                select {
                case <-s.ctx.Done():
                    return
                case domain, ok := <-s.jobs:
                    if !ok {
                        return
                    }
                    if vuln := workerFunc(s.ctx, domain); vuln != nil {
                        s.results <- vuln
                    }
                }
            }
        }()
    }
}

func (s *Scheduler) Submit(domain string) {
    select {
    case s.jobs <- domain:
    case <-s.ctx.Done():
    }
}

func (s *Scheduler) Results() <-chan *models.Vulnerability {
    return s.results
}

func (s *Scheduler) Stop() {
    s.cancel()
    close(s.jobs)
    s.wg.Wait()
    close(s.results)
}