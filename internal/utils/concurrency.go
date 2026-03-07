package utils

import (
    "runtime"
    "sync"
)

type WorkerPool struct {
    workers   int
    tasks     chan func()
    wg        sync.WaitGroup
    quit      chan bool
}

func NewWorkerPool(workers int) *WorkerPool {
    if workers <= 0 {
        workers = runtime.NumCPU()
    }

    pool := &WorkerPool{
        workers: workers,
        tasks:   make(chan func(), 1000),
        quit:    make(chan bool),
    }

    pool.Start()
    return pool
}

func (p *WorkerPool) Start() {
    for i := 0; i < p.workers; i++ {
        go p.worker()
    }
}

func (p *WorkerPool) worker() {
    for {
        select {
        case task := <-p.tasks:
            task()
            p.wg.Done()
        case <-p.quit:
            return
        }
    }
}

func (p *WorkerPool) Submit(task func()) {
    p.wg.Add(1)
    select {
    case p.tasks <- task:
    case <-p.quit:
        p.wg.Done()
    }
}

func (p *WorkerPool) Wait() {
    p.wg.Wait()
}

func (p *WorkerPool) Stop() {
    close(p.quit)
}

type Semaphore struct {
    tokens chan struct{}
}

func NewSemaphore(size int) *Semaphore {
    return &Semaphore{
        tokens: make(chan struct{}, size),
    }
}

func (s *Semaphore) Acquire() {
    s.tokens <- struct{}{}
}

func (s *Semaphore) Release() {
    <-s.tokens
}

func (s *Semaphore) TryAcquire() bool {
    select {
    case s.tokens <- struct{}{}:
        return true
    default:
        return false
    }
}