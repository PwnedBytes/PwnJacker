package cache

import (
    "encoding/json"
    "os"
    "sync"
    "time"
)

type PersistentCache struct {
    file   string
    data   map[string]cacheItem
    mu     sync.RWMutex
}

type cacheItem struct {
    Value     interface{} `json:"value"`
    ExpiresAt time.Time   `json:"expires_at"`
}

func NewPersistentCache(file string) (*PersistentCache, error) {
    pc := &PersistentCache{
        file: file,
        data: make(map[string]cacheItem),
    }
    // Try to load existing cache
    if err := pc.load(); err != nil && !os.IsNotExist(err) {
        return nil, err
    }
    return pc, nil
}

func (pc *PersistentCache) Set(key string, value interface{}, ttl time.Duration) {
    pc.mu.Lock()
    defer pc.mu.Unlock()
    pc.data[key] = cacheItem{
        Value:     value,
        ExpiresAt: time.Now().Add(ttl),
    }
    pc.save()
}

func (pc *PersistentCache) Get(key string) (interface{}, bool) {
    pc.mu.RLock()
    defer pc.mu.RUnlock()
    item, ok := pc.data[key]
    if !ok {
        return nil, false
    }
    if time.Now().After(item.ExpiresAt) {
        // expired – remove it asynchronously
        go pc.Delete(key)
        return nil, false
    }
    return item.Value, true
}

func (pc *PersistentCache) Delete(key string) {
    pc.mu.Lock()
    defer pc.mu.Unlock()
    delete(pc.data, key)
    pc.save()
}

func (pc *PersistentCache) save() error {
    tmpFile := pc.file + ".tmp"
    f, err := os.Create(tmpFile)
    if err != nil {
        return err
    }
    defer f.Close()
    enc := json.NewEncoder(f)
    if err := enc.Encode(pc.data); err != nil {
        return err
    }
    return os.Rename(tmpFile, pc.file)
}

func (pc *PersistentCache) load() error {
    f, err := os.Open(pc.file)
    if err != nil {
        return err
    }
    defer f.Close()
    dec := json.NewDecoder(f)
    return dec.Decode(&pc.data)
}