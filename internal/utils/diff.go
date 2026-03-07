package utils

import (
    "crypto/md5"
    "encoding/hex"
    "strings"
)

type DiffResult struct {
    Added   []string
    Removed []string
    Changed []string
    Same    []string
}

func CompareStrings(old, new []string) *DiffResult {
    oldMap := make(map[string]bool)
    newMap := make(map[string]bool)

    for _, s := range old {
        oldMap[s] = true
    }
    for _, s := range new {
        newMap[s] = true
    }

    result := &DiffResult{
        Added:   make([]string, 0),
        Removed: make([]string, 0),
        Changed: make([]string, 0),
        Same:    make([]string, 0),
    }

    // Find added and same
    for s := range newMap {
        if oldMap[s] {
            result.Same = append(result.Same, s)
        } else {
            result.Added = append(result.Added, s)
        }
    }

    // Find removed
    for s := range oldMap {
        if !newMap[s] {
            result.Removed = append(result.Removed, s)
        }
    }

    return result
}

func CompareResponses(oldBody, newBody string) *DiffResult {
    oldLines := strings.Split(oldBody, "\n")
    newLines := strings.Split(newBody, "\n")
    
    return CompareStrings(oldLines, newLines)
}

func HashString(s string) string {
    hash := md5.Sum([]byte(s))
    return hex.EncodeToString(hash[:])
}

func HashLines(s string) []string {
    lines := strings.Split(s, "\n")
    hashes := make([]string, len(lines))
    
    for i, line := range lines {
        hashes[i] = HashString(line)
    }
    
    return hashes
}

func Similarity(s1, s2 string) float64 {
    if s1 == s2 {
        return 1.0
    }

    h1 := HashLines(s1)
    h2 := HashLines(s2)

    matches := 0
    for i := 0; i < len(h1) && i < len(h2); i++ {
        if h1[i] == h2[i] {
            matches++
        }
    }

    maxLen := len(h1)
    if len(h2) > maxLen {
        maxLen = len(h2)
    }

    if maxLen == 0 {
        return 1.0
    }

    return float64(matches) / float64(maxLen)
}