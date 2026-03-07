package wordlist

import (
    "sort"
    "strings"
)

type ScoredWord struct {
    Word  string
    Score int
}

// PrioritizeByCommonality sorts words by likelihood of existence
func PrioritizeByCommonality(words []string, baseDomain string) []ScoredWord {
    scored := make([]ScoredWord, len(words))
    for i, w := range words {
        score := 0
        // Longer words are less common?
        if len(w) < 5 {
            score += 10
        }
        // Words containing common keywords
        if strings.Contains(w, "api") || strings.Contains(w, "admin") || strings.Contains(w, "mail") {
            score += 20
        }
        // Words that are also in the base domain
        if strings.Contains(baseDomain, w) {
            score += 5
        }
        scored[i] = ScoredWord{Word: w, Score: score}
    }
    sort.Slice(scored, func(i, j int) bool {
        return scored[i].Score > scored[j].Score
    })
    return scored
}