package wordlist

func GeneratePermutations(base string, words []string) []string {
    var results []string
    // Common permutations: prefix, suffix, hyphen, dot, number
    for _, w := range words {
        results = append(results, w)                     // base word
        results = append(results, w+"-"+base)            // word-base
        results = append(results, base+"-"+w)            // base-word
        results = append(results, w+"."+base)            // word.base
        results = append(results, base+"."+w)            // base.word
        results = append(results, w+"1", w+"2", w+"3")   // numbered
        results = append(results, "dev-"+w, "staging-"+w, "prod-"+w)
        results = append(results, w+"-dev", w+"-staging", w+"-prod")
        results = append(results, "api-"+w, "admin-"+w, "mail-"+w)
    }
    return results
}