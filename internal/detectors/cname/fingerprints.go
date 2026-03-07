package cname

// Built-in fingerprints for common services (as fallback if YAML not loaded)
var BuiltinFingerprints = []map[string]interface{}{
    {
        "service":   "AWS S3",
        "cname":     []string{"s3.amazonaws.com", "s3-website"},
        "patterns":  []string{"NoSuchBucket", "The specified bucket does not exist"},
        "status":    404,
        "severity":  "CRITICAL",
    },
    {
        "service":   "GitHub Pages",
        "cname":     []string{"github.io", "github.com"},
        "patterns":  []string{"There isn't a GitHub Pages site here"},
        "status":    404,
        "severity":  "HIGH",
    },
    // ... add more as needed
}