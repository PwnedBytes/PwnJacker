package output

import (
    "bytes"
    "fmt"
    "os"
    "text/template"

    "PwnJacker/internal/models"
)

type HackerOneWriter struct{}

func NewHackerOneWriter() *HackerOneWriter {
    return &HackerOneWriter{}
}

const hackeroneTemplate = `### Summary
A subdomain takeover vulnerability was identified on {{.Domain}}.

### Description
The subdomain {{.Domain}} points to a {{.Service}} service that appears to be unclaimed or misconfigured. This allows an attacker to claim the resource and host arbitrary content under the victim's domain, leading to potential phishing, credential theft, or malware distribution.

**Vulnerability Type:** {{.Type}}  
**Service:** {{.Service}}  
**Severity:** {{.Severity}}  

### Steps To Reproduce
1. Run: ` + "`" + `nslookup {{.Domain}}` + "`" + `
   {{range .DNSRecords}}
   - {{.Type}} record: {{.Name}} → {{.Value}}{{end}}
2. Visit https://{{.Domain}} (or http) – observe the following response:
   - Status Code: {{.HTTPResponse.StatusCode}}
   - Server Header: {{.HTTPResponse.Server}}
   - Body snippet: ` + "`" + `{{.HTTPResponse.Body | printf "%.200s"}}` + "`" + `

### Impact
An attacker can claim the subdomain and serve malicious content under the trusted domain, compromising user trust and enabling further attacks.

### Remediation
{{.Remediation}}

### References
{{range .References}}- {{.}}
{{end}}
`

func (w *HackerOneWriter) Write(findings []*models.Vulnerability, filename string) error {
    if len(findings) == 0 {
        return nil
    }
    // For HackerOne, we typically write one report per finding.
    // We'll write each to a separate file or combine with numbering.
    for i, f := range findings {
        outFile := filename
        if len(findings) > 1 {
            outFile = fmt.Sprintf("%s_%d", filename, i+1)
        }
        fname := outFile + ".md"
        tmpl, err := template.New("hackerone").Parse(hackeroneTemplate)
        if err != nil {
            return err
        }
        var buf bytes.Buffer
        if err := tmpl.Execute(&buf, f); err != nil {
            return err
        }
        if err := os.WriteFile(fname, buf.Bytes(), 0644); err != nil {
            return err
        }
    }
    return nil
}