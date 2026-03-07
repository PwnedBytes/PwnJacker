package output

import (
    "bytes"
    "os"
    "text/template"

    "PwnJacker/internal/models"
)

type BugcrowdWriter struct{}

func NewBugcrowdWriter() *BugcrowdWriter {
    return &BugcrowdWriter{}
}

const bugcrowdTemplate = `# Bugcrowd Submission

## Title
Subdomain Takeover on {{.Domain}}

## Vulnerability Type
Subdomain Takeover

## Asset
{{.Domain}}

## Description
The subdomain {{.Domain}} is vulnerable to takeover because it has a DNS record (CNAME) pointing to a {{.Service}} service that no longer exists or is unclaimed. This allows an attacker to claim the resource and serve arbitrary content under the victim's domain.

## Steps to Reproduce
1. Check DNS:
   {{range .DNSRecords}}
   - {{.Type}}: {{.Value}}{{end}}

2. Visit the domain:
   ` + "```" + `
   curl -I https://{{.Domain}}
   ` + "```" + `
   Response:
   Status: {{.HTTPResponse.StatusCode}}
   Server: {{.HTTPResponse.Server}}

3. Observe the error page indicating the service is missing.

## Impact
An attacker can host malicious content (phishing, malware) under a trusted domain, leading to credential theft, malware distribution, and reputational damage.

## Remediation
{{.Remediation}}

## References
{{range .References}}- {{.}}
{{end}}
`

func (w *BugcrowdWriter) Write(findings []*models.Vulnerability, filename string) error {
    // Similar to HackerOneWriter
    for i, f := range findings {
        outFile := filename
        if len(findings) > 1 {
            outFile = filename + "_" + string(rune('A'+i))
        }
        tmpl, _ := template.New("bugcrowd").Parse(bugcrowdTemplate)
        var buf bytes.Buffer
        tmpl.Execute(&buf, f)
        os.WriteFile(outFile+".txt", buf.Bytes(), 0644)
    }
    return nil
}