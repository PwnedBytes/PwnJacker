package output

import (
    "html/template"
    "os"
    "time"

    "PwnJacker/internal/models"
)

type HTMLWriter struct{}

func NewHTMLWriter() *HTMLWriter {
    return &HTMLWriter{}
}

const htmlTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>PwnJacker Scan Report</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        h1 { color: #333; }
        .summary { background: #f0f0f0; padding: 10px; }
        .critical { color: red; }
        .high { color: orange; }
        .medium { color: gold; }
        .low { color: green; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
    </style>
</head>
<body>
    <h1>PwnJacker Security Scan Report</h1>
    <div class="summary">
        <p><strong>Scan Date:</strong> {{.ScanDate}}</p>
        <p><strong>Total Vulnerabilities:</strong> {{len .Findings}}</p>
    </div>

    <h2>Findings</h2>
    <table>
        <tr>
            <th>Domain</th>
            <th>Type</th>
            <th>Service</th>
            <th>Severity</th>
            <th>Discovered</th>
        </tr>
        {{range .Findings}}
        <tr>
            <td>{{.Domain}}</td>
            <td>{{.Type}}</td>
            <td>{{.Service}}</td>
            <td class="{{.Severity | toLower}}">{{.Severity}}</td>
            <td>{{.Discovered.Format "2006-01-02 15:04:05"}}</td>
        </tr>
        {{end}}
    </table>
</body>
</html>`

func (w *HTMLWriter) Write(findings []*models.Vulnerability, filename string) error {
    funcMap := template.FuncMap{
        "toLower": func(s models.Severity) string {
            return string(s)
        },
    }
    tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
    if err != nil {
        return err
    }
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    data := struct {
        ScanDate string
        Findings []*models.Vulnerability
    }{
        ScanDate: time.Now().Format("2006-01-02 15:04:05"),
        Findings: findings,
    }
    return tmpl.Execute(file, data)
}