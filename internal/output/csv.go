package output

import (
    "encoding/csv"
    "fmt"
    "os"
    "strconv"
    "time"

    "PwnJacker/internal/models"
)

type CSVWriter struct{}

func NewCSVWriter() *CSVWriter {
    return &CSVWriter{}
}

func (w *CSVWriter) Write(findings []*models.Vulnerability, filename string) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    writer := csv.NewWriter(file)
    defer writer.Flush()

    // Write header
    header := []string{
        "Domain", "Type", "Service", "Severity", "Description",
        "Discovered", "CVE", "CVSS", "Verified", "Remediation",
    }
    if err := writer.Write(header); err != nil {
        return err
    }

    // Write rows
    for _, f := range findings {
        row := []string{
            f.Domain,
            f.Type,
            f.Service,
            string(f.Severity),
            f.Description,
            f.Discovered.Format(time.RFC3339),
            f.CVE,
            strconv.FormatFloat(f.CVSS, 'f', 2, 64),
            strconv.FormatBool(f.Verified),
            f.Remediation,
        }
        if err := writer.Write(row); err != nil {
            return err
        }
    }

    return nil
}