package models

// Fingerprint defines a service fingerprint for takeover detection.
type Fingerprint struct {
    Service     string            `yaml:"service" json:"service"`
    CNAME       []string          `yaml:"cname" json:"cname"`
    Patterns    []string          `yaml:"patterns" json:"patterns"`
    StatusCodes []int             `yaml:"status_codes" json:"status_codes"`
    Headers     map[string]string `yaml:"headers" json:"headers"`
    ClaimURL    string            `yaml:"claim_url" json:"claim_url"`
    Remediation string            `yaml:"remediation" json:"remediation"`
    References  []string          `yaml:"references" json:"references"`
    Severity    string            `yaml:"severity" json:"severity"`
    CVSS        float64           `yaml:"cvss" json:"cvss"`
    CVE         string            `yaml:"cve" json:"cve"`
}