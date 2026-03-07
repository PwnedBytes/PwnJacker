package models

type OrphanedResource struct {
    Type        string `json:"type"`
    Resource    string `json:"resource"`
    Context     string `json:"context"`
    RiskLevel   string `json:"risk_level"`
    Description string `json:"description"`
    Evidence    string `json:"evidence,omitempty"`
}

type SupplyChainRisk struct {
    Domain          string   `json:"domain"`
    ThirdPartyDomain string   `json:"third_party_domain"`
    ResourceType    string   `json:"resource_type"`
    ResourcePath    string   `json:"resource_path"`
    Vulnerable      bool     `json:"vulnerable"`
    RiskLevel       string   `json:"risk_level"`
    Remediation     string   `json:"remediation"`
}

type HistoricalDNS struct {
    Domain      string      `json:"domain"`
    Snapshots   []DNSSnapshot `json:"snapshots"`
    Changes     []DNSChange `json:"changes"`
    RiskScore   float64     `json:"risk_score"`
}

type DNSSnapshot struct {
    Timestamp   time.Time   `json:"timestamp"`
    Records     []DNSRecord `json:"records"`
    Source      string      `json:"source"` // e.g., "SecurityTrails", "Censys", "DNSDumpster"
}

type DNSChange struct {
    From        DNSRecord   `json:"from"`
    To          DNSRecord   `json:"to"`
    ChangedAt   time.Time   `json:"changed_at"`
    RiskLevel   string      `json:"risk_level"`
}

type AttackPath struct {
    EntryPoint      string   `json:"entry_point"`
    Chain           []string `json:"chain"`
    FinalTarget     string   `json:"final_target"`
    ExploitSequence []string `json:"exploit_sequence"`
    Impact          string   `json:"impact"`
    Complexity      string   `json:"complexity"`
}