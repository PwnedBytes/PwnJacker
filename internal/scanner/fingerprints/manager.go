package fingerprints

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "strings"
    "sync"

    "PwnJacker/internal/models"
    "gopkg.in/yaml.v3"
)

type Service struct {
    Name        string   `yaml:"name" json:"name"`
    CNAME       []string `yaml:"cname" json:"cname"`
    Patterns    []string `yaml:"patterns" json:"patterns"`
    StatusCodes []int    `yaml:"status_codes" json:"status_codes"`
    Headers     map[string]string `yaml:"headers" json:"headers"`
    ClaimURL    string   `yaml:"claim_url" json:"claim_url"`
    Remediation string   `yaml:"remediation" json:"remediation"`
    References  []string `yaml:"references" json:"references"`
    Severity    string   `yaml:"severity" json:"severity"`
    CVSS        float64  `yaml:"cvss" json:"cvss"`
    CVE         string   `yaml:"cve" json:"cve"`
}

type FingerprintDB struct {
    Version     string             `yaml:"version" json:"version"`
    Services    []Service          `yaml:"services" json:"services"`
    UpdatedAt   string             `yaml:"updated_at" json:"updated_at"`
    ByCNAME     map[string]Service `yaml:"-" json:"-"`
    ByPattern   map[string]Service `yaml:"-" json:"-"`
}

type Manager struct {
    db     *FingerprintDB
    mu     sync.RWMutex
    loaded bool
}

func NewManager() *Manager {
    m := &Manager{
        db: &FingerprintDB{
            Services: make([]Service, 0),
            ByCNAME:  make(map[string]Service),
            ByPattern: make(map[string]Service),
        },
    }
    
    // Load built-in fingerprints
    m.LoadBuiltin()
    
    return m
}

func (m *Manager) LoadBuiltin() {
    // Built-in fingerprints for common services
    builtin := []Service{
        {
            Name:        "AWS S3",
            CNAME:       []string{"s3.amazonaws.com", "s3-website"},
            Patterns:    []string{"NoSuchBucket", "The specified bucket does not exist"},
            StatusCodes: []int{404},
            Headers:     map[string]string{"Server": "AmazonS3"},
            ClaimURL:    "https://console.aws.amazon.com/s3",
            Remediation: "Recreate the S3 bucket or remove the DNS record",
            Severity:    "CRITICAL",
        },
        {
            Name:        "GitHub Pages",
            CNAME:       []string{"github.io", "github.com"},
            Patterns:    []string{"There isn't a GitHub Pages site here", "404 - File not found"},
            StatusCodes: []int{404},
            ClaimURL:    "https://github.com/new",
            Remediation: "Recreate the GitHub Pages site or remove the DNS record",
            Severity:    "HIGH",
        },
        {
            Name:        "Azure App Service",
            CNAME:       []string{"azurewebsites.net"},
            Patterns:    []string{"404 - Web Site not found", "Azure Web App - Not Found"},
            StatusCodes: []int{404, 410},
            ClaimURL:    "https://portal.azure.com",
            Remediation: "Recreate the Azure App Service or remove the DNS record",
            Severity:    "CRITICAL",
        },
        {
            Name:        "Heroku",
            CNAME:       []string{"herokuapp.com"},
            Patterns:    []string{"No such app", "Heroku | No such app"},
            StatusCodes: []int{404},
            ClaimURL:    "https://dashboard.heroku.com",
            Remediation: "Recreate the Heroku app or remove the DNS record",
            Severity:    "HIGH",
        },
        {
            Name:        "CloudFront",
            CNAME:       []string{"cloudfront.net"},
            Patterns:    []string{"The request could not be satisfied", "BadRequest"},
            StatusCodes: []int{403, 404},
            ClaimURL:    "https://console.aws.amazon.com/cloudfront",
            Remediation: "Recreate the CloudFront distribution or remove the DNS record",
            Severity:    "CRITICAL",
        },
        {
            Name:        "Fastly",
            CNAME:       []string{"fastly.net"},
            Patterns:    []string{"Fastly error: unknown domain"},
            StatusCodes: []int{503},
            ClaimURL:    "https://manage.fastly.com",
            Remediation: "Re-add the domain to Fastly or remove the DNS record",
            Severity:    "HIGH",
        },
        {
            Name:        "Shopify",
            CNAME:       []string{"myshopify.com"},
            Patterns:    []string{"Sorry, this shop is currently unavailable"},
            StatusCodes: []int{404},
            ClaimURL:    "https://www.shopify.com",
            Remediation: "Recreate the Shopify store or remove the DNS record",
            Severity:    "MEDIUM",
        },
        {
            Name:        "Tumblr",
            CNAME:       []string{"tumblr.com"},
            Patterns:    []string{"There's nothing here"},
            StatusCodes: []int{404},
            ClaimURL:    "https://www.tumblr.com",
            Remediation: "Recreate the Tumblr blog or remove the DNS record",
            Severity:    "MEDIUM",
        },
        {
            Name:        "WordPress.com",
            CNAME:       []string{"wordpress.com"},
            Patterns:    []string{"Do you want to register", "No site configured at this address"},
            StatusCodes: []int{404},
            ClaimURL:    "https://wordpress.com/start",
            Remediation: "Recreate the WordPress site or remove the DNS record",
            Severity:    "MEDIUM",
        },
        {
            Name:        "Netlify",
            CNAME:       []string{"netlify.app", "netlify.com"},
            Patterns:    []string{"Not Found - Request ID:", "Page not found"},
            StatusCodes: []int{404},
            ClaimURL:    "https://app.netlify.com",
            Remediation: "Recreate the Netlify site or remove the DNS record",
            Severity:    "HIGH",
        },
        {
            Name:        "Vercel",
            CNAME:       []string{"vercel.app"},
            Patterns:    []string{"The page could not be found", "404: This page could not be found"},
            StatusCodes: []int{404},
            ClaimURL:    "https://vercel.com",
            Remediation: "Recreate the Vercel project or remove the DNS record",
            Severity:    "HIGH",
        },
        {
            Name:        "Surge.sh",
            CNAME:       []string{"surge.sh"},
            Patterns:    []string{"project not found"},
            StatusCodes: []int{404},
            ClaimURL:    "https://surge.sh",
            Remediation: "Recreate the Surge project or remove the DNS record",
            Severity:    "MEDIUM",
        },
        {
            Name:        "ReadTheDocs",
            CNAME:       []string{"readthedocs.io", "readthedocs.org"},
            Patterns:    []string{"No project found", "Project not found"},
            StatusCodes: []int{404},
            ClaimURL:    "https://readthedocs.org",
            Remediation: "Recreate the ReadTheDocs project or remove the DNS record",
            Severity:    "MEDIUM",
        },
        {
            Name:        "SendGrid",
            CNAME:       []string{"sendgrid.net"},
            Patterns:    []string{"The domain you are trying to access is not configured"},
            StatusCodes: []int{404},
            ClaimURL:    "https://app.sendgrid.com",
            Remediation: "Reconfigure SendGrid domain or remove the DNS record",
            Severity:    "HIGH",
        },
        {
            Name:        "Mailgun",
            CNAME:       []string{"mailgun.org"},
            Patterns:    []string{"Domain not found"},
            StatusCodes: []int{404},
            ClaimURL:    "https://app.mailgun.com",
            Remediation: "Recreate the Mailgun domain or remove the DNS record",
            Severity:    "HIGH",
        },
    }
    
    m.mu.Lock()
    defer m.mu.Unlock()
    
    m.db.Services = builtin
    m.rebuildIndex()
    m.loaded = true
}

func (m *Manager) LoadFromFile(path string) error {
    data, err := ioutil.ReadFile(path)
    if err != nil {
        return err
    }
    
    var db FingerprintDB
    if err := yaml.Unmarshal(data, &db); err != nil {
        return err
    }
    
    m.mu.Lock()
    defer m.mu.Unlock()
    
    m.db = &db
    m.rebuildIndex()
    m.loaded = true
    
    return nil
}

func (m *Manager) rebuildIndex() {
    m.db.ByCNAME = make(map[string]Service)
    m.db.ByPattern = make(map[string]Service)
    
    for _, service := range m.db.Services {
        for _, cname := range service.CNAME {
            m.db.ByCNAME[strings.ToLower(cname)] = service
        }
        for _, pattern := range service.Patterns {
            m.db.ByPattern[strings.ToLower(pattern)] = service
        }
    }
}

func (m *Manager) MatchCNAME(cname string) *Service {
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    cnameLower := strings.ToLower(cname)
    
    // Check exact matches first
    if service, ok := m.db.ByCNAME[cnameLower]; ok {
        return &service
    }
    
    // Check partial matches
    for pattern, service := range m.db.ByCNAME {
        if strings.Contains(cnameLower, pattern) {
            return &service
        }
    }
    
    return nil
}

func (m *Manager) MatchResponse(service *Service, resp *models.HTTPResponse) bool {
    if service == nil || resp == nil {
        return false
    }
    
    // Check status code
    if len(service.StatusCodes) > 0 {
        statusMatch := false
        for _, code := range service.StatusCodes {
            if resp.StatusCode == code {
                statusMatch = true
                break
            }
        }
        if !statusMatch {
            return false
        }
    }
    
    // Check body patterns
    if len(service.Patterns) > 0 {
        patternMatch := false
        for _, pattern := range service.Patterns {
            if strings.Contains(resp.Body, pattern) {
                patternMatch = true
                break
            }
        }
        if !patternMatch {
            return false
        }
    }
    
    // Check headers
    if len(service.Headers) > 0 {
        for k, v := range service.Headers {
            if resp.Headers[strings.ToLower(k)] != v {
                return false
            }
        }
    }
    
    return true
}

func (m *Manager) ExportJSON() (string, error) {
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    data, err := json.MarshalIndent(m.db, "", "  ")
    if err != nil {
        return "", err
    }
    
    return string(data), nil
}

func (m *Manager) AddService(service Service) error {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    // Check for duplicates
    for _, s := range m.db.Services {
        if s.Name == service.Name {
            return fmt.Errorf("service %s already exists", service.Name)
        }
    }
    
    m.db.Services = append(m.db.Services, service)
    m.rebuildIndex()
    
    return nil
}

func (m *Manager) GetServices() []Service {
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    return m.db.Services
}

func (m *Manager) GetService(name string) *Service {
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    for _, service := range m.db.Services {
        if service.Name == name {
            return &service
        }
    }
    
    return nil
}