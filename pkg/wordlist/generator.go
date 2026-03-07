package wordlist

import (
    "bufio"
    "os"
    "strings"
)

type Generator struct {
    baseDomain string
    commonWords []string
    techStacks  []string
    patterns    []string
}

func NewGenerator(baseDomain string) *Generator {
    return &Generator{
        baseDomain: baseDomain,
        commonWords: []string{
            "admin", "api", "app", "apps", "blog", "cdn", "dev", "development",
            "staging", "stage", "test", "testing", "qa", "uat", "demo", "sandbox",
            "portal", "secure", "login", "signin", "auth", "accounts", "account",
            "support", "help", "docs", "documentation", "wiki", "kb", "knowledge",
            "status", "stats", "analytics", "metrics", "monitor", "monitoring",
            "git", "github", "bitbucket", "gitlab", "code", "source", "src",
            "ci", "cd", "jenkins", "travis", "circleci", "build", "jenkins",
            "mail", "email", "smtp", "imap", "pop3", "webmail", "roundcube",
            "cpanel", "whm", "plesk", "webmin", "phpmyadmin", "phpPgAdmin",
            "mysql", "postgres", "redis", "memcached", "elastic", "elasticsearch",
            "kibana", "grafana", "prometheus", "graphite", "statsd",
            "jenkins", "sonar", "sonarqube", "nexus", "artifactory",
            "jira", "confluence", "wiki", "fisheye", "crucible", "bamboo",
            "slack", "discord", "teams", "chat", "mattermost", "rocket",
            "vpn", "openvpn", "wireguard", "proxy", "socks", "squid",
            "db", "database", "sql", "nosql", "mongo", "mongodb", "couch",
            "backup", "backups", "dump", "dumps", "export", "import",
            "old", "new", "beta", "alpha", "gamma", "edge", "canary",
            "public", "private", "internal", "external", "corp", "corporate",
            "partner", "partners", "vendor", "vendors", "client", "clients",
            "customer", "customers", "user", "users", "member", "members",
            "employee", "employees", "staff", "hr", "human-resources",
            "payroll", "salary", "benefits", "insurance", "health",
            "time", "timesheet", "attendance", "leave", "vacation",
            "expense", "expenses", "reimburse", "reimbursement",
            "travel", "booking", "reservation", "hotel", "flight",
            "calendar", "schedule", "meeting", "event", "events",
            "office", "workspace", "desk", "room", "conference",
            "phone", "voip", "sip", "call", "calls", "recording",
            "video", "zoom", "webex", "gotomeeting", "team",
            "training", "learn", "learning", "academy", "edu",
            "course", "courses", "class", "classes", "tutorial",
            "survey", "poll", "feedback", "suggestion", "complaint",
        },
        techStacks: []string{
            "aws", "azure", "gcp", "cloud", "kubernetes", "k8s", "docker",
            "nginx", "apache", "tomcat", "jetty", "jboss", "wildfly",
            "node", "npm", "yarn", "webpack", "gulp", "grunt",
            "react", "vue", "angular", "svelte", "next", "nuxt",
            "php", "python", "ruby", "java", "go", "golang", "rust",
            "laravel", "symfony", "django", "flask", "rails", "spring",
            "wordpress", "joomla", "drupal", "magento", "shopify",
            "mysql", "mariadb", "postgresql", "mongodb", "cassandra",
            "redis", "memcached", "rabbitmq", "kafka", "activemq",
            "elasticsearch", "solr", "sphinx", "lucene",
            "hadoop", "spark", "flink", "storm", "samza",
        },
        patterns: []string{
            "%s",                       // Exact
            "%s-%s",                    // With hyphen
            "%s.%s",                    // With dot
            "%s_%s",                    // With underscore
            "%s%s",                     // Concatenated
            "%s1", "%s2", "%s3",        // Numbered
            "dev-%s", "staging-%s",      // Prefixed
            "%s-dev", "%s-staging",      // Suffixed
            "test-%s", "qa-%s",          // Environment
            "%s-test", "%s-qa",
            "old-%s", "new-%s",          // Version
            "%s-old", "%s-new",
            "v1.%s", "v2.%s",            // Versioned
            "%s-v1", "%s-v2",
            "api-%s", "%s-api",          // API variants
            "app-%s", "%s-app",
            "web-%s", "%s-web",
            "mobile-%s", "%s-mobile",
        },
    }
}

func (g *Generator) Generate() []string {
    wordlist := make(map[string]bool)

    // Add common words
    for _, word := range g.commonWords {
        wordlist[word] = true
    }

    // Add tech stacks
    for _, tech := range g.techStacks {
        wordlist[tech] = true
    }

    // Extract words from base domain
    domainWords := strings.Split(g.baseDomain, ".")
    for _, word := range domainWords {
        if len(word) > 2 {
            wordlist[word] = true
            // Add variations
            wordlist[word+"-dev"] = true
            wordlist["dev-"+word] = true
            wordlist[word+"-api"] = true
            wordlist["api-"+word] = true
        }
    }

    // Generate pattern combinations
    var baseWords []string
    for word := range wordlist {
        baseWords = append(baseWords, word)
    }

    for _, pattern := range g.patterns {
        for _, w1 := range baseWords {
            for _, w2 := range baseWords {
                if w1 != w2 {
                    wordlist[g.formatPattern(pattern, w1, w2)] = true
                }
            }
        }
    }

    // Convert to slice
    result := make([]string, 0, len(wordlist))
    for word := range wordlist {
        result = append(result, word)
    }

    return result
}

func (g *Generator) formatPattern(pattern, w1, w2 string) string {
    switch strings.Count(pattern, "%s") {
    case 1:
        return strings.Replace(pattern, "%s", w1, -1)
    case 2:
        return strings.Replace(strings.Replace(pattern, "%s", w1, 1), "%s", w2, 1)
    default:
        return pattern
    }
}

func (g *Generator) SaveToFile(filename string) error {
    words := g.Generate()
    
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    writer := bufio.NewWriter(file)
    for _, word := range words {
        writer.WriteString(word + "\n")
    }
    writer.Flush()

    return nil
}

func (g *Generator) LoadCustomWords(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        word := strings.TrimSpace(scanner.Text())
        if word != "" && !strings.HasPrefix(word, "#") {
            g.commonWords = append(g.commonWords, word)
        }
    }

    return scanner.Err()
}