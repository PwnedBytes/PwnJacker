package cloud

import (
    "context"
    "fmt"
    "net/http"
    "strings"
    "time"

    "PwnJacker/internal/models"
    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/credentials"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/s3"
)

type AWSDetector struct {
    name       string
    enabled    bool
    s3Client   *s3.S3
    httpClient *http.Client
}

func NewAWSDetector() *AWSDetector {
    // Create AWS session with anonymous credentials
    sess := session.Must(session.NewSession(&aws.Config{
        Credentials: credentials.AnonymousCredentials,
        Region:      aws.String("us-east-1"),
    }))

    return &AWSDetector{
        name:     "AWS Cloud Detector",
        enabled:  true,
        s3Client: s3.New(sess),
        httpClient: &http.Client{
            Timeout: 10 * time.Second,
        },
    }
}

func (d *AWSDetector) Name() string {
    return d.name
}

func (d *AWSDetector) IsEnabled() bool {
    return d.enabled
}

func (d *AWSDetector) Detect(ctx context.Context, domain string) *models.Vulnerability {
    // Extract bucket name from domain
    bucketName := d.extractBucketName(domain)
    if bucketName == "" {
        return nil
    }

    // Check S3 bucket
    if vuln := d.checkS3Bucket(ctx, bucketName, domain); vuln != nil {
        return vuln
    }

    // Check CloudFront
    if vuln := d.checkCloudFront(ctx, domain); vuln != nil {
        return vuln
    }

    // Check API Gateway
    if vuln := d.checkAPIGateway(ctx, domain); vuln != nil {
        return vuln
    }

    return nil
}

func (d *AWSDetector) extractBucketName(domain string) string {
    // Handle common S3 bucket domain patterns
    patterns := []string{
        ".s3.amazonaws.com",
        ".s3-website",
        ".s3-",
    }

    for _, pattern := range patterns {
        if idx := strings.Index(domain, pattern); idx > 0 {
            return domain[:idx]
        }
    }

    return ""
}

func (d *AWSDetector) checkS3Bucket(ctx context.Context, bucketName, domain string) *models.Vulnerability {
    // Try to access bucket via S3 API
    input := &s3.HeadBucketInput{
        Bucket: aws.String(bucketName),
    }

    _, err := d.s3Client.HeadBucketWithContext(ctx, input)
    if err != nil {
        if strings.Contains(err.Error(), "NotFound") {
            // Bucket doesn't exist - vulnerable
            return &models.Vulnerability{
                Domain:      domain,
                Type:        "AWS S3 Takeover",
                Service:     "AWS S3",
                Severity:    models.SeverityCritical,
                Description: fmt.Sprintf("S3 bucket '%s' does not exist and can be claimed", bucketName),
                Evidence: map[string]string{
                    "bucket_name": bucketName,
                    "error":       err.Error(),
                },
                Remediation: "Create the S3 bucket or remove the DNS record",
                References: []string{
                    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/website-hosting-custom-domain-walkthrough.html",
                },
                Discovered: time.Now(),
                Verified:   true,
            }
        }
        
        if strings.Contains(err.Error(), "Forbidden") {
            // Bucket exists but is private - check if we can create it
            if d.canClaimBucket(bucketName) {
                return &models.Vulnerability{
                    Domain:      domain,
                    Type:        "AWS S3 Misconfiguration",
                    Service:     "AWS S3",
                    Severity:    models.SeverityHigh,
                    Description: fmt.Sprintf("S3 bucket '%s' exists but may be claimable", bucketName),
                    Evidence: map[string]string{
                        "bucket_name": bucketName,
                        "status":      "bucket exists but may be misconfigured",
                    },
                    Remediation: "Review bucket permissions and ownership",
                    Discovered:  time.Now(),
                    Verified:    true,
                }
            }
        }
    }

    return nil
}

func (d *AWSDetector) canClaimBucket(bucketName string) bool {
    // This would require AWS credentials to attempt bucket creation
    // For now, we'll return false
    return false
}

func (d *AWSDetector) checkCloudFront(ctx context.Context, domain string) *models.Vulnerability {
    // Check if domain is a CloudFront distribution
    url := fmt.Sprintf("https://%s", domain)
    
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return nil
    }

    resp, err := d.httpClient.Do(req)
    if err != nil {
        return nil
    }
    defer resp.Body.Close()

    // Check for CloudFront error responses
    if resp.StatusCode == 403 || resp.StatusCode == 404 {
        server := resp.Header.Get("Server")
        if strings.Contains(server, "CloudFront") {
            // Check if it's the generic error page
            return &models.Vulnerability{
                Domain:      domain,
                Type:        "AWS CloudFront Takeover",
                Service:     "AWS CloudFront",
                Severity:    models.SeverityCritical,
                Description: "CloudFront distribution may be unclaimed",
                Evidence: map[string]string{
                    "status_code": fmt.Sprintf("%d", resp.StatusCode),
                    "server":      server,
                },
                Remediation: "Recreate the CloudFront distribution or remove the DNS record",
                Discovered:  time.Now(),
                Verified:    true,
            }
        }
    }

    return nil
}

func (d *AWSDetector) checkAPIGateway(ctx context.Context, domain string) *models.Vulnerability {
    // Check for API Gateway endpoints
    if strings.Contains(domain, "execute-api") {
        url := fmt.Sprintf("https://%s", domain)
        
        req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
        if err != nil {
            return nil
        }

        resp, err := d.httpClient.Do(req)
        if err != nil {
            return nil
        }
        defer resp.Body.Close()

        if resp.StatusCode == 403 && strings.Contains(resp.Header.Get("x-amzn-ErrorType"), "MissingAuthenticationToken") {
            return &models.Vulnerability{
                Domain:      domain,
                Type:        "AWS API Gateway Takeover",
                Service:     "AWS API Gateway",
                Severity:    models.SeverityHigh,
                Description: "API Gateway endpoint may be unclaimed",
                Evidence: map[string]string{
                    "status_code": fmt.Sprintf("%d", resp.StatusCode),
                    "error_type":  resp.Header.Get("x-amzn-ErrorType"),
                },
                Remediation: "Recreate the API Gateway or remove the DNS record",
                Discovered:  time.Now(),
                Verified:    true,
            }
        }
    }

    return nil
}