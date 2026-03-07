package registry

import (
    "context"
    "sync"

    "PwnJacker/internal/detectors/cname"
    "PwnJacker/internal/detectors/cloud"
    "PwnJacker/internal/detectors/email"
    "PwnJacker/internal/detectors/nxdomain"
    "PwnJacker/internal/detectors/wildcard"
    "PwnJacker/internal/models"
)

type Detector interface {
    Name() string
    Detect(ctx context.Context, domain string) *models.Vulnerability
    IsEnabled() bool
}

var (
    detectors []Detector
    once      sync.Once
)

func InitializeDetectors(deepScan, checkEmail bool) []Detector {
    once.Do(func() {
        // Always enabled detectors
        detectors = append(detectors,
            cname.NewDetector(),
            nxdomain.NewDetector(),
            wildcard.NewDetector(),
        )

        // Cloud detectors (always enabled)
        detectors = append(detectors,
            cloud.NewAWSDetector(),
            cloud.NewAzureDetector(),
            cloud.NewGCPDetector(),
            cloud.NewDigitalOceanDetector(),
        )

        // Email detectors (optional)
        if checkEmail {
            detectors = append(detectors,
                email.NewSPFDetector(),
                email.NewDKIMDetector(),
                email.NewDMARCDetector(),
                email.NewMXDetector(),
            )
        }

        // Deep scan detectors (optional)
        if deepScan {
            // Add more thorough detectors
        }
    })

    return detectors
}