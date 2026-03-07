package detectors

import (
    "context"
    "PwnJacker/internal/models"
)

// Detector is the interface that all vulnerability detectors must implement.
type Detector interface {
    // Name returns the detector's name.
    Name() string

    // IsEnabled indicates whether the detector is active.
    IsEnabled() bool

    // Detect performs the detection logic on the given domain.
    // Returns a Vulnerability if found, otherwise nil.
    Detect(ctx context.Context, domain string) *models.Vulnerability
}

// BaseDetector provides common fields and default methods for detectors.
type BaseDetector struct {
    DetectorName string
    Enabled      bool
}

// Name returns the detector's name.
func (b *BaseDetector) Name() string {
    return b.DetectorName
}

// IsEnabled returns whether the detector is enabled.
func (b *BaseDetector) IsEnabled() bool {
    return b.Enabled
}

// NewBaseDetector creates a BaseDetector with the given name and enabled status.
func NewBaseDetector(name string, enabled bool) *BaseDetector {
    return &BaseDetector{
        DetectorName: name,
        Enabled:      enabled,
    }
}