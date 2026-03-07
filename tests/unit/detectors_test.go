package unit

import (
    "context"
    "testing"
    "PwnJacker/internal/detectors/cname"
)

func TestCNAMEDetector(t *testing.T) {
    d := cname.NewDetector()
    if d.Name() == "" {
        t.Error("detector name empty")
    }
    // Mock tests would go here
}