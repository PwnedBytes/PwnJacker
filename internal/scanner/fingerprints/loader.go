package fingerprints

import (
    "fmt"
    "io/ioutil"
    "path/filepath"
    "strings"

    "PwnJacker/internal/models"
    "gopkg.in/yaml.v3"
)

// FingerprintFile represents the structure of a fingerprint YAML file.
type FingerprintFile struct {
    Version  string                 `yaml:"version"`
    Updated  string                 `yaml:"updated"`
    Services []models.Fingerprint   `yaml:"services"`
}

// Loader handles loading fingerprint definitions from YAML files.
type Loader struct {
    fingerprintDir string
}

// NewLoader creates a new Loader with the given directory containing fingerprint YAMLs.
func NewLoader(dir string) *Loader {
    return &Loader{
        fingerprintDir: dir,
    }
}

// LoadAll loads all fingerprint YAML files from the configured directory.
// It returns a slice of FingerprintFile or an error if any file fails to load.
func (l *Loader) LoadAll() ([]FingerprintFile, error) {
    files, err := ioutil.ReadDir(l.fingerprintDir)
    if err != nil {
        return nil, fmt.Errorf("failed to read fingerprint directory %s: %v", l.fingerprintDir, err)
    }

    var allFingerprints []FingerprintFile
    for _, f := range files {
        if f.IsDir() || !strings.HasSuffix(f.Name(), ".yaml") {
            continue
        }
        path := filepath.Join(l.fingerprintDir, f.Name())
        fpFile, err := l.LoadFile(path)
        if err != nil {
            // Log warning but continue loading other files
            fmt.Printf("Warning: failed to load %s: %v\n", path, err)
            continue
        }
        allFingerprints = append(allFingerprints, *fpFile)
    }
    return allFingerprints, nil
}

// LoadFile loads a single fingerprint YAML file.
func (l *Loader) LoadFile(path string) (*FingerprintFile, error) {
    data, err := ioutil.ReadFile(path)
    if err != nil {
        return nil, err
    }

    var fpFile FingerprintFile
    err = yaml.Unmarshal(data, &fpFile)
    if err != nil {
        return nil, fmt.Errorf("failed to parse YAML in %s: %v", path, err)
    }

    // Validate basic structure
    if fpFile.Version == "" {
        return nil, fmt.Errorf("missing version in %s", path)
    }
    return &fpFile, nil
}

// MergeIntoManager merges all loaded fingerprints into the given Manager.
func (l *Loader) MergeIntoManager(mgr *Manager) error {
    files, err := l.LoadAll()
    if err != nil {
        return err
    }
    for _, file := range files {
        for _, svc := range file.Services {
            // Use Manager's AddService method to add (with duplicate check)
            if err := mgr.AddService(svc); err != nil {
                // Log but continue
                fmt.Printf("Warning: could not add service %s: %v\n", svc.Name, err)
            }
        }
    }
    return nil
}