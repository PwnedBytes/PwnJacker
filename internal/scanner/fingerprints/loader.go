package fingerprints

import (
    "fmt"
    "io/ioutil"
    "path/filepath"
    "strings"

    "gopkg.in/yaml.v3"
)

type FingerprintFile struct {
    Version  string    `yaml:"version"`
    Updated  string    `yaml:"updated"`
    Services []Service `yaml:"services"`  // Use Service type from manager.go
}

type Loader struct {
    fingerprintDir string
}

func NewLoader(dir string) *Loader {
    return &Loader{fingerprintDir: dir}
}

func (l *Loader) LoadAll() ([]FingerprintFile, error) {
    files, err := ioutil.ReadDir(l.fingerprintDir)
    if err != nil {
        return nil, err
    }

    var result []FingerprintFile
    for _, f := range files {
        if f.IsDir() || !strings.HasSuffix(f.Name(), ".yaml") {
            continue
        }
        path := filepath.Join(l.fingerprintDir, f.Name())
        fpFile, err := l.LoadFile(path)
        if err != nil {
            fmt.Printf("Warning: failed to load %s: %v\n", path, err)
            continue
        }
        result = append(result, *fpFile)
    }
    return result, nil
}

func (l *Loader) LoadFile(path string) (*FingerprintFile, error) {
    data, err := ioutil.ReadFile(path)
    if err != nil {
        return nil, err
    }

    var fpFile FingerprintFile
    if err := yaml.Unmarshal(data, &fpFile); err != nil {
        return nil, fmt.Errorf("failed to parse YAML in %s: %v", path, err)
    }

    if fpFile.Version == "" {
        return nil, fmt.Errorf("missing version in %s", path)
    }
    return &fpFile, nil
}

func (l *Loader) MergeIntoManager(mgr *Manager) error {
    files, err := l.LoadAll()
    if err != nil {
        return err
    }
    for _, file := range files {
        for _, svc := range file.Services {
            if err := mgr.AddService(svc); err != nil {
                fmt.Printf("Warning: could not add service %s: %v\n", svc.Name, err)
            }
        }
    }
    return nil
}