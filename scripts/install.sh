#!/data/data/com.termux/files/usr/bin/bash
# scripts/install.sh – PwnJacker installer for Termux
# Uses ~/PwnJacker as the default project directory

set -e  # Exit on any error

echo "📦 Installing PwnJacker for Termux..."

# Check if running in Termux
if [ ! -d "/data/data/com.termux" ]; then
    echo "❌ This script must be run in Termux!"
    exit 1
fi

# Update packages
echo "📦 Updating Termux packages..."
pkg update -y
pkg upgrade -y

# Install dependencies
echo "📦 Installing dependencies..."
pkg install -y golang git make

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p $HOME/.config/pwnjacker
mkdir -p $HOME/.cache/pwnjacker
mkdir -p $HOME/.local/share/pwnjacker/fingerprints

# Set the default project directory to ~/PwnJacker (capital P)
DEFAULT_PROJECT="$HOME/PwnJacker"

# Determine project directory (use current if it's a PwnJacker repo, else use default)
if [ -f "cmd/pwnjacker/main.go" ]; then
    PROJECT_DIR=$(pwd)
    echo "📁 Using current directory: $PROJECT_DIR"
else
    PROJECT_DIR="$DEFAULT_PROJECT"
    echo "📁 Will use default directory: $PROJECT_DIR"
fi

# Clone or update repository
if [ -d "$PROJECT_DIR/.git" ]; then
    echo "📥 Updating existing repository at $PROJECT_DIR..."
    cd "$PROJECT_DIR"

    # Stash any local changes
    if ! git diff --quiet; then
        echo "⚠️  Local changes detected. Stashing them temporarily."
        git stash push -m "auto-stash before install"
        STASHED=1
    fi

    # Try to pull with rebase
    if ! git pull --rebase origin main; then
        echo "⚠️  Pull failed. Attempting to fetch and reset to origin/main..."
        git fetch origin
        if git diff --quiet origin/main; then
            echo "✅ Already up to date."
        else
            echo "⚠️  Your local branch has diverged. Resetting to origin/main (local changes will be lost)."
            git reset --hard origin/main
        fi
    fi

    # Restore stashed changes
    if [ "$STASHED" = 1 ]; then
        echo "📦 Restoring local changes."
        git stash pop
    fi
else
    echo "📥 Cloning PwnJacker into $PROJECT_DIR..."
    git clone https://github.com/PwnedBytes/PwnJacker.git "$PROJECT_DIR"
    cd "$PROJECT_DIR"
fi

# ========== PATCHES AND FIXES ==========

# 1. Prepare embed files for dashboard (copy web files into internal/dashboard)
echo "🔧 Preparing embed files for dashboard..."
mkdir -p internal/dashboard/templates
mkdir -p internal/dashboard/static

if [ -d "web/templates" ]; then
    cp -r web/templates/* internal/dashboard/templates/
else
    echo "⚠️  web/templates not found, skipping."
fi

if [ -d "web/static" ]; then
    cp -r web/static/* internal/dashboard/static/
else
    echo "⚠️  web/static not found, skipping."
fi

# Update server.go to use the new embed paths
SERVER_FILE="internal/dashboard/server.go"
if [ -f "$SERVER_FILE" ]; then
    echo "🔧 Updating embed directive in $SERVER_FILE..."
    sed -i '/^\/\/go:embed/,/var content embed.FS/c\
//go:embed templates/* static/*\
var content embed.FS' "$SERVER_FILE"

    # Update template parsing paths (remove "web/" prefix)
    sed -i 's|"web/templates/|"templates/|g' "$SERVER_FILE"
    sed -i 's|"web/static/|"static/|g' "$SERVER_FILE"
else
    echo "⚠️  $SERVER_FILE not found, skipping embed patch."
fi

# 2. Create missing registry package if it doesn't exist
REGISTRY_DIR="internal/detectors/registry"
REGISTRY_FILE="$REGISTRY_DIR/registry.go"
if [ ! -f "$REGISTRY_FILE" ]; then
    echo "🔧 Creating missing registry package at $REGISTRY_FILE..."
    mkdir -p "$REGISTRY_DIR"
    cat > "$REGISTRY_FILE" << 'EOF'
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
        detectors = append(detectors,
            cname.NewDetector(),
            nxdomain.NewDetector(),
            wildcard.NewDetector(),
        )

        detectors = append(detectors,
            cloud.NewAWSDetector(),
            cloud.NewAzureDetector(),
            cloud.NewGCPDetector(),
            cloud.NewDigitalOceanDetector(),
        )

        if checkEmail {
            detectors = append(detectors,
                email.NewSPFDetector(),
                email.NewDKIMDetector(),
                email.NewDMARCDetector(),
                email.NewMXDetector(),
            )
        }

        // Add deep scan detectors if needed (placeholder)
        _ = deepScan
    })
    return detectors
}
EOF
else
    echo "✅ Registry package already exists."
fi

# 3. Fix duplicate structs in models and checkpoint
echo "🔧 Applying code fixes for duplicate structs..."

# Ensure internal/models/dns.go exists and is correct
if [ ! -f "internal/models/dns.go" ]; then
    cat > "internal/models/dns.go" << 'EOF'
package models

type DNSRecord struct {
    Type    string `json:"type"`
    Name    string `json:"name"`
    Value   string `json:"value"`
    TTL     int    `json:"ttl"`
    Service string `json:"service,omitempty"`
}
EOF
fi

# Ensure internal/models/http.go exists and is correct
if [ ! -f "internal/models/http.go" ]; then
    cat > "internal/models/http.go" << 'EOF'
package models

type HTTPResponse struct {
    StatusCode  int               `json:"status_code"`
    Headers     map[string]string `json:"headers"`
    Body        string            `json:"body,omitempty"`
    BodyHash    string            `json:"body_hash"`
    Title       string            `json:"title,omitempty"`
    Server      string            `json:"server,omitempty"`
    ContentType string            `json:"content_type,omitempty"`
}
EOF
fi

# Remove duplicate checkpoint state file (if it exists)
if [ -f "pkg/checkpoint/state.go" ]; then
    echo "🧹 Removing duplicate pkg/checkpoint/state.go..."
    rm -f "pkg/checkpoint/state.go"
fi

# Add missing import in internal/utils/http.go (if needed)
if grep -q "func HeadersToMap" internal/utils/http.go && ! grep -q '"strings"' internal/utils/http.go; then
    echo "🔧 Adding missing 'strings' import in internal/utils/http.go..."
    sed -i '/^import (/,/^)/ {
        /^import (/ a\
    "strings"
    }' internal/utils/http.go
fi

# Remove old go.sum to avoid checksum mismatches
echo "🧹 Removing old go.sum..."
rm -f go.sum

# Detect architecture for optimal build
ARCH=$(uname -m)
case $ARCH in
    aarch64) GOARCH=arm64 ;;
    armv7l|armv8l) GOARCH=arm ;;
    x86_64) GOARCH=amd64 ;;
    i686) GOARCH=386 ;;
    *) GOARCH=arm64 ;;
esac
echo "🔍 Detected architecture: $ARCH → GOARCH=$GOARCH"

# Tidy modules and download dependencies
echo "🔧 Tidying Go modules (this will regenerate go.sum)..."
export GO111MODULE=on
export CGO_ENABLED=0
go mod tidy

# Build PwnJacker
echo "🔨 Building PwnJacker..."
go build -ldflags="-s -w" -trimpath -o $PREFIX/bin/pwnjacker ./cmd/pwnjacker

# Copy configuration files
echo "⚙️ Installing configuration..."

if [ -f "configs/config.yaml" ]; then
    cp configs/config.yaml $HOME/.config/pwnjacker/
else
    echo "⚠️  config.yaml not found, skipping."
fi

# Handle fingerprints
if [ -f "configs/fingerprints.yaml" ]; then
    echo "📄 Using combined fingerprints.yaml"
    cp configs/fingerprints.yaml $HOME/.local/share/pwnjacker/
elif [ -d "internal/scanner/fingerprints/data" ]; then
    echo "📄 Using split fingerprint files from internal/scanner/fingerprints/data/"
    cp internal/scanner/fingerprints/data/*.yaml $HOME/.local/share/pwnjacker/fingerprints/
    ln -sf $HOME/.local/share/pwnjacker/fingerprints $HOME/.local/share/pwnjacker/fingerprints_data
else
    echo "⚠️  No fingerprint files found. Please obtain them manually."
fi

# Create alias (optional)
if ! grep -q "alias pwnjacker=" $HOME/.bashrc; then
    echo "alias pwnjacker='pwnjacker'" >> $HOME/.bashrc
fi

echo "✅ PwnJacker installed successfully!"
echo ""
echo "Usage examples:"
echo "  pwnjacker -l subdomains.txt"
echo "  pwnjacker -l domains.txt --dashboard :8080"
echo "  pwnjacker -l targets.txt --check-email --deep"
echo ""
echo "Configuration: $HOME/.config/pwnjacker/config.yaml"
if [ -f "$HOME/.local/share/pwnjacker/fingerprints.yaml" ]; then
    echo "Fingerprints: $HOME/.local/share/pwnjacker/fingerprints.yaml"
else
    echo "Fingerprints directory: $HOME/.local/share/pwnjacker/fingerprints/"
fi