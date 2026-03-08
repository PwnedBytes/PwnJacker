#!/data/data/com.termux/files/usr/bin/bash
# scripts/install-termux.sh – Clean PwnJacker installer for Termux
# No patches – uses code directly from GitHub

set -e

echo "📦 Installing PwnJacker for Termux..."

# Check if running in Termux
if [ ! -d "/data/data/com.termux" ]; then
    echo "❌ This script must be run in Termux!"
    exit 1
fi

# Update packages
echo "📦 Updating Termux packages..."
pkg update -y && pkg upgrade -y

# Install dependencies
echo "📦 Installing dependencies..."
pkg install -y golang git make

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p $HOME/.config/pwnjacker
mkdir -p $HOME/.cache/pwnjacker
mkdir -p $HOME/.local/share/pwnjacker/fingerprints

# Set project directory
PROJECT_DIR="$HOME/PwnJacker"

# Clone or update repository
if [ -d "$PROJECT_DIR/.git" ]; then
    echo "📥 Updating existing repository at $PROJECT_DIR..."
    cd "$PROJECT_DIR"
    git pull --rebase origin main
else
    echo "📥 Cloning PwnJacker into $PROJECT_DIR..."
    git clone https://github.com/PwnedBytes/PwnJacker.git "$PROJECT_DIR"
    cd "$PROJECT_DIR"
fi

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    aarch64) GOARCH=arm64 ;;
    armv7l|armv8l) GOARCH=arm ;;
    x86_64) GOARCH=amd64 ;;
    i686) GOARCH=386 ;;
    *) GOARCH=arm64 ;;
esac
echo "🔍 Detected architecture: $ARCH → GOARCH=$GOARCH"

# Build
echo "🔨 Building PwnJacker..."
export GO111MODULE=on
export CGO_ENABLED=0
go mod tidy
go build -ldflags="-s -w" -trimpath -o $PREFIX/bin/pwnjacker ./cmd/pwnjacker

# Copy configuration files
echo "⚙️ Installing configuration..."
[ -f "configs/config.yaml" ] && cp configs/config.yaml $HOME/.config/pwnjacker/

# Handle fingerprints
if [ -f "configs/fingerprints.yaml" ]; then
    cp configs/fingerprints.yaml $HOME/.local/share/pwnjacker/
elif [ -d "internal/scanner/fingerprints/data" ]; then
    cp internal/scanner/fingerprints/data/*.yaml $HOME/.local/share/pwnjacker/fingerprints/
fi

# Create alias
if ! grep -q "alias pwnjacker=" $HOME/.bashrc; then
    echo "alias pwnjacker='pwnjacker'" >> $HOME/.bashrc
fi

echo "✅ PwnJacker installed successfully!"
echo ""
echo "Usage: pwnjacker -l subdomains.txt [options]"