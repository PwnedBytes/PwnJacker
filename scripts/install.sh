#!/data/data/com.termux/files/usr/bin/bash
# scripts/install-termux.sh – PwnJacker installer for Termux

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

# Determine project directory (use current if it's a PwnJacker repo)
if [ -f "cmd/pwnjacker/main.go" ]; then
    PROJECT_DIR=$(pwd)
    echo "📁 Using current directory: $PROJECT_DIR"
else
    PROJECT_DIR="$HOME/pwnjacker"
    echo "📁 Will use $PROJECT_DIR"
fi

# Clone or update repository
if [ -d "$PROJECT_DIR/.git" ]; then
    echo "📥 Updating existing repository at $PROJECT_DIR..."
    cd "$PROJECT_DIR"

    # Stash any local changes (optional – comment out if you want to keep them)
    if ! git diff --quiet; then
        echo "⚠️  Local changes detected. Stashing them temporarily."
        git stash push -m "auto-stash before install"
        STASHED=1
    fi

    # Try to pull with rebase (avoids merge commits)
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

    # Restore stashed changes if any
    if [ "$STASHED" = 1 ]; then
        echo "📦 Restoring local changes."
        git stash pop
    fi
else
    echo "📥 Cloning PwnJacker into $PROJECT_DIR..."
    git clone https://github.com/PwnedBytes/PwnJacker.git "$PROJECT_DIR"
    cd "$PROJECT_DIR"
fi

# Remove existing go.sum to avoid checksum mismatches
echo "🧹 Removing old go.sum to prevent checksum errors..."
rm -f go.sum

# Detect architecture for optimal build
ARCH=$(uname -m)
case $ARCH in
    aarch64) GOARCH=arm64 ;;
    armv7l|armv8l) GOARCH=arm ;;
    x86_64) GOARCH=amd64 ;;
    i686) GOARCH=386 ;;
    *) GOARCH=arm64 ;; # default to arm64
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

# Copy main config if it exists
if [ -f "configs/config.yaml" ]; then
    cp configs/config.yaml $HOME/.config/pwnjacker/
else
    echo "⚠️  config.yaml not found, skipping."
fi

# Handle fingerprints: try combined file first, then split files
if [ -f "configs/fingerprints.yaml" ]; then
    echo "📄 Using combined fingerprints.yaml"
    cp configs/fingerprints.yaml $HOME/.local/share/pwnjacker/
elif [ -d "internal/scanner/fingerprints/data" ]; then
    echo "📄 Using split fingerprint files from internal/scanner/fingerprints/data/"
    cp internal/scanner/fingerprints/data/*.yaml $HOME/.local/share/pwnjacker/fingerprints/
    # Create a symlink or note for the main fingerprints location
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