#!/data/data/com.termux/files/usr/bin/bash
# install-termux.sh – Bulletproof PwnJacker installer for Termux
# Handles: git conflicts, go checksum errors, network issues, corrupted caches

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}📦 PwnJacker Termux Installer${NC}"
echo "================================"

# Check if running in Termux
if [ ! -d "/data/data/com.termux" ]; then
    echo -e "${RED}❌ This script must be run in Termux!${NC}"
    exit 1
fi

# Update packages
echo -e "\n${BLUE}📦 Updating Termux packages...${NC}"
pkg update -y && pkg upgrade -y

# Install dependencies
echo -e "\n${BLUE}📦 Installing dependencies...${NC}"
pkg install -y golang git make curl wget

# Create necessary directories
echo -e "\n${BLUE}📁 Creating directories...${NC}"
mkdir -p $HOME/.config/pwnjacker
mkdir -p $HOME/.cache/pwnjacker
mkdir -p $HOME/.local/share/pwnjacker/fingerprints

# Set project directory
PROJECT_DIR="$HOME/PwnJacker"
BACKUP_DIR="$HOME/.pwnjacker-backup-$(date +%s)"

# Function to handle errors
handle_error() {
    echo -e "\n${RED}❌ Error occurred at line $1${NC}"
    echo -e "${YELLOW}💡 Trying recovery methods...${NC}"
}

trap 'handle_error $LINENO' ERR

# Clone or update repository with conflict resolution
echo -e "\n${BLUE}📥 Setting up PwnJacker repository...${NC}"

if [ -d "$PROJECT_DIR/.git" ]; then
    echo "Found existing repository. Checking for issues..."
    cd "$PROJECT_DIR"
    
    # Check if we're in a git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  Corrupted git repo. Backing up and re-cloning...${NC}"
        mv "$PROJECT_DIR" "$BACKUP_DIR"
        git clone https://github.com/PwnedBytes/PwnJacker.git "$PROJECT_DIR"
        cd "$PROJECT_DIR"
    else
        # Check for unstaged/staged changes
        if ! git diff --quiet HEAD 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
            echo -e "${YELLOW}⚠️  Detected local changes. Stashing...${NC}"
            git stash push -m "auto-backup-$(date +%s)" || {
                echo -e "${YELLOW}⚠️  Stash failed, backing up manually...${NC}"
                cp -r "$PROJECT_DIR" "$BACKUP_DIR"
                git reset --hard HEAD
            }
        fi
        
        # Check for untracked files that might interfere
        if [ -n "$(git ls-files --others --exclude-standard)" ]; then
            echo -e "${YELLOW}⚠️  Cleaning untracked files...${NC}"
            git clean -fd
        fi
        
        # Now try to pull
        echo "📥 Pulling latest changes..."
        if ! git pull --rebase origin main 2>/dev/null; then
            echo -e "${YELLOW}⚠️  Pull failed. Trying force reset...${NC}"
            git fetch origin
            git reset --hard origin/main
        fi
        
        # Restore stashed changes if they exist
        if git stash list | grep -q "auto-backup"; then
            echo -e "${YELLOW}📤 Restoring stashed changes...${NC}"
            git stash pop || echo -e "${YELLOW}⚠️  Could not restore stashed changes${NC}"
        fi
    fi
else
    echo "📥 Cloning fresh repository..."
    # Remove any existing directory (not git repo)
    [ -d "$PROJECT_DIR" ] && rm -rf "$PROJECT_DIR"
    git clone https://github.com/PwnedBytes/PwnJacker.git "$PROJECT_DIR"
    cd "$PROJECT_DIR"
fi

# Detect architecture
echo -e "\n${BLUE}🔍 Detecting architecture...${NC}"
ARCH=$(uname -m)
case $ARCH in
    aarch64) GOARCH=arm64 ;;
    armv7l|armv8l) GOARCH=arm ;;
    x86_64) GOARCH=amd64 ;;
    i686) GOARCH=386 ;;
    *) GOARCH=arm64 ;;
esac
echo "Architecture: $ARCH → GOARCH=$GOARCH"

# Clean up Go environment
echo -e "\n${BLUE}🧹 Cleaning Go environment...${NC}"
export GO111MODULE=on
export CGO_ENABLED=0

# Aggressive cache cleaning
go clean -cache 2>/dev/null || true
go clean -modcache 2>/dev/null || true
go clean -testcache 2>/dev/null || true

# Remove problematic files
rm -f go.sum
rm -rf vendor/

# Fix go.mod if corrupted
if [ ! -f "go.mod" ]; then
    echo -e "${YELLOW}⚠️  go.mod missing. Initializing...${NC}"
    go mod init github.com/PwnedBytes/PwnJacker 2>/dev/null || true
fi

# Download dependencies with multiple fallback strategies
echo -e "\n${BLUE}📥 Downloading Go dependencies...${NC}"

# Strategy 1: Standard tidy
if go mod tidy 2>/dev/null; then
    echo -e "${GREEN}✅ Dependencies resolved with standard method${NC}"
else
    echo -e "${YELLOW}⚠️  Standard tidy failed. Trying direct download...${NC}"
    
    # Strategy 2: Direct from source (no proxy)
    export GOPROXY=direct
    if go mod tidy 2>/dev/null; then
        echo -e "${GREEN}✅ Dependencies resolved with direct download${NC}"
    else
        echo -e "${YELLOW}⚠️  Direct download failed. Trying with checksum bypass...${NC}"
        
        # Strategy 3: Disable checksum verification (last resort)
        export GOSUMDB=off
        if go mod tidy 2>/dev/null; then
            echo -e "${GREEN}✅ Dependencies resolved with checksum bypass${NC}"
            echo -e "${YELLOW}⚠️  Warning: Checksum verification disabled${NC}"
        else
            echo -e "${RED}❌ All dependency resolution strategies failed${NC}"
            echo -e "${YELLOW}💡 Trying nuclear option: update all dependencies...${NC}"
            
            # Strategy 4: Update everything
            go get -u ./... 2>/dev/null || true
            go mod tidy || {
                echo -e "${RED}❌ Critical failure. Cannot resolve dependencies.${NC}"
                exit 1
            }
        fi
    fi
fi

# Verify dependencies downloaded
if [ ! -d "$HOME/go/pkg/mod" ] && [ ! -d "$(go env GOPATH)/pkg/mod" ]; then
    echo -e "${YELLOW}⚠️  Warning: Module cache may be empty${NC}"
fi

# Build with multiple attempts
echo -e "\n${BLUE}🔨 Building PwnJacker...${NC}"

BUILD_FLAGS="-ldflags='-s -w' -trimpath"
OUTPUT="$PREFIX/bin/pwnjacker"

# Attempt 1: Standard build
if go build $BUILD_FLAGS -o "$OUTPUT" ./cmd/pwnjacker 2>/dev/null; then
    echo -e "${GREEN}✅ Build successful${NC}"
else
    echo -e "${YELLOW}⚠️  Standard build failed. Trying without flags...${NC}"
    
    # Attempt 2: Simple build
    if go build -o "$OUTPUT" ./cmd/pwnjacker 2>/dev/null; then
        echo -e "${GREEN}✅ Build successful (without optimization flags)${NC}"
    else
        echo -e "${YELLOW}⚠️  Build failed. Checking for syntax errors...${NC}"
        
        # Attempt 3: Check what packages are missing
        go build -o "$OUTPUT" ./cmd/pwnjacker 2>&1 | head -20
        
        echo -e "${YELLOW}💡 Attempting to fix by updating all packages...${NC}"
        go get -u all 2>/dev/null || true
        go mod download all 2>/dev/null || true
        
        if go build -o "$OUTPUT" ./cmd/pwnjacker; then
            echo -e "${GREEN}✅ Build successful after updates${NC}"
        else
            echo -e "${RED}❌ Build failed. Please check the error messages above.${NC}"
            exit 1
        fi
    fi
fi

# Make executable
chmod +x "$OUTPUT"

# Verify installation
if [ -f "$OUTPUT" ]; then
    echo -e "\n${GREEN}✅ Binary created successfully${NC}"
    "$OUTPUT" --version 2>/dev/null || echo -e "${YELLOW}⚠️  Binary exists but version check failed${NC}"
else
    echo -e "${RED}❌ Binary not found at $OUTPUT${NC}"
    exit 1
fi

# Install configuration files
echo -e "\n${BLUE}⚙️ Installing configuration...${NC}"

# Config file
if [ -f "configs/config.yaml" ]; then
    cp configs/config.yaml $HOME/.config/pwnjacker/
    echo "✅ Config installed"
elif [ -f "config.yaml" ]; then
    cp config.yaml $HOME/.config/pwnjacker/
    echo "✅ Config installed"
else
    echo -e "${YELLOW}⚠️  No config.yaml found${NC}"
fi

# Fingerprints
if [ -f "configs/fingerprints.yaml" ]; then
    cp configs/fingerprints.yaml $HOME/.local/share/pwnjacker/
    echo "✅ Fingerprints installed"
elif [ -d "internal/scanner/fingerprints/data" ]; then
    cp internal/scanner/fingerprints/data/*.yaml $HOME/.local/share/pwnjacker/fingerprints/ 2>/dev/null || true
    echo "✅ Fingerprints installed"
else
    echo -e "${YELLOW}⚠️  No fingerprints found${NC}"
fi

# Create alias if not exists
if ! grep -q "alias pwnjacker=" $HOME/.bashrc 2>/dev/null; then
    echo "alias pwnjacker='pwnjacker'" >> $HOME/.bashrc
    echo "✅ Alias added to .bashrc"
fi

# Also add to zsh if exists
if [ -f "$HOME/.zshrc" ] && ! grep -q "alias pwnjacker=" $HOME/.zshrc 2>/dev/null; then
    echo "alias pwnjacker='pwnjacker'" >> $HOME/.zshrc
    echo "✅ Alias added to .zshrc"
fi

# Final summary
echo -e "\n${GREEN}================================${NC}"
echo -e "${GREEN}✅ PwnJacker installed successfully!${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo -e "${BLUE}📍 Location:${NC} $OUTPUT"
echo -e "${BLUE}📝 Config:${NC} $HOME/.config/pwnjacker/"
echo -e "${BLUE}🔍 Fingerprints:${NC} $HOME/.local/share/pwnjacker/"
echo ""
echo -e "${YELLOW}🚀 Usage:${NC}"
echo "   pwnjacker -l subdomains.txt"
echo "   pwnjacker --help"
echo ""
echo -e "${YELLOW}💡 To use immediately, run:${NC} source ~/.bashrc"
echo -e "${YELLOW}🔄 To update later, just run this script again${NC}"

if [ -d "$BACKUP_DIR" ]; then
    echo ""
    echo -e "${BLUE}💾 Backup saved at:${NC} $BACKUP_DIR"
fi

exit 0
