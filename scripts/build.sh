#!/bin/bash

# PwnJacker Build Script

set -e

VERSION="1.0.0"
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "Building PwnJacker v$VERSION ($COMMIT)..."

# Clean previous builds
rm -rf dist/
mkdir -p dist

# Build for different platforms
build() {
    local GOOS=$1
    local GOARCH=$2
    local EXT=$3
    
    echo "Building for $GOOS/$GOARCH..."
    
    GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 go build \
        -ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.date=$DATE" \
        -trimpath \
        -o "dist/pwnjacker-$VERSION-$GOOS-$GOARCH$EXT" \
        ./cmd/pwnjacker
    
    # Create checksum
    cd dist
    sha256sum "pwnjacker-$VERSION-$GOOS-$GOARCH$EXT" > "pwnjacker-$VERSION-$GOOS-$GOARCH$EXT.sha256"
    cd ..
}

# Linux builds
build "linux" "amd64" ""
build "linux" "386" ""
build "linux" "arm64" ""
build "linux" "arm" ""

# Android/Termux builds
build "android" "arm64" ""
build "android" "arm" ""

# macOS builds
build "darwin" "amd64" ""
build "darwin" "arm64" ""

# Windows builds
build "windows" "amd64" ".exe"
build "windows" "386" ".exe"

# Create fingerprint database
echo "Packaging fingerprint database..."
cp configs/fingerprints.yaml dist/

# Create archive
cd dist
tar -czf "pwnjacker-$VERSION-fingerprints.tar.gz" fingerprints.yaml
cd ..

echo "Build complete! Check the dist/ directory."