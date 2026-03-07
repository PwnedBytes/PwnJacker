.PHONY: all build clean test install run help

VERSION := 1.0.0
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags="-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

all: clean build

build:
@echo "Building PwnJacker $(VERSION)..."
CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o bin/pwnjacker ./cmd/pwnjacker

build-termux:
@echo "Building for Termux..."
CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build $(LDFLAGS) -trimpath -o bin/pwnjacker-termux ./cmd/pwnjacker

install:
@echo "Installing PwnJacker..."
go install $(LDFLAGS) ./cmd/pwnjacker

clean:
@echo "Cleaning..."
rm -rf bin/ dist/
go clean

test:
@echo "Running tests..."
go test -v ./...

lint:
@echo "Linting..."
golangci-lint run

deps:
@echo "Downloading dependencies..."
go mod download
go mod verify

update-fingerprints:
@echo "Updating fingerprint database..."
curl -o configs/fingerprints.yaml https://raw.githubusercontent.com/PwnedBytes/PwnJacker/main/fingerprints.yaml

run: build
./bin/pwnjacker $(ARGS)

release: clean test build-termux
@echo "Creating release..."
mkdir -p dist
cp bin/pwnjacker-termux dist/
cp configs/fingerprints.yaml dist/
cd dist && tar -czf pwnjacker-termux-$(VERSION).tar.gz pwnjacker-termux fingerprints.yaml
cd dist && sha256sum pwnjacker-termux-$(VERSION).tar.gz > pwnjacker-termux-$(VERSION).tar.gz.sha256

help:
@echo "PwnJacker Makefile"
@echo ""
@echo "Usage:"
@echo " make build - Build for current platform"
@echo " make build-termux - Build for Termux (Android)"
@echo " make install - Install to GOPATH/bin"
@echo " make clean - Remove build artifacts"
@echo " make test - Run tests"
@echo " make lint - Run linter"
@echo " make deps - Download dependencies"
@echo " make update-fingerprints - Update fingerprint database"
@echo " make run ARGS='-l list.txt' - Run with arguments"
@echo " make release - Create release package"