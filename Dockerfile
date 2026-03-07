# PwnJacker Dockerfile
# Multi-stage build for smaller final image

# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

WORKDIR /app

# Copy go module files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary with optimizations
RUN CGO_ENABLED=0 GOOS=linux go build \
-ldflags="-s -w -X main.version=$(git describe --tags 2>/dev/null || echo 'dev')" \
-trimpath \
-o pwnjacker \
./cmd/pwnjacker

# Final stage
FROM alpine:latest

# Install CA certificates for HTTPS requests
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user for security
RUN addgroup -g 1000 -S pwnjacker && \
adduser -u 1000 -S pwnjacker -G pwnjacker

WORKDIR /home/pwnjacker

# Copy binary and configuration
COPY --from=builder --chown=pwnjacker:pwnjacker /app/pwnjacker /usr/local/bin/
COPY --chown=pwnjacker:pwnjacker configs/fingerprints.yaml /home/pwnjacker/configs/
COPY --chown=pwnjacker:pwnjacker entrypoint.sh /home/pwnjacker/

# Make entrypoint executable
RUN chmod +x /home/pwnjacker/entrypoint.sh

# Switch to non-root user
USER pwnjacker

# Expose dashboard port
EXPOSE 8080

# Set entrypoint
ENTRYPOINT ["/home/pwnjacker/entrypoint.sh"]