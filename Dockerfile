# Multi-stage Dockerfile for subfinder tool
# Follows Gibson tool containerization best practices

# Stage 1: Download subfinder binary
FROM alpine:3.21 AS downloader

# Install download utilities
RUN apk add --no-cache wget unzip

# Download subfinder binary from ProjectDiscovery
ARG SUBFINDER_VERSION=2.6.7
RUN wget -qO /tmp/subfinder.zip \
    "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" && \
    unzip /tmp/subfinder.zip -d /tmp && \
    chmod +x /tmp/subfinder && \
    rm /tmp/subfinder.zip

# Stage 2: Build the Go wrapper
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -a -installsuffix cgo \
    -ldflags '-extldflags "-static"' \
    -o subfinder-tool ./cmd

# Stage 3: Runtime image
FROM alpine:3.21

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata

# Create non-root user gibson with UID 1000
RUN addgroup -g 1000 gibson && \
    adduser -D -u 1000 -G gibson gibson

# Copy subfinder binary from downloader stage
COPY --from=downloader /tmp/subfinder /usr/local/bin/subfinder

# Copy the Go wrapper binary from builder stage
COPY --from=builder /build/subfinder-tool /usr/local/bin/subfinder-tool

# Set ownership
RUN chown gibson:gibson /usr/local/bin/subfinder /usr/local/bin/subfinder-tool

# Expose gRPC port and health port
EXPOSE 50051
EXPOSE 8080

# Add healthcheck using wget to health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/healthz || exit 1

# Run as non-root user
USER gibson

# Set the entrypoint to the Go wrapper
ENTRYPOINT ["/usr/local/bin/subfinder-tool"]
