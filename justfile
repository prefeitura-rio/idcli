# List available commands
default:
    @just --list

# Build the CLI
build:
    go build -o idcli

# Run the CLI
run: build
    ./idcli --config config.yaml

# Clean build artifacts
clean:
    rm -f idcli

# Install dependencies
deps:
    go mod tidy

# Format code
fmt:
    go fmt ./...

# Run linter
lint:
    go vet ./...

# Run tests
test:
    go test ./...

# Build for multiple platforms
build-all: clean
    GOOS=linux GOARCH=amd64 go build -o idcli-linux-amd64
    GOOS=darwin GOARCH=amd64 go build -o idcli-darwin-amd64
    GOOS=darwin GOARCH=arm64 go build -o idcli-darwin-arm64
    GOOS=windows GOARCH=amd64 go build -o idcli-windows-amd64.exe

# Development workflow: format, lint, test, and build
dev: fmt lint test build 