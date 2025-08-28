.PHONY: build test lint clean

# Default target
all: build

# Build the binary
build:
	go build -o bin/cryptkeeper ./cmd/cryptkeeper

# Run tests
test:
	go test ./...

# Run linter/vet
lint:
	go vet ./...

# Clean build artifacts
clean:
	rm -rf bin/