.PHONY: build build-mcp build-all run dev test clean lint tidy web-dev web-build normalize crawl

BINARY_NAME=booltools-security-checker
MCP_BINARY=security-checker-mcp

build:
	go build -o bin/$(BINARY_NAME) ./cmd/server

build-mcp:
	go build -o bin/$(MCP_BINARY) ./cmd/mcp-server

build-all: build build-mcp

run: build
	./bin/$(BINARY_NAME)

dev:
	go run ./cmd/server

test:
	go test ./... -v -count=1

lint:
	go vet ./...

tidy:
	go mod tidy

web-dev:
	cd web && npm run dev

web-build:
	cd web && npm run build

normalize:
	go run ./cmd/normalize

crawl:
	go run ./cmd/crawler

clean:
	go clean
	-rm -rf bin 2>/dev/null || rd /s /q bin 2>nul || true
	-rm -f security_rules.db 2>/dev/null || del security_rules.db 2>nul || true
