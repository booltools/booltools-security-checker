.PHONY: build build-mcp build-all run dev test clean lint tidy web-dev web-build normalize crawl deduplicate dbstats

BINARY_NAME=booltools-security-checker
MCP_BINARY=security-checker-mcp

build:
	go build -o bin/$(BINARY_NAME) ./cmd/server

build-mcp:
	go build -o bin/$(MCP_BINARY) ./cmd/mcp-server

build-all: build build-mcp

run: build
	bin\$(BINARY_NAME).exe

dev:
	go build -o bin/$(BINARY_NAME).exe ./cmd/server && bin\$(BINARY_NAME).exe

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
	go build -o bin/normalize.exe ./cmd/normalize && bin\normalize.exe

crawl:
	go build -o bin/crawler.exe ./cmd/crawler && bin\crawler.exe

deduplicate:
	go build -o bin/deduplicate.exe ./cmd/deduplicate && bin\deduplicate.exe

dbstats:
	go build -o bin/dbstats.exe ./cmd/dbstats && bin\dbstats.exe

clean:
	go clean
	-rm -rf bin 2>/dev/null || rd /s /q bin 2>nul || true
	-rm -f security_rules.db 2>/dev/null || del security_rules.db 2>nul || true
