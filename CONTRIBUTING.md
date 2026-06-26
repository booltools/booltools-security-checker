# Contributing to Booltools Security Checker

Thank you for your interest in contributing! This guide will help you get started.

## Getting Started

### Prerequisites

- **Go** 1.21+
- **Node.js** 20+
- **Make** (optional, for convenience commands)

### Setup

```bash
# Clone the repository
git clone https://github.com/booltools/booltools-security-checker.git
cd booltools-security-checker

# Install Go dependencies
go mod download

# Install frontend dependencies
cd web && npm install && cd ..

# Run tests to verify setup
make test
```

### Running Locally

```bash
# Terminal 1 — Backend
make dev

# Terminal 2 — Frontend
make web-dev
```

The frontend runs at `http://localhost:4321` and proxies API calls to the backend at `:8787`.

## Project Structure

```
├── cmd/                    # Entry points
│   ├── server/             # Web API server
│   ├── mcp-server/         # MCP server for AI agents
│   ├── crawler/            # Data source crawler
│   └── normalize/          # Data normalization pipeline
├── internal/               # Application code
│   ├── api/                # HTTP handlers, router, middleware
│   ├── mcp/                # MCP tool implementations
│   ├── normalizer/         # Parsers, enricher, schema
│   ├── crawler/            # Source crawling logic
│   └── config/             # Configuration
├── tests/                  # Test files
│   ├── mcp/                # MCP integration tests
│   ├── normalizer/         # Parser/database tests
│   └── fakerepo/           # Fake vulnerable repo for testing
├── web/                    # Astro frontend
│   ├── src/pages/          # Pages (index, report, docs)
│   └── src/components/     # Astro components
├── landing/                # Static landing page (GitHub Pages)
└── Makefile
```

## Adding a New Security Data Source

1. **Create the source downloader** in `internal/source/`
2. **Create the parser** in `internal/normalizer/parser_<source>.go`
3. **Register it** in `cmd/normalize/main.go`
4. **Add check instructions** in `internal/normalizer/check_instruction.go`
5. **Write tests** in `tests/normalizer/`
6. **Update the source config** in `config/sources.yaml`

### Parser Pattern

```go
type MySourceParser struct {
    dataDir string
    logger  *slog.Logger
}

func (p *MySourceParser) Name() string { return "my_source" }

func (p *MySourceParser) Parse() ([]SecurityRule, error) {
    // Read data files, transform to SecurityRule structs
    var rules []SecurityRule
    // ...
    return rules, nil
}
```

## Running Tests

```bash
# All tests
make test

# Specific package
go test ./tests/mcp/... -v

# With coverage
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## Code Style

- Use descriptive variable names (no abbreviations)
- Prefer early returns over nested if/else
- Keep functions focused — split long files semantically
- Use dependency injection
- Follow Clean Architecture with DDD principles
- Use English for all code, comments, and variables

## Pull Request Process

1. Fork the repository and create your branch from `master`
2. Make your changes following the code style above
3. Add or update tests as needed
4. Ensure all tests pass: `make test`
5. Ensure Go vet passes: `make lint`
6. Submit a pull request using the PR template
