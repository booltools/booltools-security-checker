# Booltools Security Checker

[![CI](https://github.com/booltools/booltools-security-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/booltools/booltools-security-checker/actions/workflows/ci.yml)
[![Release](https://github.com/booltools/booltools-security-checker/actions/workflows/release.yml/badge.svg)](https://github.com/booltools/booltools-security-checker/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev)

Open-source security validation checker that audits any repository or cloud architecture against **thousands of known vulnerabilities** from NVD, CWE, MITRE ATT&CK, CAPEC, Nuclei, CISA KEV, EPSS, Exploit-DB, GitHub Advisory, and OSV.dev.

---

## Features

- **Web UI** — Dark-themed Astro frontend with real-time SSE progress
- **REST API** — Start audits, stream progress, export CSV/Markdown reports
- **MCP Server** — Model Context Protocol server for AI agent integration
- **10+ Data Sources** — NVD, CWE, MITRE ATT&CK, CAPEC, Nuclei, CISA KEV, EPSS, Exploit-DB, GitHub Advisory, OSV.dev
- **Normalized Database** — All sources unified into a single SQLite database with common schema
- **Dockerized** — Multi-stage build with health checks and non-root user

## Quick Start

### Prerequisites

- Go 1.21+
- Node.js 20+

### Install

```bash
git clone https://github.com/booltools/booltools-security-checker.git
cd booltools-security-checker
go mod tidy
cd web && npm install && cd ..
```

### Download & Normalize Security Data

```bash
make crawl      # Download from all security sources
make normalize  # Process into SQLite database
```

### Run

```bash
# Terminal 1 — API server (port 8787)
make dev

# Terminal 2 — Web UI (port 4321)
make web-dev
```

Open **http://localhost:4321** to start scanning.

### Docker

```bash
docker compose up --build
```

## Architecture

```
├── cmd/
│   ├── server/           → HTTP API server (Chi router)
│   ├── mcp-server/       → MCP server for AI agents
│   ├── crawler/          → Data source crawler
│   └── normalize/        → Normalization pipeline
├── internal/
│   ├── api/              → Router, handlers, middleware
│   ├── mcp/             → MCP tools implementation
│   └── normalizer/       → Parsers, schema, enricher
├── web/                  → Astro frontend (SSR)
├── landing/              → Static landing page (GitHub Pages)
└── tests/                → Unit + integration tests
```

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/audit` | Start a security audit |
| `GET` | `/api/audit/:id/progress` | SSE progress stream |
| `GET` | `/api/report/:id` | Full audit report |
| `GET` | `/api/report/:id/export/json` | Download JSON report |
| `GET` | `/api/report/:id/export/csv` | Export CSV |
| `GET` | `/api/report/:id/export/md` | Export Markdown |
| `GET` | `/api/rules?q=query` | Search rules |
| `GET` | `/api/rules/detail?id=rule_id` | Rule details |
| `GET` | `/api/health` | Health check |

### Start an Audit

```bash
curl -X POST http://localhost:8787/api/audit \
  -H "Content-Type: application/json" \
  -d '{"language":"go","platform":"docker","min_severity":"high"}'
```

## Data Sources

| Source | Description | URL |
|--------|-------------|-----|
| **NVD** | NIST National Vulnerability Database — CVEs with CVSS scores | [nvd.nist.gov](https://nvd.nist.gov/) |
| **CWE** | Common Weakness Enumeration — software weakness patterns | [cwe.mitre.org](https://cwe.mitre.org/) |
| **MITRE ATT&CK** | Adversary tactics, techniques, and procedures | [attack.mitre.org](https://attack.mitre.org/) |
| **CAPEC** | Common Attack Pattern Enumeration and Classification | [capec.mitre.org](https://capec.mitre.org/) |
| **Nuclei** | ProjectDiscovery vulnerability detection templates | [github.com/projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) |
| **CISA KEV** | Known Exploited Vulnerabilities catalog | [cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| **EPSS** | Exploit Prediction Scoring System | [first.org/epss](https://www.first.org/epss/) |
| **Exploit-DB** | Public exploit database | [exploit-db.com](https://www.exploit-db.com/) |
| **GitHub Advisory** | GitHub Security Advisories (GHSA) | [github.com/advisories](https://github.com/advisories) |
| **OSV.dev** | Open Source Vulnerabilities (Go, npm, PyPI, etc.) | [osv.dev](https://osv.dev/) |

## MCP Server (AI Agent Integration)

The MCP server lets AI agents programmatically audit code:

```bash
go run ./cmd/mcp-server
```

Available tools: `start_audit`, `get_rules`, `report_results`, `get_report`, `search_rules`, `get_rule_detail`

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `PORT` | `8787` | API server port |
| `DB_PATH` | `security_rules.db` | Path to SQLite database |
| `ALLOWED_ORIGINS` | `*` | CORS allowed origins (comma-separated) |

## Development

```bash
make build      # Build backend binary
make build-mcp  # Build MCP server binary
make build-all  # Build everything
make test       # Run all tests
make lint       # Run go vet
make tidy       # go mod tidy
make clean      # Remove build artifacts
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions, coding guidelines, and how to add new security rules.

## License

[MIT](LICENSE)
