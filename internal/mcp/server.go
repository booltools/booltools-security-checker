package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type SecurityCheckerServer struct {
	mcpServer      *gomcp.Server
	database       *RulesDatabase
	sessionManager *SessionManager
	auditTools     *AuditTools
	searchTools    *SearchTools
	logger         *slog.Logger
}

func NewSecurityCheckerServer(dbPath string, logger *slog.Logger) (*SecurityCheckerServer, error) {
	database, err := NewRulesDatabase(dbPath, logger)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	sessionManager := NewSessionManager()
	auditTools := NewAuditTools(database, sessionManager)
	searchTools := NewSearchTools(database)

	mcpServer := gomcp.NewServer(
		&gomcp.Implementation{
			Name:    "security-checker",
			Version: "1.0.0",
		},
		nil,
	)

	server := &SecurityCheckerServer{
		mcpServer:      mcpServer,
		database:       database,
		sessionManager: sessionManager,
		auditTools:     auditTools,
		searchTools:    searchTools,
		logger:         logger,
	}

	server.registerTools()

	return server, nil
}

func (s *SecurityCheckerServer) Run(ctx context.Context) error {
	return s.mcpServer.Run(ctx, &gomcp.StdioTransport{})
}

func (s *SecurityCheckerServer) HTTPHandler() http.Handler {
	return gomcp.NewStreamableHTTPHandler(func(request *http.Request) *gomcp.Server {
		return s.mcpServer
	}, nil)
}

func (s *SecurityCheckerServer) Close() error {
	return s.database.Close()
}

func (s *SecurityCheckerServer) registerTools() {
	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name: "start_audit",
		Description: `Initialize a security audit session. You MUST provide:
- language: the primary language (go, python, javascript, java, etc.)
- tools: array of ALL libraries/tools/runtimes the project uses (e.g. ["react", "express", "postgres", "redis", "docker", "nginx"]). Look at package.json, go.mod, requirements.txt, etc. to find these.
- platform: cloud/infra if applicable (aws, gcp, azure, docker, kubernetes)
- audit_type: one of:
  "code" (default, ~875 rules) — application-level attack patterns (CAPEC), code weaknesses (CWE), and code-relevant MITRE techniques. Best for checking source code of web apps, APIs, and services.
  "infrastructure" (~2200 rules) — OS-level, cloud, and network attack techniques (MITRE ATT&CK + CISA KEV). Best for checking server configs, Docker, K8s, cloud IAM.
  "extended" (~8300 rules) — code patterns + nuclei product-specific templates.
  "full" (~25000 rules) — all non-dependency rules.
  "dependency" — checks vulnerable package versions only.
  "all" — everything.

IMPORTANT: After starting an audit, you MUST iterate through ALL rules using get_rules and report_results until every single rule has been checked. Do NOT skip rules or stop early. The audit is only complete when all rules have been reported.`,
	}, s.handleStartAudit)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name: "get_rules",
		Description: `Get the next batch of security rules to check. Each rule includes a check_instruction that tells you exactly what to verify in the codebase.

MANDATORY WORKFLOW: You MUST keep calling get_rules until remaining=0. For EACH rule returned, you MUST check the codebase following the check_instruction and then report the result via report_results. Do NOT skip any rules. Do NOT summarize or batch-skip rules. Every rule deserves individual verification.`,
	}, s.handleGetRules)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name: "report_results",
		Description: `Report the results of checking security rules. For each rule, report pass, fail, or skipped with evidence.

RULES:
- You MUST report results for EVERY rule received from get_rules
- Status "skipped" should ONLY be used when the rule is genuinely not applicable (e.g., a Docker rule for a project without Docker)
- You MUST provide evidence for "fail" results explaining what was found
- You MUST provide evidence for "skipped" results explaining why it was skipped
- Do NOT batch-skip rules to finish faster`,
	}, s.handleReportResults)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name: "get_report",
		Description: `Get the final security audit report. This tool will REFUSE to generate a report unless ALL rules have been checked. You must complete the full audit loop (get_rules → check → report_results) for every rule before calling this.`,
	}, s.handleGetReport)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name:        "search_rules",
		Description: "Search security rules by keyword, CVE ID, CWE ID, or description. Useful for investigating specific vulnerabilities.",
	}, s.handleSearchRules)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name:        "get_rule_detail",
		Description: "Get full details of a specific security rule including description, references, CVSS score, and all metadata.",
	}, s.handleGetRuleDetail)
}

func (s *SecurityCheckerServer) handleStartAudit(ctx context.Context, request *gomcp.CallToolRequest, input StartAuditInput) (*gomcp.CallToolResult, StartAuditOutput, error) {
	output, err := s.auditTools.StartAudit(ctx, input)
	if err != nil {
		return nil, StartAuditOutput{}, err
	}
	return nil, output, nil
}

func (s *SecurityCheckerServer) handleGetRules(ctx context.Context, request *gomcp.CallToolRequest, input GetRulesInput) (*gomcp.CallToolResult, GetRulesOutput, error) {
	output, err := s.auditTools.GetRules(ctx, input)
	if err != nil {
		return nil, GetRulesOutput{}, err
	}
	return nil, output, nil
}

func (s *SecurityCheckerServer) handleReportResults(ctx context.Context, request *gomcp.CallToolRequest, input ReportResultsInput) (*gomcp.CallToolResult, ReportResultsOutput, error) {
	output, err := s.auditTools.ReportResults(ctx, input)
	if err != nil {
		return nil, ReportResultsOutput{}, err
	}
	return nil, output, nil
}

func (s *SecurityCheckerServer) handleGetReport(ctx context.Context, request *gomcp.CallToolRequest, input GetReportInput) (*gomcp.CallToolResult, GetReportOutput, error) {
	output, err := s.auditTools.GetReport(ctx, input)
	if err != nil {
		return nil, GetReportOutput{}, err
	}
	return nil, output, nil
}

func (s *SecurityCheckerServer) handleSearchRules(ctx context.Context, request *gomcp.CallToolRequest, input SearchRulesInput) (*gomcp.CallToolResult, SearchRulesOutput, error) {
	output, err := s.searchTools.SearchRules(ctx, input)
	if err != nil {
		return nil, SearchRulesOutput{}, err
	}
	return nil, output, nil
}

func (s *SecurityCheckerServer) handleGetRuleDetail(ctx context.Context, request *gomcp.CallToolRequest, input GetRuleDetailInput) (*gomcp.CallToolResult, GetRuleDetailOutput, error) {
	output, err := s.searchTools.GetRuleDetail(ctx, input)
	if err != nil {
		return nil, GetRuleDetailOutput{}, err
	}
	return nil, output, nil
}
