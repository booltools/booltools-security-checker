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

func NewSecurityCheckerServer(dbPath string, port string, logger *slog.Logger) (*SecurityCheckerServer, error) {
	database, err := NewRulesDatabase(dbPath, logger)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	sessionManager := NewSessionManager()
	auditTools := NewAuditTools(database, sessionManager, port)
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
- audit_type: "code" (default ~875 rules), "infrastructure" (~2200), "extended" (~8300), "full" (~25000), "dependency", "all"

WORKFLOW after calling start_audit:
1. Download rules file: curl <rules_url> -o tmp/audit_rules.json
2. Read the file from top to bottom. For EACH rule, read its check_instruction field and verify if the codebase satisfies it.
3. DO NOT analyze, count, aggregate, or categorize the rules. Just verify each one sequentially against the code.
4. For each rule, record: {rule_id, status: "pass"|"fail"|"skipped", evidence: "why"}. Save to tmp/audit_results.json.
5. Upload results: curl -X POST <results_url> -H "Content-Type: application/json" -d @tmp/audit_results.json
6. Call get_report for the summary.`,
	}, s.handleStartAudit)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name: "get_rules",
		Description: `Download security rules for the audit session. By default returns ALL rules at once.
Use batch_size parameter only for very large audits (>1000 rules).

PREFERRED: Use the rules_url from start_audit to download rules as a file instead.
The file approach keeps rules out of your context window, saving significant tokens.`,
	}, s.handleGetRules)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name: "report_results",
		Description: `Submit audit results. For each rule, report: pass, fail, or skipped with evidence.
You can submit ALL results in a single call.

ALTERNATIVE: POST a JSON array of results to the results_url from start_audit.`,
	}, s.handleReportResults)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name:        "get_report",
		Description: "Get the final security audit report with score, pass/fail counts, and failed rule details. Requires at least 80% of rules to be checked.",
	}, s.handleGetReport)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name:        "search_rules",
		Description: "Search security rules by keyword, CVE ID, CWE ID, or description.",
	}, s.handleSearchRules)

	gomcp.AddTool(s.mcpServer, &gomcp.Tool{
		Name:        "get_rule_detail",
		Description: "Get full details of a rule (description, remediation, references, CVSS). Use after a rule fails to get fix guidance.",
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
