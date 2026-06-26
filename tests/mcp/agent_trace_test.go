package mcp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	secmcp "github.com/booltools/security-checker/internal/mcp"
)

const traceOutputDir = "../../tmp"

type mcpCall struct {
	Step      int         `json:"step"`
	Tool      string      `json:"tool"`
	Timestamp string      `json:"timestamp"`
	Input     interface{} `json:"input"`
	Output    interface{} `json:"output"`
	Error     string      `json:"error,omitempty"`
}

type traceRecorder struct {
	calls []mcpCall
	step  int
}

func newTraceRecorder() *traceRecorder {
	return &traceRecorder{}
}

func (r *traceRecorder) record(tool string, input interface{}, output interface{}, err error) {
	r.step++
	call := mcpCall{
		Step:      r.step,
		Tool:      tool,
		Timestamp: time.Now().Format(time.RFC3339),
		Input:     input,
		Output:    output,
	}
	if err != nil {
		call.Error = err.Error()
	}
	r.calls = append(r.calls, call)
}

func (r *traceRecorder) save(t *testing.T, filename string) {
	t.Helper()

	if err := os.MkdirAll(traceOutputDir, 0755); err != nil {
		t.Fatalf("Failed to create trace output dir: %v", err)
	}

	outputPath := filepath.Join(traceOutputDir, filename)
	data, err := json.MarshalIndent(r.calls, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal trace: %v", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		t.Fatalf("Failed to write trace file: %v", err)
	}

	t.Logf("Trace saved to: %s (%d calls, %d bytes)", outputPath, len(r.calls), len(data))
}

func TestAgentTrace_FullAuditWithIO(t *testing.T) {
	_, _, auditTools, searchTools := setupTestServer(t)
	ctx := context.Background()
	recorder := newTraceRecorder()

	repoFiles := discoverRepoFiles(t, fakeRepoPath)
	t.Logf("Fake repo has %d files", len(repoFiles))

	// === Call 1: start_audit ===
	startInput := secmcp.StartAuditInput{
		Language:    "go",
		Framework:   "",
		Platform:    "docker",
		AppliesTo:   "all",
		MinSeverity: "high",
	}
	startOutput, err := auditTools.StartAudit(ctx, startInput)
	recorder.record("start_audit", startInput, startOutput, err)
	if err != nil {
		t.Fatalf("start_audit failed: %v", err)
	}
	t.Logf("[start_audit] session=%s, total_rules=%d", startOutput.SessionID, startOutput.TotalRules)

	sessionID := startOutput.SessionID

	// === Call 2: get_rules (batch 1) ===
	getRulesInput := secmcp.GetRulesInput{
		SessionID: sessionID,
		BatchSize: 5,
	}
	rulesOutput, err := auditTools.GetRules(ctx, getRulesInput)
	recorder.record("get_rules", getRulesInput, rulesOutput, err)
	if err != nil {
		t.Fatalf("get_rules failed: %v", err)
	}
	t.Logf("[get_rules] got %d rules, remaining=%d", len(rulesOutput.Rules), rulesOutput.Remaining)

	// === Call 3: agent checks each rule against the repo and reports ===
	var batch1Results []secmcp.RuleResult
	for _, rule := range rulesOutput.Rules {
		finding := agentCheckRule(t, rule, repoFiles)
		batch1Results = append(batch1Results, secmcp.RuleResult{
			RuleID:   rule.ID,
			Status:   finding.Status,
			Evidence: finding.Evidence,
		})
	}

	reportInput := secmcp.ReportResultsInput{
		SessionID: sessionID,
		Results:   batch1Results,
	}
	reportOutput, err := auditTools.ReportResults(ctx, reportInput)
	recorder.record("report_results", reportInput, reportOutput, err)
	if err != nil {
		t.Fatalf("report_results failed: %v", err)
	}
	t.Logf("[report_results] progress=%s", reportOutput.Progress)

	// === Call 4: get_rules (batch 2) ===
	getRulesInput2 := secmcp.GetRulesInput{
		SessionID: sessionID,
		BatchSize: 5,
	}
	rulesOutput2, err := auditTools.GetRules(ctx, getRulesInput2)
	recorder.record("get_rules", getRulesInput2, rulesOutput2, err)
	if err != nil {
		t.Fatalf("get_rules (batch 2) failed: %v", err)
	}
	t.Logf("[get_rules] got %d more rules, remaining=%d", len(rulesOutput2.Rules), rulesOutput2.Remaining)

	// === Call 5: targeted search - hardcoded credentials ===
	searchInput1 := secmcp.SearchRulesInput{
		Query:      "hardcoded credentials password secret key",
		MaxResults: 5,
	}
	searchOutput1, err := searchTools.SearchRules(ctx, searchInput1)
	recorder.record("search_rules", searchInput1, searchOutput1, err)
	if err != nil {
		t.Fatalf("search_rules (credentials) failed: %v", err)
	}
	t.Logf("[search_rules] 'hardcoded credentials' found %d rules", searchOutput1.TotalFound)

	credentialFinding := checkHardcodedCredentials(t, repoFiles)
	t.Logf("  -> Agent check result: %s (evidence: %s)", credentialFinding.Status, credentialFinding.Evidence)

	// === Call 6: targeted search - SQL injection ===
	searchInput2 := secmcp.SearchRulesInput{
		Query:      "SQL injection",
		MaxResults: 5,
	}
	searchOutput2, err := searchTools.SearchRules(ctx, searchInput2)
	recorder.record("search_rules", searchInput2, searchOutput2, err)
	if err != nil {
		t.Fatalf("search_rules (SQL injection) failed: %v", err)
	}
	t.Logf("[search_rules] 'SQL injection' found %d rules", searchOutput2.TotalFound)

	sqliResponse := checkSQLInjection(t, repoFiles)
	t.Logf("  -> Agent check result: %s (evidence: %s)", sqliResponse.Status, sqliResponse.Evidence)

	// === Call 7: targeted search - command injection ===
	searchInput3 := secmcp.SearchRulesInput{
		Query:      "OS command injection exec shell",
		MaxResults: 5,
	}
	searchOutput3, err := searchTools.SearchRules(ctx, searchInput3)
	recorder.record("search_rules", searchInput3, searchOutput3, err)
	if err != nil {
		t.Fatalf("search_rules (command injection) failed: %v", err)
	}
	t.Logf("[search_rules] 'command injection' found %d rules", searchOutput3.TotalFound)

	cmdiResponse := checkCommandInjection(t, repoFiles)
	t.Logf("  -> Agent check result: %s (evidence: %s)", cmdiResponse.Status, cmdiResponse.Evidence)

	// === Call 8: targeted search - path traversal ===
	searchInput4 := secmcp.SearchRulesInput{
		Query:      "path traversal directory file read",
		MaxResults: 5,
	}
	searchOutput4, err := searchTools.SearchRules(ctx, searchInput4)
	recorder.record("search_rules", searchInput4, searchOutput4, err)
	if err != nil {
		t.Fatalf("search_rules (path traversal) failed: %v", err)
	}
	t.Logf("[search_rules] 'path traversal' found %d rules", searchOutput4.TotalFound)

	pathFinding := checkPathTraversal(t, repoFiles)
	t.Logf("  -> Agent check result: %s (evidence: %s)", pathFinding.Status, pathFinding.Evidence)

	// === Call 9: targeted search - XSS ===
	searchInput5 := secmcp.SearchRulesInput{
		Query:      "cross-site scripting XSS reflected",
		MaxResults: 5,
	}
	searchOutput5, err := searchTools.SearchRules(ctx, searchInput5)
	recorder.record("search_rules", searchInput5, searchOutput5, err)
	if err != nil {
		t.Fatalf("search_rules (XSS) failed: %v", err)
	}
	t.Logf("[search_rules] 'XSS' found %d rules", searchOutput5.TotalFound)

	xssFinding := checkXSS(t, repoFiles)
	t.Logf("  -> Agent check result: %s (evidence: %s)", xssFinding.Status, xssFinding.Evidence)

	// === Call 10: get_rule_detail on a found credential rule ===
	if searchOutput1.TotalFound > 0 {
		detailInput := secmcp.GetRuleDetailInput{
			RuleID: searchOutput1.Rules[0].ID,
		}
		detailOutput, err := searchTools.GetRuleDetail(ctx, detailInput)
		recorder.record("get_rule_detail", detailInput, detailOutput, err)
		if err == nil {
			t.Logf("[get_rule_detail] %s - %s (severity=%s)", detailOutput.ID, detailOutput.Title, detailOutput.Severity)
		}
	}

	// === Call 11: get_rule_detail on a SQL injection rule ===
	if searchOutput2.TotalFound > 0 {
		detailInput := secmcp.GetRuleDetailInput{
			RuleID: searchOutput2.Rules[0].ID,
		}
		detailOutput, err := searchTools.GetRuleDetail(ctx, detailInput)
		recorder.record("get_rule_detail", detailInput, detailOutput, err)
		if err == nil {
			t.Logf("[get_rule_detail] %s - %s (severity=%s)", detailOutput.ID, detailOutput.Title, detailOutput.Severity)
		}
	}

	// === Call 12: report targeted findings ===
	targetedResults := []secmcp.RuleResult{
		{RuleID: credentialFinding.RuleID, Status: credentialFinding.Status, Evidence: credentialFinding.Evidence},
		{RuleID: sqliResponse.RuleID, Status: sqliResponse.Status, Evidence: sqliResponse.Evidence},
		{RuleID: cmdiResponse.RuleID, Status: cmdiResponse.Status, Evidence: cmdiResponse.Evidence},
		{RuleID: pathFinding.RuleID, Status: pathFinding.Status, Evidence: pathFinding.Evidence},
		{RuleID: xssFinding.RuleID, Status: xssFinding.Status, Evidence: xssFinding.Evidence},
	}

	reportInput2 := secmcp.ReportResultsInput{
		SessionID: sessionID,
		Results:   targetedResults,
	}
	reportOutput2, err := auditTools.ReportResults(ctx, reportInput2)
	recorder.record("report_results", reportInput2, reportOutput2, err)
	if err != nil {
		t.Fatalf("report_results (targeted) failed: %v", err)
	}
	t.Logf("[report_results] progress=%s", reportOutput2.Progress)

	// === Call 13: get_report (final) ===
	getReportInput := secmcp.GetReportInput{
		SessionID: sessionID,
	}
	finalReport, err := auditTools.GetReport(ctx, getReportInput)
	recorder.record("get_report", getReportInput, finalReport, err)
	if err != nil {
		t.Fatalf("get_report failed: %v", err)
	}
	t.Logf("[get_report] score=%s, checked=%d, passed=%d, failed=%d, skipped=%d",
		finalReport.Score, finalReport.Checked, finalReport.Passed, finalReport.Failed, finalReport.Skipped)

	// Save trace
	recorder.save(t, "agent_audit_trace.json")

	// Also save a human-readable summary
	saveReadableSummary(t, recorder.calls, repoFiles)

	// Assertions: the MCP should have returned rules relevant to our fake repo
	if startOutput.TotalRules == 0 {
		t.Error("MCP returned 0 rules - something is wrong with the database")
	}
	if finalReport.Failed == 0 {
		t.Error("Expected the agent to report failures against the vulnerable fake repo")
	}
	if searchOutput1.TotalFound == 0 && searchOutput2.TotalFound == 0 {
		t.Error("Search returned no results for common vulnerability terms")
	}
}

func saveReadableSummary(t *testing.T, calls []mcpCall, repoFiles map[string]string) {
	t.Helper()

	var builder strings.Builder
	builder.WriteString("# MCP Agent Audit Trace - Readable Summary\n")
	builder.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().Format(time.RFC3339)))
	builder.WriteString(fmt.Sprintf("# Fake repo files: %d\n\n", len(repoFiles)))

	builder.WriteString("## Repository Files Analyzed:\n")
	for path := range repoFiles {
		builder.WriteString(fmt.Sprintf("  - %s\n", path))
	}
	builder.WriteString("\n")

	for _, call := range calls {
		builder.WriteString(fmt.Sprintf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"))
		builder.WriteString(fmt.Sprintf("## Step %d: %s\n", call.Step, call.Tool))
		builder.WriteString(fmt.Sprintf("   Time: %s\n\n", call.Timestamp))

		inputJSON, _ := json.MarshalIndent(call.Input, "   ", "  ")
		builder.WriteString(fmt.Sprintf("### INPUT:\n   %s\n\n", string(inputJSON)))

		outputJSON, _ := json.MarshalIndent(call.Output, "   ", "  ")
		outputStr := string(outputJSON)
		if len(outputStr) > 3000 {
			outputStr = outputStr[:3000] + "\n   ... (truncated)"
		}
		builder.WriteString(fmt.Sprintf("### OUTPUT:\n   %s\n\n", outputStr))

		if call.Error != "" {
			builder.WriteString(fmt.Sprintf("### ERROR: %s\n\n", call.Error))
		}
	}

	outputPath := filepath.Join(traceOutputDir, "agent_audit_readable.txt")
	if err := os.WriteFile(outputPath, []byte(builder.String()), 0644); err != nil {
		t.Fatalf("Failed to write readable summary: %v", err)
	}
	t.Logf("Readable summary saved to: %s", outputPath)
}
