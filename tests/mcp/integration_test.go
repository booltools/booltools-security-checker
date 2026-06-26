package mcp_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	secmcp "github.com/booltools/security-checker/internal/mcp"
	"github.com/booltools/security-checker/internal/normalizer"
)

func setupTestDB(t *testing.T) string {
	t.Helper()

	candidates := []string{
		"security_rules.db",
		"../../security_rules.db",
		"./security_rules.db",
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	t.Skip("security_rules.db not found - run 'go run ./cmd/normalize' first")
	return ""
}

func setupTestServer(t *testing.T) (*secmcp.RulesDatabase, *secmcp.SessionManager, *secmcp.AuditTools, *secmcp.SearchTools) {
	t.Helper()

	dbPath := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	database, err := secmcp.NewRulesDatabase(dbPath, logger)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}

	t.Cleanup(func() { database.Close() })

	sessionManager := secmcp.NewSessionManager()
	auditTools := secmcp.NewAuditTools(database, sessionManager)
	searchTools := secmcp.NewSearchTools(database)

	return database, sessionManager, auditTools, searchTools
}

func TestStartAudit_Go_Critical(t *testing.T) {
	_, _, auditTools, _ := setupTestServer(t)
	ctx := context.Background()

	output, err := auditTools.StartAudit(ctx, secmcp.StartAuditInput{
		Language:    "go",
		MinSeverity: "critical",
	})
	if err != nil {
		t.Fatalf("StartAudit failed: %v", err)
	}

	if output.SessionID == "" {
		t.Fatal("expected non-empty session_id")
	}
	if output.TotalRules == 0 {
		t.Fatal("expected at least some critical rules for Go")
	}
	if output.Categories == nil || len(output.Categories) == 0 {
		t.Fatal("expected non-empty categories")
	}

	t.Logf("Audit started: session=%s, total_rules=%d", output.SessionID, output.TotalRules)
	t.Logf("Categories: %v", output.Categories)
}

func TestStartAudit_Python_High(t *testing.T) {
	_, _, auditTools, _ := setupTestServer(t)
	ctx := context.Background()

	output, err := auditTools.StartAudit(ctx, secmcp.StartAuditInput{
		Language:    "python",
		MinSeverity: "high",
	})
	if err != nil {
		t.Fatalf("StartAudit failed: %v", err)
	}

	if output.TotalRules == 0 {
		t.Fatal("expected rules for Python + high severity")
	}
	t.Logf("Python/High audit: %d rules", output.TotalRules)
}

func TestStartAudit_NoResults(t *testing.T) {
	_, _, auditTools, _ := setupTestServer(t)
	ctx := context.Background()

	output, err := auditTools.StartAudit(ctx, secmcp.StartAuditInput{
		Language:    "brainfuck",
		MinSeverity: "critical",
	})
	if err != nil {
		t.Fatalf("StartAudit failed: %v", err)
	}

	if output.TotalRules != 0 {
		t.Logf("Got %d rules for 'brainfuck' (likely from 'all' language rules)", output.TotalRules)
	}
}

func TestGetRules_BatchSize(t *testing.T) {
	_, _, auditTools, _ := setupTestServer(t)
	ctx := context.Background()

	startOutput, _ := auditTools.StartAudit(ctx, secmcp.StartAuditInput{
		Language:    "javascript",
		MinSeverity: "critical",
	})

	if startOutput.SessionID == "" {
		t.Fatal("no session created")
	}

	output, err := auditTools.GetRules(ctx, secmcp.GetRulesInput{
		SessionID: startOutput.SessionID,
		BatchSize: 5,
	})
	if err != nil {
		t.Fatalf("GetRules failed: %v", err)
	}

	if len(output.Rules) == 0 {
		t.Fatal("expected at least 1 rule")
	}
	if len(output.Rules) > 5 {
		t.Errorf("expected max 5 rules, got %d", len(output.Rules))
	}

	for _, rule := range output.Rules {
		if rule.ID == "" {
			t.Error("rule has empty ID")
		}
		if rule.CheckInstruction == "" {
			t.Errorf("rule %s has empty check_instruction", rule.ID)
		}
		if rule.Severity == "" {
			t.Errorf("rule %s has empty severity", rule.ID)
		}
	}

	t.Logf("Got %d rules, remaining=%d", len(output.Rules), output.Remaining)
	for _, rule := range output.Rules {
		t.Logf("  [%s] %s - %s", rule.Severity, rule.ID, rule.Title)
	}
}

func TestGetRules_MaxBatchSizeClamped(t *testing.T) {
	_, _, auditTools, _ := setupTestServer(t)
	ctx := context.Background()

	startOutput, _ := auditTools.StartAudit(ctx, secmcp.StartAuditInput{Language: "go"})

	output, err := auditTools.GetRules(ctx, secmcp.GetRulesInput{
		SessionID: startOutput.SessionID,
		BatchSize: 100,
	})
	if err != nil {
		t.Fatalf("GetRules failed: %v", err)
	}

	if len(output.Rules) > 20 {
		t.Errorf("expected max 20 rules (clamped), got %d", len(output.Rules))
	}
}

func TestReportResults_And_GetReport(t *testing.T) {
	_, _, auditTools, _ := setupTestServer(t)
	ctx := context.Background()

	startOutput, _ := auditTools.StartAudit(ctx, secmcp.StartAuditInput{
		Language:    "go",
		MinSeverity: "critical",
	})

	rulesOutput, _ := auditTools.GetRules(ctx, secmcp.GetRulesInput{
		SessionID: startOutput.SessionID,
		BatchSize: 5,
	})

	var results []secmcp.RuleResult
	for i, rule := range rulesOutput.Rules {
		status := "pass"
		if i == 0 {
			status = "fail"
		}
		if i == 1 {
			status = "skipped"
		}
		results = append(results, secmcp.RuleResult{
			RuleID:   rule.ID,
			Status:   status,
			Evidence: "Test evidence for " + rule.ID,
		})
	}

	reportOutput, err := auditTools.ReportResults(ctx, secmcp.ReportResultsInput{
		SessionID: startOutput.SessionID,
		Results:   results,
	})
	if err != nil {
		t.Fatalf("ReportResults failed: %v", err)
	}

	if reportOutput.Acknowledged != len(results) {
		t.Errorf("expected %d acknowledged, got %d", len(results), reportOutput.Acknowledged)
	}
	if reportOutput.TotalChecked != len(results) {
		t.Errorf("expected %d total checked, got %d", len(results), reportOutput.TotalChecked)
	}
	t.Logf("Report results: %s", reportOutput.Progress)

	// Get final report
	finalReport, err := auditTools.GetReport(ctx, secmcp.GetReportInput{
		SessionID: startOutput.SessionID,
	})
	if err != nil {
		t.Fatalf("GetReport failed: %v", err)
	}

	if finalReport.Failed != 1 {
		t.Errorf("expected 1 failed, got %d", finalReport.Failed)
	}
	if finalReport.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", finalReport.Skipped)
	}
	expectedPassed := len(results) - 2
	if finalReport.Passed != expectedPassed {
		t.Errorf("expected %d passed, got %d", expectedPassed, finalReport.Passed)
	}
	if finalReport.Score == "" {
		t.Error("expected non-empty score")
	}

	t.Logf("Final report: score=%s, passed=%d, failed=%d, skipped=%d",
		finalReport.Score, finalReport.Passed, finalReport.Failed, finalReport.Skipped)

	if len(finalReport.FailedRules) != 1 {
		t.Errorf("expected 1 failed rule detail, got %d", len(finalReport.FailedRules))
	}
}

func TestGetRules_InvalidSession(t *testing.T) {
	_, _, auditTools, _ := setupTestServer(t)
	ctx := context.Background()

	_, err := auditTools.GetRules(ctx, secmcp.GetRulesInput{
		SessionID: "nonexistent-session-id",
		BatchSize: 5,
	})
	if err == nil {
		t.Fatal("expected error for invalid session")
	}
}

func TestSearchRules_ByKeyword(t *testing.T) {
	_, _, _, searchTools := setupTestServer(t)
	ctx := context.Background()

	output, err := searchTools.SearchRules(ctx, secmcp.SearchRulesInput{
		Query:      "SQL injection",
		MaxResults: 5,
	})
	if err != nil {
		t.Fatalf("SearchRules failed: %v", err)
	}

	if output.TotalFound == 0 {
		t.Fatal("expected at least 1 result for 'SQL injection'")
	}
	t.Logf("Search 'SQL injection': %d results", output.TotalFound)
	for _, rule := range output.Rules {
		t.Logf("  [%s] %s - %s", rule.Severity, rule.ID, rule.Title)
	}
}

func TestSearchRules_ByCVEID(t *testing.T) {
	_, _, _, searchTools := setupTestServer(t)
	ctx := context.Background()

	output, err := searchTools.SearchRules(ctx, secmcp.SearchRulesInput{
		Query:      "CVE-2021-44228",
		MaxResults: 5,
	})
	if err != nil {
		t.Fatalf("SearchRules failed: %v", err)
	}

	t.Logf("Search 'CVE-2021-44228': %d results", output.TotalFound)
}

func TestSearchRules_ByCWEID(t *testing.T) {
	_, _, _, searchTools := setupTestServer(t)
	ctx := context.Background()

	output, err := searchTools.SearchRules(ctx, secmcp.SearchRulesInput{
		Query:      "CWE-79",
		MaxResults: 10,
	})
	if err != nil {
		t.Fatalf("SearchRules failed: %v", err)
	}

	if output.TotalFound == 0 {
		t.Fatal("expected at least 1 result for CWE-79")
	}
	t.Logf("Search 'CWE-79': %d results", output.TotalFound)
}

func TestGetRuleDetail_Exists(t *testing.T) {
	_, _, _, searchTools := setupTestServer(t)
	ctx := context.Background()

	output, err := searchTools.GetRuleDetail(ctx, secmcp.GetRuleDetailInput{
		RuleID: "CWE-89",
	})
	if err != nil {
		t.Fatalf("GetRuleDetail failed: %v", err)
	}

	if output.ID != "CWE-89" {
		t.Errorf("expected ID 'CWE-89', got %q", output.ID)
	}
	if output.Source != normalizer.SourceCWE {
		t.Errorf("expected source 'cwe', got %q", output.Source)
	}
	if output.Title == "" {
		t.Error("expected non-empty title")
	}
	if output.CheckInstruction == "" {
		t.Error("expected non-empty check_instruction")
	}
	if output.Severity == "" {
		t.Error("expected non-empty severity")
	}

	t.Logf("Rule detail: %s - %s [%s]", output.ID, output.Title, output.Severity)
	t.Logf("  Check: %s", output.CheckInstruction)
}

func TestGetRuleDetail_NotFound(t *testing.T) {
	_, _, _, searchTools := setupTestServer(t)
	ctx := context.Background()

	_, err := searchTools.GetRuleDetail(ctx, secmcp.GetRuleDetailInput{
		RuleID: "NONEXISTENT-RULE-99999",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent rule")
	}
}

func TestFullAuditWorkflow_EndToEnd(t *testing.T) {
	_, _, auditTools, searchTools := setupTestServer(t)
	ctx := context.Background()

	// Step 1: Agent starts an audit for a Go project on AWS
	t.Log("Step 1: Starting audit for Go/AWS project")
	startOutput, err := auditTools.StartAudit(ctx, secmcp.StartAuditInput{
		Language:    "go",
		Platform:    "aws",
		AppliesTo:   "all",
		MinSeverity: "high",
	})
	if err != nil {
		t.Fatalf("StartAudit failed: %v", err)
	}
	t.Logf("  Session: %s, Total rules: %d", startOutput.SessionID, startOutput.TotalRules)

	// Step 2: Agent fetches first batch of rules
	t.Log("Step 2: Fetching first batch of rules")
	batch1, err := auditTools.GetRules(ctx, secmcp.GetRulesInput{
		SessionID: startOutput.SessionID,
		BatchSize: 3,
	})
	if err != nil {
		t.Fatalf("GetRules batch 1 failed: %v", err)
	}
	t.Logf("  Got %d rules, %d remaining", len(batch1.Rules), batch1.Remaining)

	// Step 3: Agent checks each rule and reports results
	t.Log("Step 3: Reporting results for batch 1")
	var batch1Results []secmcp.RuleResult
	for _, rule := range batch1.Rules {
		batch1Results = append(batch1Results, secmcp.RuleResult{
			RuleID:   rule.ID,
			Status:   "pass",
			Evidence: "No issues found for " + rule.ID,
		})
	}
	_, _ = auditTools.ReportResults(ctx, secmcp.ReportResultsInput{
		SessionID: startOutput.SessionID,
		Results:   batch1Results,
	})

	// Step 4: Agent fetches second batch
	t.Log("Step 4: Fetching second batch")
	batch2, err := auditTools.GetRules(ctx, secmcp.GetRulesInput{
		SessionID: startOutput.SessionID,
		BatchSize: 3,
	})
	if err != nil {
		t.Fatalf("GetRules batch 2 failed: %v", err)
	}
	t.Logf("  Got %d rules, %d remaining", len(batch2.Rules), batch2.Remaining)

	// Step 5: Agent finds an issue in batch 2
	t.Log("Step 5: Reporting mixed results for batch 2")
	var batch2Results []secmcp.RuleResult
	for i, rule := range batch2.Rules {
		status := "pass"
		evidence := "Verified OK"
		if i == 0 {
			status = "fail"
			evidence = "Found vulnerable dependency in go.mod"
		}
		batch2Results = append(batch2Results, secmcp.RuleResult{
			RuleID:   rule.ID,
			Status:   status,
			Evidence: evidence,
		})
	}
	reportOutput, _ := auditTools.ReportResults(ctx, secmcp.ReportResultsInput{
		SessionID: startOutput.SessionID,
		Results:   batch2Results,
	})
	t.Logf("  Progress: %s", reportOutput.Progress)

	// Step 6: Agent searches for more info about the failure
	if len(batch2.Rules) > 0 {
		t.Log("Step 6: Searching for more details on failed rule")
		failedRuleID := batch2.Rules[0].ID
		detail, err := searchTools.GetRuleDetail(ctx, secmcp.GetRuleDetailInput{RuleID: failedRuleID})
		if err == nil {
			t.Logf("  Detail: %s - %s", detail.ID, detail.Title)
			t.Logf("  CVSS: %.1f, KEV: %v", detail.CVSSScore, detail.IsKEV)
		}
	}

	// Step 7: Get final report
	t.Log("Step 7: Getting final report")
	finalReport, err := auditTools.GetReport(ctx, secmcp.GetReportInput{
		SessionID: startOutput.SessionID,
	})
	if err != nil {
		t.Fatalf("GetReport failed: %v", err)
	}

	t.Logf("  Score: %s", finalReport.Score)
	t.Logf("  Checked: %d/%d", finalReport.Checked, finalReport.TotalRules)
	t.Logf("  Passed: %d, Failed: %d, Skipped: %d", finalReport.Passed, finalReport.Failed, finalReport.Skipped)

	if finalReport.Failed != 1 {
		t.Errorf("expected 1 failure, got %d", finalReport.Failed)
	}
	if finalReport.Passed != len(batch1Results)+len(batch2Results)-1 {
		t.Errorf("expected %d passes, got %d", len(batch1Results)+len(batch2Results)-1, finalReport.Passed)
	}
}
