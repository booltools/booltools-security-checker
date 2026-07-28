package mcp_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	secmcp "github.com/booltools/security-checker/internal/mcp"
)

const fakeRepoPath = "../fakerepo"

type securityFinding struct {
	RuleID      string
	Severity    string
	Title       string
	Status      string
	Evidence    string
	FixApplied  string
}

func TestAgentSimulation_FullSecurityAudit(t *testing.T) {
	_, _, auditTools, searchTools := setupTestServer(t)
	ctx := context.Background()

	t.Log("=== AGENT SIMULATION: Security Audit of Fake Repository ===")
	t.Log("")

	// Agent reads the repository structure
	repoFiles := discoverRepoFiles(t, fakeRepoPath)
	t.Logf("Agent discovered %d files in the repository", len(repoFiles))

	// Step 1: Agent starts the audit
	t.Log("\n--- Step 1: Starting security audit ---")
	startOutput, err := auditTools.StartAudit(ctx, secmcp.StartAuditInput{
		Language:    "go",
		Platform:    "docker",
		AppliesTo:   "all",
		MinSeverity: "high",
	})
	if err != nil {
		t.Fatalf("StartAudit failed: %v", err)
	}
	t.Logf("Session: %s", startOutput.SessionID)
	t.Logf("Total rules to check: %d", startOutput.TotalRules)
	t.Logf("Rules URL: %s", startOutput.RulesURL)

	// Step 2: Agent gets a batch of rules
	t.Log("\n--- Step 2: Getting rules to check ---")
	rulesOutput, err := auditTools.GetRules(ctx, secmcp.GetRulesInput{
		SessionID: startOutput.SessionID,
		BatchSize: 10,
	})
	if err != nil {
		t.Fatalf("GetRules failed: %v", err)
	}
	t.Logf("Got %d rules to check", len(rulesOutput.Rules))

	// Step 3: Agent checks each rule against the repository
	t.Log("\n--- Step 3: Checking rules against repository ---")
	var findings []securityFinding
	var results []secmcp.RuleResult

	for _, rule := range rulesOutput.Rules {
		finding := agentCheckRule(t, rule, repoFiles)
		findings = append(findings, finding)
		results = append(results, secmcp.RuleResult{
			RuleID:   rule.ID,
			Status:   finding.Status,
			Evidence: finding.Evidence,
		})
	}

	// Step 4: Agent reports results
	t.Log("\n--- Step 4: Reporting results to MCP ---")
	reportOutput, err := auditTools.ReportResults(ctx, secmcp.ReportResultsInput{
		SessionID: startOutput.SessionID,
		Results:   results,
	})
	if err != nil {
		t.Fatalf("ReportResults failed: %v", err)
	}
	t.Logf("Progress: %s", reportOutput.Progress)

	// Step 5: Agent also does targeted searches for specific known issues
	t.Log("\n--- Step 5: Targeted searches for known vulnerability patterns ---")

	targetedChecks := []struct {
		query    string
		checkFn  func([]secmcp.RuleForAgent) securityFinding
	}{
		{
			query: "hardcoded credentials",
			checkFn: func(rules []secmcp.RuleForAgent) securityFinding {
				return checkHardcodedCredentials(t, repoFiles)
			},
		},
		{
			query: "SQL injection",
			checkFn: func(rules []secmcp.RuleForAgent) securityFinding {
				return checkSQLInjection(t, repoFiles)
			},
		},
		{
			query: "command injection",
			checkFn: func(rules []secmcp.RuleForAgent) securityFinding {
				return checkCommandInjection(t, repoFiles)
			},
		},
		{
			query: "path traversal",
			checkFn: func(rules []secmcp.RuleForAgent) securityFinding {
				return checkPathTraversal(t, repoFiles)
			},
		},
		{
			query: "cross-site scripting XSS",
			checkFn: func(rules []secmcp.RuleForAgent) securityFinding {
				return checkXSS(t, repoFiles)
			},
		},
	}

	var targetedResults []secmcp.RuleResult
	for _, check := range targetedChecks {
		searchOutput, err := searchTools.SearchRules(ctx, secmcp.SearchRulesInput{
			Query:      check.query,
			MaxResults: 3,
		})
		if err != nil {
			t.Logf("Search for %q failed: %v", check.query, err)
			continue
		}

		if searchOutput.TotalFound > 0 {
			finding := check.checkFn(searchOutput.Rules)
			findings = append(findings, finding)
			targetedResults = append(targetedResults, secmcp.RuleResult{
				RuleID:   finding.RuleID,
				Status:   finding.Status,
				Evidence: finding.Evidence,
			})
			t.Logf("  [%s] %s: %s - %s", finding.Severity, finding.RuleID, finding.Title, finding.Status)
		}
	}

	if len(targetedResults) > 0 {
		_, _ = auditTools.ReportResults(ctx, secmcp.ReportResultsInput{
			SessionID: startOutput.SessionID,
			Results:   targetedResults,
		})
	}

	// Step 6: Complete remaining rules to reach report threshold
	t.Log("\n--- Step 6: Completing remaining rules check ---")
	for {
		remainingRules, err := auditTools.GetRules(ctx, secmcp.GetRulesInput{
			SessionID: startOutput.SessionID,
			BatchSize: 50,
		})
		if err != nil || len(remainingRules.Rules) == 0 {
			break
		}
		var batchResults []secmcp.RuleResult
		for _, rule := range remainingRules.Rules {
			finding := agentCheckRule(t, rule, repoFiles)
			findings = append(findings, finding)
			batchResults = append(batchResults, secmcp.RuleResult{
				RuleID:   rule.ID,
				Status:   finding.Status,
				Evidence: finding.Evidence,
			})
		}
		_, _ = auditTools.ReportResults(ctx, secmcp.ReportResultsInput{
			SessionID: startOutput.SessionID,
			Results:   batchResults,
		})
	}

	// Step 7: Get final report
	t.Log("\n--- Step 7: Final audit report ---")
	finalReport, err := auditTools.GetReport(ctx, secmcp.GetReportInput{
		SessionID: startOutput.SessionID,
	})
	if err != nil {
		t.Fatalf("GetReport failed: %v", err)
	}

	t.Logf("Score: %s", finalReport.Score)
	t.Logf("Checked: %d / %d total rules", finalReport.Checked, finalReport.TotalRules)
	t.Logf("Passed: %d | Failed: %d | Skipped: %d", finalReport.Passed, finalReport.Failed, finalReport.Skipped)

	// Step 7: Print all findings summary
	t.Log("\n--- Step 8: Findings Summary ---")
	failCount := 0
	for _, finding := range findings {
		if finding.Status == "fail" {
			failCount++
			t.Logf("  FAIL [%s] %s: %s", finding.Severity, finding.RuleID, finding.Title)
			t.Logf("       Evidence: %s", finding.Evidence)
			if finding.FixApplied != "" {
				t.Logf("       Fix: %s", finding.FixApplied)
			}
		}
	}

	t.Logf("\nTotal vulnerabilities found: %d", failCount)

	// Verify the agent found issues
	if failCount == 0 {
		t.Error("Expected the agent to find vulnerabilities in the fake repo")
	}
	if failCount < 3 {
		t.Errorf("Expected at least 3 vulnerabilities, only found %d", failCount)
	}
}

func discoverRepoFiles(t *testing.T, repoPath string) map[string]string {
	t.Helper()
	files := make(map[string]string)

	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		relevantExtensions := map[string]bool{
			".go": true, ".mod": true, ".yaml": true, ".yml": true,
			".json": true, ".toml": true, ".env": true, "": true,
		}

		baseName := filepath.Base(path)
		if relevantExtensions[ext] || baseName == "Dockerfile" || baseName == "docker-compose.yml" {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			relPath, _ := filepath.Rel(repoPath, path)
			files[relPath] = string(data)
		}
		return nil
	})

	if err != nil {
		t.Logf("Warning: error walking repo: %v", err)
	}
	return files
}

func agentCheckRule(t *testing.T, rule secmcp.RuleForAgent, repoFiles map[string]string) securityFinding {
	t.Helper()

	finding := securityFinding{
		RuleID:   rule.ID,
		Severity: rule.Severity,
		Title:    rule.Title,
		Status:   "pass",
	}

	instruction := strings.ToLower(rule.CheckInstruction)

	for filePath, content := range repoFiles {
		contentLower := strings.ToLower(content)

		if containsCredentialPattern(instruction) && containsHardcodedCredential(content) {
			finding.Status = "fail"
			finding.Evidence = fmt.Sprintf("Hardcoded credential found in %s", filePath)
			finding.FixApplied = "Move secrets to environment variables"
			return finding
		}

		if containsSQLPattern(instruction) && containsSQLInjection(content) {
			finding.Status = "fail"
			finding.Evidence = fmt.Sprintf("SQL injection vulnerability in %s - string concatenation in query", filePath)
			finding.FixApplied = "Use parameterized queries"
			return finding
		}

		if containsCommandPattern(instruction) && containsCommandInjection(content) {
			finding.Status = "fail"
			finding.Evidence = fmt.Sprintf("Command injection in %s - user input passed to exec", filePath)
			finding.FixApplied = "Validate and sanitize input, use allowlist"
			return finding
		}

		if containsPathPattern(instruction) && containsPathTraversal(contentLower) {
			finding.Status = "fail"
			finding.Evidence = fmt.Sprintf("Path traversal in %s - user input used in file path", filePath)
			finding.FixApplied = "Validate path, use filepath.Clean, restrict to base directory"
			return finding
		}

		if containsXSSPattern(instruction) && containsXSSVulnerability(content) {
			finding.Status = "fail"
			finding.Evidence = fmt.Sprintf("XSS vulnerability in %s - unescaped user input in HTML", filePath)
			finding.FixApplied = "Use html/template for escaping"
			return finding
		}
	}

	return finding
}

func checkHardcodedCredentials(t *testing.T, repoFiles map[string]string) securityFinding {
	t.Helper()
	for filePath, content := range repoFiles {
		if containsHardcodedCredential(content) {
			return securityFinding{
				RuleID:     "CWE-798-hardcoded",
				Severity:   "critical",
				Title:      "Hardcoded Credentials",
				Status:     "fail",
				Evidence:   fmt.Sprintf("Found hardcoded secrets in %s (API keys, passwords, AWS keys)", filePath),
				FixApplied: "Use environment variables or secret management (Vault, AWS Secrets Manager)",
			}
		}
	}
	return securityFinding{RuleID: "CWE-798-hardcoded", Title: "Hardcoded Credentials", Status: "pass", Severity: "critical"}
}

func checkSQLInjection(t *testing.T, repoFiles map[string]string) securityFinding {
	t.Helper()
	for filePath, content := range repoFiles {
		if containsSQLInjection(content) {
			return securityFinding{
				RuleID:     "CWE-89-sqli",
				Severity:   "critical",
				Title:      "SQL Injection",
				Status:     "fail",
				Evidence:   fmt.Sprintf("SQL injection via string concatenation in %s", filePath),
				FixApplied: "Replace fmt.Sprintf/concatenation with parameterized queries ($1, $2)",
			}
		}
	}
	return securityFinding{RuleID: "CWE-89-sqli", Title: "SQL Injection", Status: "pass", Severity: "critical"}
}

func checkCommandInjection(t *testing.T, repoFiles map[string]string) securityFinding {
	t.Helper()
	for filePath, content := range repoFiles {
		if containsCommandInjection(content) {
			return securityFinding{
				RuleID:     "CWE-78-cmdi",
				Severity:   "critical",
				Title:      "OS Command Injection",
				Status:     "fail",
				Evidence:   fmt.Sprintf("User input passed directly to exec.Command in %s", filePath),
				FixApplied: "Validate input against allowlist, never pass raw user input to shell",
			}
		}
	}
	return securityFinding{RuleID: "CWE-78-cmdi", Title: "OS Command Injection", Status: "pass", Severity: "critical"}
}

func checkPathTraversal(t *testing.T, repoFiles map[string]string) securityFinding {
	t.Helper()
	for filePath, content := range repoFiles {
		if containsPathTraversal(strings.ToLower(content)) {
			return securityFinding{
				RuleID:     "CWE-22-path",
				Severity:   "high",
				Title:      "Path Traversal",
				Status:     "fail",
				Evidence:   fmt.Sprintf("User-controlled file path in %s allows reading arbitrary files", filePath),
				FixApplied: "Use filepath.Clean, validate against base directory, reject '..' sequences",
			}
		}
	}
	return securityFinding{RuleID: "CWE-22-path", Title: "Path Traversal", Status: "pass", Severity: "high"}
}

func checkXSS(t *testing.T, repoFiles map[string]string) securityFinding {
	t.Helper()
	for filePath, content := range repoFiles {
		if containsXSSVulnerability(content) {
			return securityFinding{
				RuleID:     "CWE-79-xss",
				Severity:   "high",
				Title:      "Cross-Site Scripting (XSS)",
				Status:     "fail",
				Evidence:   fmt.Sprintf("Unescaped user input written to HTML response in %s", filePath),
				FixApplied: "Use html/template package for HTML escaping, set Content-Security-Policy header",
			}
		}
	}
	return securityFinding{RuleID: "CWE-79-xss", Title: "Cross-Site Scripting (XSS)", Status: "pass", Severity: "high"}
}

// Pattern detection helpers

func containsCredentialPattern(instruction string) bool {
	patterns := []string{"credential", "password", "secret", "hard-coded", "hardcoded", "api key"}
	for _, p := range patterns {
		if strings.Contains(instruction, p) {
			return true
		}
	}
	return false
}

func containsSQLPattern(instruction string) bool {
	patterns := []string{"sql", "injection", "parameterized", "prepared statement", "query"}
	for _, p := range patterns {
		if strings.Contains(instruction, p) {
			return true
		}
	}
	return false
}

func containsCommandPattern(instruction string) bool {
	patterns := []string{"command", "os command", "exec", "shell", "injection"}
	for _, p := range patterns {
		if strings.Contains(instruction, p) {
			return true
		}
	}
	return false
}

func containsPathPattern(instruction string) bool {
	patterns := []string{"path", "traversal", "directory", "file", "lfi"}
	for _, p := range patterns {
		if strings.Contains(instruction, p) {
			return true
		}
	}
	return false
}

func containsXSSPattern(instruction string) bool {
	patterns := []string{"xss", "cross-site", "script", "escap", "sanitiz", "html"}
	for _, p := range patterns {
		if strings.Contains(instruction, p) {
			return true
		}
	}
	return false
}

func containsHardcodedCredential(content string) bool {
	indicators := []string{
		"Password = \"",
		"SecretKey = \"",
		"APISecretKey",
		"AWSAccessKey",
		"sk_live_",
		"AKIA",
		"adminPassword",
		`Password: "`,
		`SecretKey: "`,
	}
	for _, indicator := range indicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}
	return false
}

func containsSQLInjection(content string) bool {
	sqlPatterns := []string{
		"fmt.Sprintf(\"SELECT",
		"fmt.Sprintf(\"DELETE",
		"fmt.Sprintf(\"INSERT",
		"fmt.Sprintf(\"UPDATE",
		`"SELECT ` + `" +`,
		`"DELETE ` + `" +`,
		`WHERE id = '" + `,
		`WHERE id = " + `,
		`LIKE '%" + `,
	}
	for _, pattern := range sqlPatterns {
		if strings.Contains(content, pattern) {
			return true
		}
	}
	return false
}

func containsCommandInjection(content string) bool {
	if !strings.Contains(content, "exec.Command") {
		return false
	}
	dangerousPatterns := []string{
		`exec.Command("sh", "-c"`,
		`exec.Command("bash", "-c"`,
		`.Query().Get(`,
		`r.URL.Query`,
		`r.FormValue`,
	}
	hasExec := strings.Contains(content, "exec.Command")
	hasUserInput := false
	for _, pattern := range dangerousPatterns {
		if strings.Contains(content, pattern) {
			hasUserInput = true
			break
		}
	}
	return hasExec && hasUserInput
}

func containsPathTraversal(content string) bool {
	hasFileOp := strings.Contains(content, "os.readfile") || strings.Contains(content, "os.open") || strings.Contains(content, "os.create")
	hasUserInput := strings.Contains(content, "r.url.query") || strings.Contains(content, "query().get") || strings.Contains(content, "formvalue")
	return hasFileOp && hasUserInput
}

func containsXSSVulnerability(content string) bool {
	xssPatterns := []string{
		`fmt.Fprintf(w, "<`,
		`w.Write([]byte("<html`,
		`Fprintf(w, "<!DOCTYPE`,
	}
	for _, pattern := range xssPatterns {
		if strings.Contains(content, pattern) {
			if strings.Contains(content, "Query().Get") || strings.Contains(content, "r.URL") {
				return true
			}
		}
	}
	return false
}
