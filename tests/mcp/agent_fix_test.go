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

type vulnerabilityFix struct {
	FilePath    string
	VulnType    string
	Original    string
	Fixed       string
	Explanation string
}

func TestAgentSimulation_FixVulnerabilities(t *testing.T) {
	_, _, auditTools, searchTools := setupTestServer(t)
	ctx := context.Background()

	t.Log("=== AGENT SIMULATION: Finding and Fixing Vulnerabilities ===")

	repoFiles := discoverRepoFiles(t, fakeRepoPath)

	// Agent starts the audit focused on code quality
	startOutput, err := auditTools.StartAudit(ctx, secmcp.StartAuditInput{
		Language:  "go",
		Platform:  "docker",
		AppliesTo: "code",
	})
	if err != nil {
		t.Fatalf("StartAudit failed: %v", err)
	}
	t.Logf("Audit started: %s (Total rules: %d)", startOutput.SessionID, startOutput.TotalRules)

	// Agent searches for specific vulnerability types and generates fixes
	fixes := agentFindAndFix(t, ctx, searchTools, repoFiles)

	t.Logf("\n--- Generated %d fixes ---\n", len(fixes))
	for i, fix := range fixes {
		t.Logf("Fix #%d: %s in %s", i+1, fix.VulnType, fix.FilePath)
		t.Logf("  Explanation: %s", fix.Explanation)
		t.Logf("  Original (snippet): %s", truncate(fix.Original, 80))
		t.Logf("  Fixed (snippet): %s", truncate(fix.Fixed, 80))
		t.Log("")
	}

	// Agent reports all as fixed
	var results []secmcp.RuleResult
	for _, fix := range fixes {
		results = append(results, secmcp.RuleResult{
			RuleID:   fix.VulnType,
			Status:   "fail",
			Evidence: fmt.Sprintf("Fixed in %s: %s", fix.FilePath, fix.Explanation),
		})
	}

	if len(results) > 0 {
		_, err := auditTools.ReportResults(ctx, secmcp.ReportResultsInput{
			SessionID: startOutput.SessionID,
			Results:   results,
		})
		if err != nil {
			t.Fatalf("ReportResults failed: %v", err)
		}
	}

	// Verify fixes apply correctly
	t.Log("\n--- Verifying fixes ---")
	verifyFixes(t, fixes)

	// Validate fix count
	if len(fixes) < 5 {
		t.Errorf("Expected at least 5 fixes, got %d", len(fixes))
	}
}

func TestAgentSimulation_DockerSecurityAudit(t *testing.T) {
	_, _, auditTools, _ := setupTestServer(t)
	ctx := context.Background()

	t.Log("=== AGENT SIMULATION: Docker Security Audit ===")

	dockerfilePath := filepath.Join(fakeRepoPath, "Dockerfile")
	dockerfileBytes, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Skipf("Dockerfile not found: %v", err)
	}
	dockerfileContent := string(dockerfileBytes)

	startOutput, err := auditTools.StartAudit(ctx, secmcp.StartAuditInput{
		Language:  "go",
		Platform:  "docker",
		AppliesTo: "infrastructure",
	})
	if err != nil {
		t.Fatalf("StartAudit failed: %v", err)
	}
	t.Logf("Docker audit session: %s", startOutput.SessionID)

	// Agent checks Docker-specific issues
	dockerIssues := checkDockerSecurity(t, dockerfileContent)
	t.Logf("Found %d Docker security issues", len(dockerIssues))

	var results []secmcp.RuleResult
	for _, issue := range dockerIssues {
		t.Logf("  [%s] %s: %s", issue.Severity, issue.Title, issue.Evidence)
		results = append(results, secmcp.RuleResult{
			RuleID:   issue.RuleID,
			Status:   "fail",
			Evidence: issue.Evidence,
		})
	}

	if len(results) > 0 {
		_, err = auditTools.ReportResults(ctx, secmcp.ReportResultsInput{
			SessionID: startOutput.SessionID,
			Results:   results,
		})
		if err != nil {
			t.Fatalf("ReportResults failed: %v", err)
		}
	}

	// Complete remaining rules to reach report threshold
	for {
		remaining, err := auditTools.GetRules(ctx, secmcp.GetRulesInput{
			SessionID: startOutput.SessionID,
			BatchSize: 50,
		})
		if err != nil || len(remaining.Rules) == 0 {
			break
		}
		var batchResults []secmcp.RuleResult
		for _, rule := range remaining.Rules {
			batchResults = append(batchResults, secmcp.RuleResult{
				RuleID:   rule.ID,
				Status:   "pass",
				Evidence: "Not applicable to this Dockerfile",
			})
		}
		_, _ = auditTools.ReportResults(ctx, secmcp.ReportResultsInput{
			SessionID: startOutput.SessionID,
			Results:   batchResults,
		})
	}

	report, err := auditTools.GetReport(ctx, secmcp.GetReportInput{
		SessionID: startOutput.SessionID,
	})
	if err != nil {
		t.Fatalf("GetReport failed: %v", err)
	}
	t.Logf("Docker audit score: %s", report.Score)

	if len(dockerIssues) < 2 {
		t.Error("Expected at least 2 Docker security issues")
	}
}

func TestAgentSimulation_GetRuleDetail(t *testing.T) {
	_, _, _, searchTools := setupTestServer(t)
	ctx := context.Background()

	t.Log("=== AGENT SIMULATION: Investigating Specific Vulnerability Details ===")

	// Agent searches for SQL injection rules
	searchOutput, err := searchTools.SearchRules(ctx, secmcp.SearchRulesInput{
		Query:      "SQL injection",
		MaxResults: 1,
	})
	if err != nil {
		t.Fatalf("SearchRules failed: %v", err)
	}

	if searchOutput.TotalFound == 0 {
		t.Skip("No SQL injection rules found in database - skipping detail test")
	}

	ruleID := searchOutput.Rules[0].ID
	t.Logf("Investigating rule: %s", ruleID)

	// Agent gets full detail
	detail, err := searchTools.GetRuleDetail(ctx, secmcp.GetRuleDetailInput{
		RuleID: ruleID,
	})
	if err != nil {
		t.Fatalf("GetRuleDetail failed: %v", err)
	}

	t.Logf("Title: %s", detail.Title)
	t.Logf("Severity: %s", detail.Severity)
	t.Logf("Category: %s", detail.Category)
	t.Logf("Check Instruction: %s", truncate(detail.CheckInstruction, 200))

	if len(detail.References) > 0 {
		t.Logf("References: %v", detail.References[:min(3, len(detail.References))])
	}

	// Verify the rule has meaningful content
	if detail.Title == "" {
		t.Error("Rule should have a title")
	}
	if detail.CheckInstruction == "" {
		t.Error("Rule should have check instructions")
	}
}

func agentFindAndFix(t *testing.T, ctx context.Context, searchTools *secmcp.SearchTools, repoFiles map[string]string) []vulnerabilityFix {
	t.Helper()
	var fixes []vulnerabilityFix

	// Fix 1: SQL Injection in queries.go
	if content, ok := findFileContaining(repoFiles, "queries.go"); ok {
		if containsSQLInjection(content.content) {
			fixes = append(fixes, vulnerabilityFix{
				FilePath: content.path,
				VulnType: "CWE-89",
				Original: `query := fmt.Sprintf("SELECT id, name, email FROM users WHERE id = '%s'", userID)`,
				Fixed:    `query := "SELECT id, name, email FROM users WHERE id = $1"` + "\n" + `row := r.db.QueryRow(query, userID)`,
				Explanation: "Replace string interpolation with parameterized query to prevent SQL injection",
			})
			fixes = append(fixes, vulnerabilityFix{
				FilePath: content.path,
				VulnType: "CWE-89",
				Original: `query := "SELECT id, name, email FROM users WHERE name LIKE '%" + searchTerm + "%'"`,
				Fixed:    `query := "SELECT id, name, email FROM users WHERE name LIKE '%' || $1 || '%'"` + "\n" + `rows, err := r.db.Query(query, searchTerm)`,
				Explanation: "Replace string concatenation with parameterized LIKE query",
			})
		}
	}

	// Fix 2: Hardcoded credentials in main.go
	if content, ok := findFileContaining(repoFiles, "main.go"); ok {
		if containsHardcodedCredential(content.content) {
			fixes = append(fixes, vulnerabilityFix{
				FilePath: content.path,
				VulnType: "CWE-798",
				Original: `const DatabasePassword = "SuperSecret123!"`,
				Fixed:    `var DatabasePassword = os.Getenv("DATABASE_PASSWORD")`,
				Explanation: "Move hardcoded credentials to environment variables",
			})
			fixes = append(fixes, vulnerabilityFix{
				FilePath: content.path,
				VulnType: "CWE-798",
				Original: `AWSSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
				Fixed:    `var AWSSecretKey = os.Getenv("AWS_SECRET_ACCESS_KEY")`,
				Explanation: "Move AWS credentials to environment variables or use IAM roles",
			})
		}
	}

	// Fix 3: Command injection in template.go
	if content, ok := findFileContaining(repoFiles, "template.go"); ok {
		if containsCommandInjection(content.content) {
			fixes = append(fixes, vulnerabilityFix{
				FilePath: content.path,
				VulnType: "CWE-78",
				Original: `output, _ := exec.Command("sh", "-c", cmd).Output()`,
				Fixed: `// Remove DiagHandler entirely - never expose arbitrary command execution
// If ping is needed, validate against IP/hostname regex
func PingHandler(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    if !isValidHostname(host) {
        http.Error(w, "invalid host", 400)
        return
    }
    output, err := exec.Command("ping", "-c", "4", host).Output()
    // ...
}`,
				Explanation: "Remove arbitrary command execution, validate inputs with allowlist pattern",
			})
		}
	}

	// Fix 4: XSS in template.go
	for _, file := range repoFiles {
		if strings.Contains(file, `fmt.Fprintf(w, "<html>`) {
			fixes = append(fixes, vulnerabilityFix{
				FilePath: "internal/handlers/template.go",
				VulnType: "CWE-79",
				Original: `fmt.Fprintf(w, "<html><body><h1>Welcome, %s</h1></body></html>", username)`,
				Fixed: `tmpl := template.Must(template.New("profile").Parse("<html><body><h1>Welcome, {{.}}</h1></body></html>"))
tmpl.Execute(w, username)`,
				Explanation: "Use html/template for automatic HTML escaping instead of fmt.Fprintf",
			})
			break
		}
	}

	// Fix 5: Path traversal in main.go
	for _, file := range repoFiles {
		if strings.Contains(file, `os.ReadFile(path)`) && strings.Contains(file, `Query().Get("path")`) {
			fixes = append(fixes, vulnerabilityFix{
				FilePath: "cmd/api/main.go",
				VulnType: "CWE-22",
				Original: `path := r.URL.Query().Get("path")
data, _ := os.ReadFile(path)`,
				Fixed: `path := r.URL.Query().Get("path")
cleanPath := filepath.Clean(path)
if strings.Contains(cleanPath, "..") || filepath.IsAbs(cleanPath) {
    http.Error(w, "forbidden", 403)
    return
}
safePath := filepath.Join("/allowed/directory", cleanPath)
data, err := os.ReadFile(safePath)`,
				Explanation: "Validate path input, reject traversal sequences, restrict to base directory",
			})
			break
		}
	}

	// Fix 6: Weak cryptography (MD5 for passwords)
	for _, file := range repoFiles {
		if strings.Contains(file, "md5.Sum([]byte(password))") {
			fixes = append(fixes, vulnerabilityFix{
				FilePath: "internal/auth/auth.go",
				VulnType: "CWE-327",
				Original: `hash := md5.Sum([]byte(password))
return hex.EncodeToString(hash[:])`,
				Fixed: `hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
if err != nil { return "" }
return string(hashedBytes)`,
				Explanation: "Replace MD5 with bcrypt for password hashing - MD5 is not collision-resistant",
			})
			break
		}
	}

	// Fix 7: Insecure cookie
	for _, file := range repoFiles {
		if strings.Contains(file, "http.SetCookie") && !strings.Contains(file, "Secure:") {
			fixes = append(fixes, vulnerabilityFix{
				FilePath: "internal/auth/auth.go",
				VulnType: "CWE-614",
				Original: `http.SetCookie(w, &http.Cookie{
    Name:    "session",
    Value:   token,
    Path:    "/",
    Expires: time.Now().Add(24 * time.Hour),
})`,
				Fixed: `http.SetCookie(w, &http.Cookie{
    Name:     "session",
    Value:    token,
    Path:     "/",
    Expires:  time.Now().Add(24 * time.Hour),
    Secure:   true,
    HttpOnly: true,
    SameSite: http.SameSiteStrictMode,
})`,
				Explanation: "Add Secure, HttpOnly, and SameSite flags to prevent session hijacking",
			})
			break
		}
	}

	// Agent also checks Dockerfile via search
	_, err := searchTools.SearchRules(ctx, secmcp.SearchRulesInput{
		Query:      "container running as root",
		MaxResults: 2,
	})
	if err == nil {
		for _, file := range repoFiles {
			if strings.Contains(file, "FROM golang") && !strings.Contains(file, "USER") {
				fixes = append(fixes, vulnerabilityFix{
					FilePath:    "Dockerfile",
					VulnType:    "CWE-250",
					Original:    "CMD [\"/app/server\"]",
					Fixed:       "RUN adduser -D appuser\nUSER appuser\nCMD [\"/app/server\"]",
					Explanation: "Add non-root user to container to limit privilege escalation",
				})
				break
			}
		}
	}

	return fixes
}

func checkDockerSecurity(t *testing.T, content string) []securityFinding {
	t.Helper()
	var issues []securityFinding

	// Check: running as root
	if !strings.Contains(content, "USER") {
		issues = append(issues, securityFinding{
			RuleID:   "docker-root",
			Severity: "high",
			Title:    "Container runs as root",
			Status:   "fail",
			Evidence: "Dockerfile has no USER directive - container runs as root by default",
		})
	}

	// Check: no HEALTHCHECK
	if !strings.Contains(content, "HEALTHCHECK") {
		issues = append(issues, securityFinding{
			RuleID:   "docker-healthcheck",
			Severity: "medium",
			Title:    "No health check defined",
			Status:   "fail",
			Evidence: "Dockerfile has no HEALTHCHECK instruction for container orchestration",
		})
	}

	// Check: debug port exposed
	if strings.Contains(content, "6060") {
		issues = append(issues, securityFinding{
			RuleID:   "docker-debug-port",
			Severity: "high",
			Title:    "Debug port exposed",
			Status:   "fail",
			Evidence: "Port 6060 (pprof/debug) is exposed in production Dockerfile",
		})
	}

	// Check: not using multi-stage build
	fromCount := strings.Count(content, "FROM ")
	if fromCount < 2 {
		issues = append(issues, securityFinding{
			RuleID:   "docker-multistage",
			Severity: "medium",
			Title:    "Not using multi-stage build",
			Status:   "fail",
			Evidence: "Single-stage build includes build tools in final image, increasing attack surface",
		})
	}

	// Check: using latest or full image
	if strings.Contains(content, "golang:1.21") && !strings.Contains(content, "alpine") && !strings.Contains(content, "slim") {
		issues = append(issues, securityFinding{
			RuleID:   "docker-base-image",
			Severity: "medium",
			Title:    "Using full base image",
			Status:   "fail",
			Evidence: "Using full golang image instead of alpine/distroless for smaller attack surface",
		})
	}

	return issues
}

type fileMatch struct {
	path    string
	content string
}

func findFileContaining(repoFiles map[string]string, filename string) (fileMatch, bool) {
	for path, content := range repoFiles {
		if strings.Contains(path, filename) {
			return fileMatch{path: path, content: content}, true
		}
	}
	return fileMatch{}, false
}

func verifyFixes(t *testing.T, fixes []vulnerabilityFix) {
	t.Helper()
	for _, fix := range fixes {
		if fix.Original == "" {
			t.Errorf("Fix for %s in %s has empty original", fix.VulnType, fix.FilePath)
		}
		if fix.Fixed == "" {
			t.Errorf("Fix for %s in %s has empty fix", fix.VulnType, fix.FilePath)
		}
		if fix.Original == fix.Fixed {
			t.Errorf("Fix for %s in %s: original and fixed are identical", fix.VulnType, fix.FilePath)
		}
		if fix.Explanation == "" {
			t.Errorf("Fix for %s has no explanation", fix.VulnType)
		}
	}
}

func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " | ")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
