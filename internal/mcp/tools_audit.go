package mcp

import (
	"context"
	"fmt"

	"github.com/booltools/security-checker/internal/normalizer"
)

type AuditTools struct {
	database       *RulesDatabase
	sessionManager *SessionManager
	serverPort     string
}

func NewAuditTools(database *RulesDatabase, sessionManager *SessionManager, serverPort string) *AuditTools {
	return &AuditTools{
		database:       database,
		sessionManager: sessionManager,
		serverPort:     serverPort,
	}
}

func (t *AuditTools) StartAudit(ctx context.Context, input StartAuditInput) (StartAuditOutput, error) {
	filter := normalizer.QueryFilter{
		AppliesTo:   input.AppliesTo,
		MinSeverity: mapMinSeverityToFilter(input.MinSeverity),
	}

	// Filter by audit type to control which rules are served.
	// Default "code" mode only serves rules actually checkable by reading source code.
	switch input.AuditType {
	case "dependency":
		// Only dependency/supply-chain version checks
		filter.Category = "supply_chain"
	case "extended":
		// Code patterns + nuclei product-specific templates
		filter.ExcludeCategories = []string{"supply_chain"}
		filter.Sources = []string{"cwe", "capec", "mitre_attack", "nuclei", "sast_patterns"}
	case "infrastructure":
		// All MITRE techniques + CISA KEV (OS-level, cloud, infra attacks) + IaC + Containers
		filter.ExcludeCategories = []string{"supply_chain"}
		filter.Sources = []string{"mitre_attack", "cisa_kev", "iac", "container"}
	case "secrets":
		// Only hardcoded credentials/secrets detection
		filter.Sources = []string{"secrets"}
	case "iac":
		// Only Infrastructure as Code + container misconfigurations
		filter.Sources = []string{"iac", "container"}
	case "full":
		// All code-level rules (includes exploitdb, nvd, nuclei, sast_patterns, secrets)
		filter.ExcludeCategories = []string{"supply_chain"}
	case "all":
		// Everything including supply_chain
	default:
		// "code" or empty (default) — only rules checkable by reading source code:
		// - ALL CAPEC rules (application-level attack patterns: SQL injection, XSS, CSRF, etc.)
		// - ALL CWE rules (code weaknesses: buffer overflow, improper validation, etc.)
		// - Only code-relevant MITRE techniques (credential access, auth, injection, info exposure)
		// - SAST patterns (language-specific curated rules like Snyk/Aikido)
		// - Secrets detection (hardcoded credentials)
		// Excludes: OS-level MITRE ("other" category: Rundll32, VNC, Screen Capture, etc.)
		// Excludes: product-specific CISA KEV (Cisco, Ubiquiti, Oracle CVEs)
		filter.ExcludeCategories = []string{"supply_chain"}
		filter.Sources = []string{"cwe", "capec", "mitre_attack", "sast_patterns", "secrets"}
		filter.ExcludeSourceCategories = map[string][]string{
			"mitre_attack": {"other"},
		}
	}

	if input.Language != "" {
		filter.Languages = []string{input.Language}
	}
	if input.Framework != "" {
		filter.Frameworks = []string{input.Framework}
	}
	if input.Platform != "" {
		filter.Platforms = []string{input.Platform}
	}
	for _, tool := range input.Tools {
		if tool != "" {
			filter.Frameworks = append(filter.Frameworks, tool)
		}
	}

	totalRules, err := t.database.CountFiltered(filter)
	if err != nil {
		return StartAuditOutput{}, fmt.Errorf("counting rules: %w", err)
	}

	if totalRules == 0 {
		return StartAuditOutput{
			Message: "No rules found matching the specified criteria. Try broadening your filters.",
		}, nil
	}

	session := t.sessionManager.CreateSession(filter, totalRules)

	rulesURL := fmt.Sprintf("http://localhost:%s/audit/%s/rules.json", t.serverPort, session.ID)
	resultsURL := fmt.Sprintf("http://localhost:%s/audit/%s/results", t.serverPort, session.ID)

	return StartAuditOutput{
		SessionID:  session.ID,
		TotalRules: totalRules,
		RulesURL:   rulesURL,
		ResultsURL: resultsURL,
		Message: fmt.Sprintf(
			"%d security rules to check. "+
				"INSTRUCTIONS: "+
				"1) Download rules: curl %s -o tmp/audit_rules.json "+
				"2) Read the file from top to bottom. For EACH rule, read its check_instruction and verify if the codebase satisfies it. "+
				"DO NOT analyze, aggregate, count, or categorize the rules. Just check them one by one sequentially. "+
				"3) For each rule write a result: {rule_id, status (pass/fail/skipped), evidence}. Save all results to tmp/audit_results.json. "+
				"4) POST results: curl -X POST %s -H 'Content-Type: application/json' -d @tmp/audit_results.json "+
				"5) Call get_report for the final summary.",
			totalRules, rulesURL, resultsURL),
	}, nil
}

func (t *AuditTools) GetRules(ctx context.Context, input GetRulesInput) (GetRulesOutput, error) {
	session, err := t.sessionManager.GetSession(input.SessionID)
	if err != nil {
		return GetRulesOutput{}, err
	}

	filter := session.Filter
	filter.Offset = session.CurrentIndex

	if input.BatchSize > 0 {
		filter.Limit = input.BatchSize
	}

	rules, err := t.database.QueryRules(filter)
	if err != nil {
		return GetRulesOutput{}, fmt.Errorf("querying rules: %w", err)
	}

	agentRules := make([]RuleForAgent, 0, len(rules))
	for _, rule := range rules {
		agentRules = append(agentRules, RuleForAgent{
			ID:               rule.ID,
			Source:           rule.Source,
			Category:         rule.Category,
			Severity:         rule.Severity,
			Title:            rule.Title,
			CheckInstruction: rule.CheckInstruction,
		})
	}

	t.sessionManager.AdvanceIndex(input.SessionID, len(rules))

	remaining := session.TotalRules - session.CurrentIndex - len(rules)
	if remaining < 0 {
		remaining = 0
	}

	return GetRulesOutput{
		Rules:     agentRules,
		Remaining: remaining,
		Progress:  fmt.Sprintf("%d rules delivered, %d remaining", len(rules), remaining),
	}, nil
}

func (t *AuditTools) ReportResults(ctx context.Context, input ReportResultsInput) (ReportResultsOutput, error) {
	err := t.sessionManager.RecordResults(input.SessionID, input.Results)
	if err != nil {
		return ReportResultsOutput{}, err
	}

	checked, total := t.sessionManager.GetProgress(input.SessionID)

	progress := fmt.Sprintf("%d/%d rules checked (%.0f%%)",
		checked, total, float64(checked)/float64(total)*100)
	if checked >= total {
		progress += ". Audit complete — call get_report for the final summary."
	}

	return ReportResultsOutput{
		Acknowledged: len(input.Results),
		TotalChecked: checked,
		TotalRules:   total,
		Progress:     progress,
	}, nil
}

func (t *AuditTools) GetReport(ctx context.Context, input GetReportInput) (GetReportOutput, error) {
	session, err := t.sessionManager.GetSession(input.SessionID)
	if err != nil {
		return GetReportOutput{}, err
	}

	checked := len(session.Results)
	completionRatio := float64(checked) / float64(session.TotalRules)

	if completionRatio < 0.8 {
		return GetReportOutput{}, fmt.Errorf(
			"AUDIT INCOMPLETE: Only %d/%d rules checked (%.0f%%). "+
				"You must check at least 80%% of rules before generating a report. "+
				"Call get_rules to continue checking the remaining %d rules",
			checked, session.TotalRules, completionRatio*100, session.TotalRules-checked)
	}

	var passed, failed, skipped int
	var failedRules []FailedRuleEntry
	severitySummary := make(map[string]int)

	for _, result := range session.Results {
		switch result.Status {
		case "pass":
			passed++
		case "fail":
			failed++
			rule, ruleErr := t.database.GetRuleByID(result.RuleID)
			if ruleErr == nil && rule != nil {
				failedRules = append(failedRules, FailedRuleEntry{
					RuleID:   result.RuleID,
					Title:    rule.Title,
					Severity: rule.Severity,
					Evidence: result.Evidence,
				})
				severitySummary[rule.Severity]++
			}
		case "skipped":
			skipped++
		}
	}

	score := calculateScore(passed, failed, session.TotalRules)

	return GetReportOutput{
		SessionID:       session.ID,
		TotalRules:      session.TotalRules,
		Checked:         checked,
		Passed:          passed,
		Failed:          failed,
		Skipped:         skipped,
		FailedRules:     failedRules,
		SeveritySummary: severitySummary,
		Score:           score,
	}, nil
}

func mapMinSeverityToFilter(minSeverity string) string {
	switch minSeverity {
	case "critical", "high", "medium", "low", "info":
		return minSeverity
	default:
		return ""
	}
}

func calculateScore(passed int, failed int, total int) string {
	if total == 0 {
		return "N/A"
	}
	checked := passed + failed
	if checked == 0 {
		return "Not started"
	}
	percentage := float64(passed) / float64(checked) * 100
	switch {
	case percentage >= 95:
		return fmt.Sprintf("A (%.0f%% pass rate)", percentage)
	case percentage >= 85:
		return fmt.Sprintf("B (%.0f%% pass rate)", percentage)
	case percentage >= 70:
		return fmt.Sprintf("C (%.0f%% pass rate)", percentage)
	case percentage >= 50:
		return fmt.Sprintf("D (%.0f%% pass rate)", percentage)
	default:
		return fmt.Sprintf("F (%.0f%% pass rate)", percentage)
	}
}
