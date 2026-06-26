package mcp

import (
	"context"
	"fmt"

	"github.com/booltools/security-checker/internal/normalizer"
)

type AuditTools struct {
	database       *RulesDatabase
	sessionManager *SessionManager
}

func NewAuditTools(database *RulesDatabase, sessionManager *SessionManager) *AuditTools {
	return &AuditTools{
		database:       database,
		sessionManager: sessionManager,
	}
}

func (t *AuditTools) StartAudit(ctx context.Context, input StartAuditInput) (StartAuditOutput, error) {
	filter := normalizer.QueryFilter{
		AppliesTo: input.AppliesTo,
		Severity:  mapMinSeverityToFilter(input.MinSeverity),
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

	categories, err := t.database.GetCategoryCounts(filter)
	if err != nil {
		categories = make(map[string]int)
	}

	session := t.sessionManager.CreateSession(filter, totalRules)

	return StartAuditOutput{
		SessionID:  session.ID,
		TotalRules: totalRules,
		Categories: categories,
		Message: fmt.Sprintf(
			"Audit session created with %d security rules to check. "+
				"MANDATORY: You must call get_rules repeatedly and check EVERY rule individually against the codebase. "+
				"Report results for each batch before requesting the next. Do NOT skip any rules. "+
				"The audit is only complete when all %d rules have been checked.",
			totalRules, totalRules),
	}, nil
}

func (t *AuditTools) GetRules(ctx context.Context, input GetRulesInput) (GetRulesOutput, error) {
	session, err := t.sessionManager.GetSession(input.SessionID)
	if err != nil {
		return GetRulesOutput{}, err
	}

	batchSize := input.BatchSize
	if batchSize <= 0 {
		batchSize = 5
	}
	if batchSize > 20 {
		batchSize = 20
	}

	filter := session.Filter
	filter.Limit = batchSize
	filter.Offset = session.CurrentIndex

	rules, err := t.database.QueryRules(filter)
	if err != nil {
		return GetRulesOutput{}, fmt.Errorf("querying rules: %w", err)
	}

	agentRules := make([]RuleForAgent, 0, len(rules))
	for _, rule := range rules {
		agentRules = append(agentRules, RuleForAgent{
			ID:               rule.ID,
			Category:         rule.Category,
			Severity:         rule.Severity,
			Title:            rule.Title,
			CheckInstruction: rule.CheckInstruction,
			Remediation:      rule.Remediation,
			References:       rule.References,
		})
	}

	t.sessionManager.AdvanceIndex(input.SessionID, len(rules))

	remaining := session.TotalRules - session.CurrentIndex - len(rules)
	if remaining < 0 {
		remaining = 0
	}

	checked, total := t.sessionManager.GetProgress(input.SessionID)

	var progress string
	if remaining > 0 {
		progress = fmt.Sprintf(
			"%d/%d checked, %d remaining. IMPORTANT: You MUST continue calling get_rules and checking each rule. Do NOT stop until remaining=0.",
			checked, total, remaining)
	} else {
		progress = fmt.Sprintf(
			"%d/%d checked. All rules served. Report results for this final batch, then call get_report.",
			checked, total)
	}

	return GetRulesOutput{
		Rules:     agentRules,
		Remaining: remaining,
		Progress:  progress,
	}, nil
}

func (t *AuditTools) ReportResults(ctx context.Context, input ReportResultsInput) (ReportResultsOutput, error) {
	err := t.sessionManager.RecordResults(input.SessionID, input.Results)
	if err != nil {
		return ReportResultsOutput{}, err
	}

	checked, total := t.sessionManager.GetProgress(input.SessionID)
	percentage := float64(checked) / float64(total) * 100

	var progress string
	if checked < total {
		progress = fmt.Sprintf(
			"%d/%d rules checked (%.0f%%). Continue: call get_rules for the next batch. %d rules remaining.",
			checked, total, percentage, total-checked)
	} else {
		progress = fmt.Sprintf(
			"%d/%d rules checked (100%%). Audit complete! Call get_report to see the final summary.",
			checked, total)
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
