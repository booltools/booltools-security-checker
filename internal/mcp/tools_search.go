package mcp

import (
	"context"
	"fmt"
)

type SearchTools struct {
	database *RulesDatabase
}

func NewSearchTools(database *RulesDatabase) *SearchTools {
	return &SearchTools{database: database}
}

func (t *SearchTools) SearchRules(ctx context.Context, input SearchRulesInput) (SearchRulesOutput, error) {
	maxResults := input.MaxResults
	if maxResults <= 0 {
		maxResults = 10
	}
	if maxResults > 50 {
		maxResults = 50
	}

	rules, err := t.database.SearchRules(input.Query, maxResults)
	if err != nil {
		return SearchRulesOutput{}, fmt.Errorf("searching rules: %w", err)
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
			Remediation:      rule.Remediation,
			References:       rule.References,
		})
	}

	return SearchRulesOutput{
		Rules:      agentRules,
		TotalFound: len(agentRules),
	}, nil
}

func (t *SearchTools) GetRuleDetail(ctx context.Context, input GetRuleDetailInput) (GetRuleDetailOutput, error) {
	rule, err := t.database.GetRuleByID(input.RuleID)
	if err != nil {
		return GetRuleDetailOutput{}, fmt.Errorf("rule not found: %s", input.RuleID)
	}

	return GetRuleDetailOutput{
		ID:               rule.ID,
		Source:           rule.Source,
		Category:         rule.Category,
		Severity:         rule.Severity,
		Title:            rule.Title,
		Description:      rule.Description,
		Remediation:      rule.Remediation,
		CheckInstruction: rule.CheckInstruction,
		Languages:        rule.Languages,
		Frameworks:       rule.Frameworks,
		Platforms:        rule.Platforms,
		CVSSScore:        rule.CVSSScore,
		EPSSScore:        rule.EPSSScore,
		IsKEV:            rule.IsKEV,
		CVEIDs:           rule.CVEIDs,
		CWEIDs:           rule.CWEIDs,
		References:       rule.References,
		Tags:             rule.Tags,
	}, nil
}
