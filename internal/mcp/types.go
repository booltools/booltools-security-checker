package mcp

type StartAuditInput struct {
	Language    string   `json:"language" jsonschema:"Primary programming language of the project (e.g. go, python, javascript, java)"`
	Framework   string   `json:"framework,omitempty" jsonschema:"Framework used (e.g. express, django, spring, nextjs)"`
	Platform    string   `json:"platform,omitempty" jsonschema:"Cloud/infrastructure platform (e.g. aws, gcp, azure, docker, kubernetes)"`
	Tools       []string `json:"tools,omitempty" jsonschema:"Libraries and tools used in the project (e.g. react, node, webpack, prisma, redis, postgres, nginx)"`
	AuditType   string   `json:"audit_type,omitempty" jsonschema:"Type of audit: code (default ~875 rules, application-level attack patterns checkable in source code), infrastructure (~2200 rules, OS/cloud/network attacks for server configs), extended (~8300 rules, code + nuclei templates), full (~25k all non-dependency), dependency (package version checks), all (everything)"`
	AppliesTo   string   `json:"applies_to,omitempty" jsonschema:"Focus area: code, config, dependency, infrastructure, or all"`
	MinSeverity string   `json:"min_severity,omitempty" jsonschema:"Minimum severity to include: critical, high, medium, low, info"`
}

type StartAuditOutput struct {
	SessionID  string         `json:"session_id"`
	TotalRules int            `json:"total_rules"`
	Categories map[string]int `json:"categories"`
	Message    string         `json:"message"`
}

type GetRulesInput struct {
	SessionID string `json:"session_id" jsonschema:"Session ID from start_audit"`
	BatchSize int    `json:"batch_size,omitempty" jsonschema:"Number of rules to return (default 5, max 20)"`
}

type RuleForAgent struct {
	ID               string   `json:"id"`
	Source           string   `json:"source"`
	Category         string   `json:"category"`
	Severity         string   `json:"severity"`
	Title            string   `json:"title"`
	CheckInstruction string   `json:"check_instruction"`
	Remediation      string   `json:"remediation,omitempty"`
	References       []string `json:"references,omitempty"`
}

type GetRulesOutput struct {
	Rules     []RuleForAgent `json:"rules"`
	Remaining int            `json:"remaining"`
	Progress  string         `json:"progress"`
}

type ReportResultsInput struct {
	SessionID string       `json:"session_id" jsonschema:"Session ID from start_audit"`
	Results   []RuleResult `json:"results" jsonschema:"Array of check results"`
}

type RuleResult struct {
	RuleID   string `json:"rule_id" jsonschema:"The rule ID that was checked"`
	Status   string `json:"status" jsonschema:"Result: pass, fail, or skipped"`
	Evidence string `json:"evidence,omitempty" jsonschema:"Evidence or explanation for the result"`
}

type ReportResultsOutput struct {
	Acknowledged int    `json:"acknowledged"`
	TotalChecked int    `json:"total_checked"`
	TotalRules   int    `json:"total_rules"`
	Progress     string `json:"progress"`
}

type GetReportInput struct {
	SessionID string `json:"session_id" jsonschema:"Session ID from start_audit"`
}

type GetReportOutput struct {
	SessionID       string            `json:"session_id"`
	TotalRules      int               `json:"total_rules"`
	Checked         int               `json:"checked"`
	Passed          int               `json:"passed"`
	Failed          int               `json:"failed"`
	Skipped         int               `json:"skipped"`
	FailedRules     []FailedRuleEntry `json:"failed_rules"`
	SeveritySummary map[string]int    `json:"severity_summary"`
	Score           string            `json:"score"`
}

type FailedRuleEntry struct {
	RuleID   string `json:"rule_id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Evidence string `json:"evidence"`
}

type SearchRulesInput struct {
	Query      string `json:"query" jsonschema:"Search term (CVE ID, CWE ID, keyword, etc)"`
	MaxResults int    `json:"max_results,omitempty" jsonschema:"Maximum results to return (default 10)"`
}

type SearchRulesOutput struct {
	Rules      []RuleForAgent `json:"rules"`
	TotalFound int            `json:"total_found"`
}

type GetRuleDetailInput struct {
	RuleID string `json:"rule_id" jsonschema:"The rule ID to get details for"`
}

type GetRuleDetailOutput struct {
	ID               string   `json:"id"`
	Source           string   `json:"source"`
	Category         string   `json:"category"`
	Severity         string   `json:"severity"`
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	Remediation      string   `json:"remediation,omitempty"`
	CheckInstruction string   `json:"check_instruction"`
	Languages        []string `json:"languages"`
	Frameworks       []string `json:"frameworks"`
	Platforms        []string `json:"platforms"`
	CVSSScore        float64  `json:"cvss_score,omitempty"`
	EPSSScore        float64  `json:"epss_score,omitempty"`
	IsKEV            bool     `json:"is_kev"`
	CVEIDs           []string `json:"cve_ids,omitempty"`
	CWEIDs           []string `json:"cwe_ids,omitempty"`
	References       []string `json:"references,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}
