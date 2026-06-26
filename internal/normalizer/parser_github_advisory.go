package normalizer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type GitHubAdvisoryParser struct {
	dataDir string
}

type ghsaAdvisory struct {
	GHSAID          string             `json:"ghsa_id"`
	CVEID           string             `json:"cve_id"`
	Summary         string             `json:"summary"`
	Description     string             `json:"description"`
	Severity        string             `json:"severity"`
	CVSS            ghsaCVSS           `json:"cvss"`
	CWEs            []ghsaCWE          `json:"cwes"`
	Vulnerabilities []ghsaVulnerability `json:"vulnerabilities"`
	PublishedAt     string             `json:"published_at"`
	UpdatedAt       string             `json:"updated_at"`
	References      []string           `json:"references"`
}

type ghsaCVSS struct {
	Score float64 `json:"score"`
}

type ghsaCWE struct {
	CWEID string `json:"cwe_id"`
}

type ghsaVulnerability struct {
	Package               ghsaPackage `json:"package"`
	VulnerableVersionRange string     `json:"vulnerable_version_range"`
	FirstPatchedVersion   string     `json:"first_patched_version"`
}

type ghsaPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

func NewGitHubAdvisoryParser(dataDir string) *GitHubAdvisoryParser {
	return &GitHubAdvisoryParser{dataDir: dataDir}
}

func (p *GitHubAdvisoryParser) Name() string {
	return "GitHub Advisory"
}

func (p *GitHubAdvisoryParser) Parse(ctx context.Context) ([]SecurityRule, error) {
	filePath := filepath.Join(p.dataDir, "github-advisory", "advisories.json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading GitHub Advisory file: %w", err)
	}

	var advisories []ghsaAdvisory
	if err := json.Unmarshal(data, &advisories); err != nil {
		return nil, fmt.Errorf("parsing GitHub Advisory JSON: %w", err)
	}

	var rules []SecurityRule
	for _, advisory := range advisories {
		advRules := p.convertToRules(advisory)
		rules = append(rules, advRules...)
	}

	return rules, nil
}

func (p *GitHubAdvisoryParser) convertToRules(advisory ghsaAdvisory) []SecurityRule {
	var rules []SecurityRule

	var cweIDs []string
	for _, cwe := range advisory.CWEs {
		cweIDs = append(cweIDs, cwe.CWEID)
	}

	var cveIDs []string
	if advisory.CVEID != "" {
		cveIDs = append(cveIDs, advisory.CVEID)
	}

	severity := mapGHSASeverity(advisory.Severity)

	if len(advisory.Vulnerabilities) == 0 {
		rule := SecurityRule{
			ID:               advisory.GHSAID,
			Source:           SourceGitHubAdvisory,
			Category:         mapCWEToCategory(cweIDs),
			Severity:         severity,
			Title:            advisory.Summary,
			Description:      advisory.Description,
			CheckInstruction: GenerateGHSACheckInstruction(advisory.GHSAID, advisory.Summary, "", "", ""),
			Languages:        []string{"all"},
			Frameworks:       []string{"all"},
			Platforms:        []string{"all"},
			AppliesTo:        AppliesToDependency,
			CVSSScore:        advisory.CVSS.Score,
			CVEIDs:           cveIDs,
			CWEIDs:           cweIDs,
			References:       advisory.References,
			PublishedAt:      advisory.PublishedAt,
			UpdatedAt:        advisory.UpdatedAt,
			Tags:             []string{"ghsa", severity},
		}
		rules = append(rules, rule)
		return rules
	}

	for _, vuln := range advisory.Vulnerabilities {
		ruleID := fmt.Sprintf("%s-%s-%s", advisory.GHSAID, vuln.Package.Ecosystem, sanitizeForID(vuln.Package.Name))

		languages := mapEcosystemToLanguages(vuln.Package.Ecosystem)

		remediation := ""
		if vuln.FirstPatchedVersion != "" {
			remediation = fmt.Sprintf("Upgrade %s to version %s or later.", vuln.Package.Name, vuln.FirstPatchedVersion)
		}

		rule := SecurityRule{
			ID:          ruleID,
			Source:      SourceGitHubAdvisory,
			Category:    mapCWEToCategory(cweIDs),
			Severity:    severity,
			Title:       advisory.Summary,
			Description: advisory.Description,
			Remediation: remediation,
			CheckInstruction: GenerateGHSACheckInstruction(
				advisory.GHSAID, advisory.Summary,
				vuln.Package.Ecosystem, vuln.Package.Name, vuln.VulnerableVersionRange,
			),
			Languages:   languages,
			Frameworks:  []string{"all"},
			Platforms:   []string{"all"},
			AppliesTo:   AppliesToDependency,
			CVSSScore:   advisory.CVSS.Score,
			CVEIDs:      cveIDs,
			CWEIDs:      cweIDs,
			References:  advisory.References,
			PublishedAt: advisory.PublishedAt,
			UpdatedAt:   advisory.UpdatedAt,
			Tags:        []string{"ghsa", severity, vuln.Package.Ecosystem},
		}
		rules = append(rules, rule)
	}

	return rules
}

func mapGHSASeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "moderate", "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func mapEcosystemToLanguages(ecosystem string) []string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return []string{"javascript", "typescript"}
	case "pip", "pypi":
		return []string{"python"}
	case "go":
		return []string{"go"}
	case "maven":
		return []string{"java"}
	case "nuget":
		return []string{"csharp"}
	case "rubygems":
		return []string{"ruby"}
	case "packagist", "composer":
		return []string{"php"}
	case "cargo", "crates.io":
		return []string{"rust"}
	case "pub":
		return []string{"dart"}
	default:
		return []string{"all"}
	}
}

func sanitizeForID(input string) string {
	replacer := strings.NewReplacer("/", "_", "@", "", " ", "_")
	return replacer.Replace(input)
}
