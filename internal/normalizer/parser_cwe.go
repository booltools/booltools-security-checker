package normalizer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type CWEParser struct {
	dataDir string
}

type cweViewFile struct {
	Views      []cweView      `json:"Views"`
	Weaknesses []cweWeakness  `json:"Weaknesses"`
}

type cweView struct {
	ID      string      `json:"ID"`
	Name    string      `json:"Name"`
	Members []cweMember `json:"Members"`
}

type cweMember struct {
	CweID  string `json:"CweID"`
	ViewID string `json:"ViewID"`
}

type cweWeakness struct {
	ID                  string `json:"ID"`
	Name                string `json:"Name"`
	Description         string `json:"Description"`
	ExtendedDescription string `json:"Extended_Description"`
	LikelihoodOfExploit string `json:"Likelihood_Of_Exploit"`
}

func NewCWEParser(dataDir string) *CWEParser {
	return &CWEParser{dataDir: dataDir}
}

func (p *CWEParser) Name() string {
	return "CWE"
}

func (p *CWEParser) Parse(ctx context.Context) ([]SecurityRule, error) {
	cweDir := filepath.Join(p.dataDir, "cwe")
	entries, err := os.ReadDir(cweDir)
	if err != nil {
		return nil, fmt.Errorf("reading CWE directory: %w", err)
	}

	var allRules []SecurityRule
	seenCWEs := make(map[string]bool)

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || strings.HasPrefix(entry.Name(), "_") || entry.Name() == "version.json" {
			continue
		}

		filePath := filepath.Join(cweDir, entry.Name())
		rules, err := p.parseFile(filePath, seenCWEs)
		if err != nil {
			continue
		}
		allRules = append(allRules, rules...)
	}

	return allRules, nil
}

func (p *CWEParser) parseFile(filePath string, seenCWEs map[string]bool) ([]SecurityRule, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var viewFile cweViewFile
	if err := json.Unmarshal(data, &viewFile); err != nil {
		return nil, fmt.Errorf("parsing CWE file %s: %w", filePath, err)
	}

	if len(viewFile.Weaknesses) > 0 {
		return p.parseWeaknesses(viewFile.Weaknesses, seenCWEs), nil
	}

	if len(viewFile.Views) > 0 {
		return p.parseViews(viewFile.Views, seenCWEs), nil
	}

	return nil, nil
}

func (p *CWEParser) parseViews(views []cweView, seenCWEs map[string]bool) []SecurityRule {
	var rules []SecurityRule
	for _, view := range views {
		for _, member := range view.Members {
			cweID := fmt.Sprintf("CWE-%s", member.CweID)

			if seenCWEs[cweID] {
				continue
			}
			seenCWEs[cweID] = true

			name := cweIDToName(cweID)
			severity := mapCWEIDToSeverity(cweID)
			category := mapCWEToCategory([]string{cweID})

			rule := SecurityRule{
				ID:               cweID,
				Source:           SourceCWE,
				Category:         category,
				Severity:         severity,
				Title:            fmt.Sprintf("%s: %s", cweID, name),
				Description:      fmt.Sprintf("Common weakness: %s. This is part of the %s view.", name, view.Name),
				CheckInstruction: GenerateCWECheckInstruction(cweID, name, ""),
				Languages:        []string{"all"},
				Frameworks:       []string{"all"},
				Platforms:        []string{"all"},
				AppliesTo:        AppliesToCode,
				CWEIDs:           []string{cweID},
				Tags:             []string{"cwe", strings.ToLower(cweID), "weakness", "top25"},
			}
			rules = append(rules, rule)
		}
	}
	return rules
}

func (p *CWEParser) parseWeaknesses(weaknesses []cweWeakness, seenCWEs map[string]bool) []SecurityRule {
	var rules []SecurityRule
	for _, weakness := range weaknesses {
		if weakness.ID == "" || weakness.Name == "" {
			continue
		}

		cweID := fmt.Sprintf("CWE-%s", weakness.ID)
		if seenCWEs[cweID] {
			continue
		}
		seenCWEs[cweID] = true

		description := weakness.Description
		if description == "" {
			description = weakness.ExtendedDescription
		}
		if description == "" {
			description = weakness.Name
		}

		severity := mapCWELikelihoodToSeverity(weakness.LikelihoodOfExploit)
		category := mapCWEToCategory([]string{cweID})

		rule := SecurityRule{
			ID:               cweID,
			Source:           SourceCWE,
			Category:         category,
			Severity:         severity,
			Title:            fmt.Sprintf("%s: %s", cweID, weakness.Name),
			Description:      description,
			CheckInstruction: GenerateCWECheckInstruction(cweID, weakness.Name, description),
			Languages:        []string{"all"},
			Frameworks:       []string{"all"},
			Platforms:        []string{"all"},
			AppliesTo:        AppliesToCode,
			CWEIDs:           []string{cweID},
			Tags:             []string{"cwe", strings.ToLower(cweID), "weakness"},
		}
		rules = append(rules, rule)
	}
	return rules
}

func mapCWELikelihoodToSeverity(likelihood string) string {
	switch strings.ToLower(likelihood) {
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityMedium
	}
}

func cweIDToName(cweID string) string {
	cweNames := map[string]string{
		"CWE-787": "Out-of-bounds Write",
		"CWE-79":  "Cross-site Scripting (XSS)",
		"CWE-89":  "SQL Injection",
		"CWE-416": "Use After Free",
		"CWE-78":  "OS Command Injection",
		"CWE-20":  "Improper Input Validation",
		"CWE-125": "Out-of-bounds Read",
		"CWE-22":  "Path Traversal",
		"CWE-352": "Cross-Site Request Forgery (CSRF)",
		"CWE-434": "Unrestricted Upload of File with Dangerous Type",
		"CWE-862": "Missing Authorization",
		"CWE-476": "NULL Pointer Dereference",
		"CWE-287": "Improper Authentication",
		"CWE-190": "Integer Overflow or Wraparound",
		"CWE-502": "Deserialization of Untrusted Data",
		"CWE-77":  "Command Injection",
		"CWE-119": "Buffer Overflow",
		"CWE-798": "Use of Hard-coded Credentials",
		"CWE-918": "Server-Side Request Forgery (SSRF)",
		"CWE-306": "Missing Authentication for Critical Function",
		"CWE-362": "Race Condition",
		"CWE-269": "Improper Privilege Management",
		"CWE-94":  "Code Injection",
		"CWE-863": "Incorrect Authorization",
		"CWE-276": "Incorrect Default Permissions",
		"CWE-284": "Improper Access Control",
		"CWE-435": "Improper Interaction Between Multiple Correctly-Behaving Entities",
		"CWE-664": "Improper Control of a Resource Through its Lifetime",
		"CWE-682": "Incorrect Calculation",
		"CWE-691": "Insufficient Control Flow Management",
		"CWE-693": "Protection Mechanism Failure",
		"CWE-697": "Incorrect Comparison",
		"CWE-703": "Improper Check or Handling of Exceptional Conditions",
		"CWE-707": "Improper Neutralization",
		"CWE-710": "Improper Adherence to Coding Standards",
	}

	if name, exists := cweNames[cweID]; exists {
		return name
	}
	return "Common Weakness"
}

func mapCWEIDToSeverity(cweID string) string {
	highSeverityCWEs := map[string]bool{
		"CWE-787": true, "CWE-79": true, "CWE-89": true, "CWE-416": true,
		"CWE-78": true, "CWE-125": true, "CWE-22": true, "CWE-287": true,
		"CWE-502": true, "CWE-77": true, "CWE-119": true, "CWE-798": true,
		"CWE-918": true, "CWE-94": true,
	}

	if highSeverityCWEs[cweID] {
		return SeverityHigh
	}
	return SeverityMedium
}
