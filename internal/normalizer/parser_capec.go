package normalizer

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type CAPECParser struct {
	dataDir string
}

type capecCatalog struct {
	XMLName        xml.Name             `xml:"Attack_Pattern_Catalog"`
	AttackPatterns capecAttackPatterns  `xml:"Attack_Patterns"`
}

type capecAttackPatterns struct {
	Patterns []capecAttackPattern `xml:"Attack_Pattern"`
}

type capecAttackPattern struct {
	ID                 string `xml:"ID,attr"`
	Name               string `xml:"Name,attr"`
	Status             string `xml:"Status,attr"`
	Description        string `xml:"Description"`
	LikelihoodOfAttack string `xml:"Likelihood_Of_Attack"`
	TypicalSeverity    string `xml:"Typical_Severity"`
	Mitigations        capecMitigations `xml:"Mitigations"`
}

type capecMitigations struct {
	Items []capecMitigation `xml:"Mitigation"`
}

type capecMitigation struct {
	Description string `xml:"Description"`
}

func NewCAPECParser(dataDir string) *CAPECParser {
	return &CAPECParser{dataDir: dataDir}
}

func (p *CAPECParser) Name() string {
	return "CAPEC"
}

func (p *CAPECParser) Parse(ctx context.Context) ([]SecurityRule, error) {
	filePath := filepath.Join(p.dataDir, "capec", "capec_latest.xml")
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading CAPEC file: %w", err)
	}

	var catalog capecCatalog
	if err := xml.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("parsing CAPEC XML: %w", err)
	}

	var rules []SecurityRule
	for _, pattern := range catalog.AttackPatterns.Patterns {
		if pattern.Status == "Deprecated" || pattern.Status == "Obsolete" {
			continue
		}

		rule := p.convertToRule(pattern)
		if rule != nil {
			rules = append(rules, *rule)
		}
	}

	return rules, nil
}

func (p *CAPECParser) convertToRule(pattern capecAttackPattern) *SecurityRule {
	capecID := fmt.Sprintf("CAPEC-%s", pattern.ID)

	description := strings.TrimSpace(pattern.Description)
	if description == "" {
		description = pattern.Name
	}

	var remediation string
	if len(pattern.Mitigations.Items) > 0 {
		var mitigations []string
		for _, mit := range pattern.Mitigations.Items {
			text := strings.TrimSpace(mit.Description)
			if text != "" {
				mitigations = append(mitigations, text)
			}
		}
		if len(mitigations) > 0 {
			remediation = strings.Join(mitigations, "; ")
		}
	}

	severity := mapCAPECSeverity(pattern.TypicalSeverity)

	return &SecurityRule{
		ID:               capecID,
		Source:           SourceCAPEC,
		Category:         CategoryOther,
		Severity:         severity,
		Title:            fmt.Sprintf("%s: %s", capecID, pattern.Name),
		Description:      description,
		Remediation:      remediation,
		CheckInstruction: GenerateCAPECCheckInstruction(capecID, pattern.Name, description),
		Languages:        []string{"all"},
		Frameworks:       []string{"all"},
		Platforms:        []string{"all"},
		AppliesTo:        AppliesToCode,
		Tags:             []string{"capec", "attack-pattern", strings.ToLower(capecID)},
	}
}

func mapCAPECSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "very high":
		return SeverityCritical
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
