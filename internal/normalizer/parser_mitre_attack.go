package normalizer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type MITREAttackParser struct {
	dataDir string
}

type stixBundle struct {
	Objects []json.RawMessage `json:"objects"`
}

type stixObject struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Created     string `json:"created"`
	Modified    string `json:"modified"`
	ExternalReferences []stixExternalRef `json:"external_references"`
	KillChainPhases    []stixKillChain   `json:"kill_chain_phases"`
	Revoked     bool   `json:"revoked"`
	Deprecated  bool   `json:"x_mitre_deprecated"`
}

type stixExternalRef struct {
	SourceName  string `json:"source_name"`
	ExternalID  string `json:"external_id"`
	URL         string `json:"url"`
}

type stixKillChain struct {
	PhaseName string `json:"phase_name"`
}

func NewMITREAttackParser(dataDir string) *MITREAttackParser {
	return &MITREAttackParser{dataDir: dataDir}
}

func (p *MITREAttackParser) Name() string {
	return "MITRE ATT&CK"
}

func (p *MITREAttackParser) Parse(ctx context.Context) ([]SecurityRule, error) {
	attackDir := filepath.Join(p.dataDir, "mitre-attack")
	entries, err := os.ReadDir(attackDir)
	if err != nil {
		return nil, fmt.Errorf("reading MITRE ATT&CK directory: %w", err)
	}

	var allRules []SecurityRule
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || strings.HasPrefix(entry.Name(), "_") {
			continue
		}

		filePath := filepath.Join(attackDir, entry.Name())
		rules, err := p.parseFile(filePath)
		if err != nil {
			continue
		}
		allRules = append(allRules, rules...)
	}

	return allRules, nil
}

func (p *MITREAttackParser) parseFile(filePath string) ([]SecurityRule, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var bundle stixBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, err
	}

	var rules []SecurityRule
	for _, raw := range bundle.Objects {
		var obj stixObject
		if err := json.Unmarshal(raw, &obj); err != nil {
			continue
		}

		if obj.Type != "attack-pattern" || obj.Revoked || obj.Deprecated {
			continue
		}

		rule := p.convertToRule(obj)
		if rule != nil {
			rules = append(rules, *rule)
		}
	}

	return rules, nil
}

func (p *MITREAttackParser) convertToRule(obj stixObject) *SecurityRule {
	techniqueID := ""
	var references []string

	for _, ref := range obj.ExternalReferences {
		if ref.SourceName == "mitre-attack" {
			techniqueID = ref.ExternalID
		}
		if ref.URL != "" && len(references) < 3 {
			references = append(references, ref.URL)
		}
	}

	if techniqueID == "" || obj.Name == "" {
		return nil
	}

	tags := []string{"mitre-attack", "technique"}
	for _, phase := range obj.KillChainPhases {
		tags = append(tags, strings.ReplaceAll(phase.PhaseName, "-", "_"))
	}

	return &SecurityRule{
		ID:               techniqueID,
		Source:           SourceMITREAttack,
		Category:         mapTacticToCategory(obj.KillChainPhases),
		Severity:         SeverityHigh,
		Title:            fmt.Sprintf("%s: %s", techniqueID, obj.Name),
		Description:      obj.Description,
		CheckInstruction: GenerateMITREAttackCheckInstruction(techniqueID, obj.Name, obj.Description),
		Languages:        []string{"all"},
		Frameworks:       []string{"all"},
		Platforms:        []string{"all"},
		AppliesTo:        AppliesToAll,
		References:       references,
		PublishedAt:      obj.Created,
		UpdatedAt:        obj.Modified,
		Tags:             tags,
	}
}

func mapTacticToCategory(phases []stixKillChain) string {
	for _, phase := range phases {
		switch phase.PhaseName {
		case "initial-access":
			return CategoryRemoteCodeExecution
		case "privilege-escalation":
			return CategoryPrivilegeEscalation
		case "credential-access":
			return CategoryAuthFailure
		case "defense-evasion":
			return CategoryMisconfiguration
		case "exfiltration":
			return CategoryExposure
		}
	}
	return CategoryOther
}
