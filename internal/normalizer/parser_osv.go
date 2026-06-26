package normalizer

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

type OSVParser struct {
	dataDir string
}

type osvEntry struct {
	ID        string         `json:"id"`
	Summary   string         `json:"summary"`
	Details   string         `json:"details"`
	Aliases   []string       `json:"aliases"`
	Severity  []osvSeverity  `json:"severity"`
	Affected  []osvAffected  `json:"affected"`
	Published string         `json:"published"`
	Modified  string         `json:"modified"`
	References []osvReference `json:"references"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package  osvPackage   `json:"package"`
	Ranges   []osvRange   `json:"ranges"`
	Versions []string     `json:"versions"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type osvRange struct {
	Type   string      `json:"type"`
	Events []osvEvent  `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func NewOSVParser(dataDir string) *OSVParser {
	return &OSVParser{dataDir: dataDir}
}

func (p *OSVParser) Name() string {
	return "OSV"
}

func (p *OSVParser) Parse(ctx context.Context) ([]SecurityRule, error) {
	osvDir := filepath.Join(p.dataDir, "osv")
	entries, err := filepath.Glob(filepath.Join(osvDir, "*.zip"))
	if err != nil {
		return nil, fmt.Errorf("finding OSV zip files: %w", err)
	}

	var allRules []SecurityRule
	for _, zipPath := range entries {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		rules, err := p.parseZip(zipPath)
		if err != nil {
			continue
		}
		allRules = append(allRules, rules...)
	}

	return allRules, nil
}

func (p *OSVParser) parseZip(zipPath string) ([]SecurityRule, error) {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	var rules []SecurityRule
	for _, file := range reader.File {
		if !strings.HasSuffix(file.Name, ".json") {
			continue
		}

		rule, err := p.parseEntry(file)
		if err != nil {
			continue
		}
		if rule != nil {
			rules = append(rules, *rule)
		}
	}

	return rules, nil
}

func (p *OSVParser) parseEntry(file *zip.File) (*SecurityRule, error) {
	rc, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	data, err := io.ReadAll(io.LimitReader(rc, 512*1024))
	if err != nil {
		return nil, err
	}

	var entry osvEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}

	if entry.ID == "" {
		return nil, nil
	}

	return p.convertToRule(entry), nil
}

func (p *OSVParser) convertToRule(entry osvEntry) *SecurityRule {
	description := entry.Summary
	if description == "" {
		description = entry.Details
	}
	if description == "" {
		description = entry.ID
	}

	var cveIDs []string
	for _, alias := range entry.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			cveIDs = append(cveIDs, alias)
		}
	}

	var references []string
	for _, ref := range entry.References {
		if len(references) >= 3 {
			break
		}
		references = append(references, ref.URL)
	}

	severity := SeverityMedium
	var cvssScore float64
	for _, sev := range entry.Severity {
		if sev.Type == "CVSS_V3" {
			cvssScore = extractCVSSFromVector(sev.Score)
			severity = cvssToSeverity(cvssScore)
		}
	}

	var packageName, ecosystem, affectedRanges string
	var languages []string
	if len(entry.Affected) > 0 {
		affected := entry.Affected[0]
		packageName = affected.Package.Name
		ecosystem = affected.Package.Ecosystem
		languages = mapEcosystemToLanguages(ecosystem)
		affectedRanges = buildAffectedRanges(affected.Ranges)
	} else {
		languages = []string{"all"}
	}

	return &SecurityRule{
		ID:          entry.ID,
		Source:      SourceOSV,
		Category:    CategorySupplyChain,
		Severity:    severity,
		Title:       truncateDescription(description, 120),
		Description: description,
		CheckInstruction: GenerateOSVCheckInstruction(
			entry.ID, entry.Summary, ecosystem, packageName, affectedRanges,
		),
		Languages:   languages,
		Frameworks:  []string{"all"},
		Platforms:   []string{"all"},
		AppliesTo:   AppliesToDependency,
		CVSSScore:   cvssScore,
		CVEIDs:      cveIDs,
		References:  references,
		PublishedAt: entry.Published,
		UpdatedAt:   entry.Modified,
		Tags:        []string{"osv", ecosystem, "supply-chain"},
	}
}

func extractCVSSFromVector(vector string) float64 {
	return 0
}

func buildAffectedRanges(ranges []osvRange) string {
	var parts []string
	for _, r := range ranges {
		for _, event := range r.Events {
			if event.Introduced != "" {
				parts = append(parts, ">= "+event.Introduced)
			}
			if event.Fixed != "" {
				parts = append(parts, "< "+event.Fixed)
			}
		}
	}
	return strings.Join(parts, ", ")
}
