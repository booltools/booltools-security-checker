package normalizer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type CISAKEVParser struct {
	dataDir string
}

type cisaKEVCatalog struct {
	Vulnerabilities []cisaKEVEntry `json:"vulnerabilities"`
}

type cisaKEVEntry struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

func NewCISAKEVParser(dataDir string) *CISAKEVParser {
	return &CISAKEVParser{dataDir: dataDir}
}

func (p *CISAKEVParser) Name() string {
	return "CISA KEV"
}

func (p *CISAKEVParser) Parse(ctx context.Context) ([]SecurityRule, error) {
	filePath := filepath.Join(p.dataDir, "cisa-kev", "known_exploited_vulnerabilities.json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading CISA KEV file: %w", err)
	}

	var catalog cisaKEVCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("parsing CISA KEV JSON: %w", err)
	}

	var rules []SecurityRule
	for _, entry := range catalog.Vulnerabilities {
		severity := SeverityCritical
		tags := []string{"kev", "actively-exploited"}

		if strings.EqualFold(entry.KnownRansomwareCampaignUse, "Known") {
			tags = append(tags, "ransomware")
		}

		rule := SecurityRule{
			ID:          entry.CVEID,
			Source:      SourceCISAKEV,
			Category:    CategoryRemoteCodeExecution,
			Severity:    severity,
			Title:       entry.VulnerabilityName,
			Description: entry.ShortDescription,
			Remediation: entry.RequiredAction,
			CheckInstruction: GenerateKEVCheckInstruction(
				entry.CVEID, entry.VendorProject, entry.Product, entry.RequiredAction,
			),
			Languages:   []string{"all"},
			Frameworks:  []string{"all"},
			Platforms:   []string{"all"},
			AppliesTo:   AppliesToDependency,
			IsKEV:       true,
			CVEIDs:      []string{entry.CVEID},
			PublishedAt: entry.DateAdded,
			Tags:        tags,
		}

		rules = append(rules, rule)
	}

	return rules, nil
}
