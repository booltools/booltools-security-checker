package normalizer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type NVDParser struct {
	dataDir string
}

type nvdFile struct {
	Vulnerabilities []nvdVulnerability `json:"vulnerabilities"`
}

type nvdVulnerability struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID               string           `json:"id"`
	Published        string           `json:"published"`
	LastModified     string           `json:"lastModified"`
	Descriptions     []nvdDescription `json:"descriptions"`
	Metrics          nvdMetrics       `json:"metrics"`
	Weaknesses       []nvdWeakness    `json:"weaknesses"`
	Configurations   []nvdConfig      `json:"configurations"`
	References       []nvdReference   `json:"references"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CvssMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CvssMetricV30 []nvdCVSSMetric `json:"cvssMetricV30"`
	CvssMetricV2  []nvdCVSSMetric `json:"cvssMetricV2"`
}

type nvdCVSSMetric struct {
	CvssData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	BaseScore float64 `json:"baseScore"`
	BaseSeverity string `json:"baseSeverity"`
}

type nvdWeakness struct {
	Description []nvdDescription `json:"description"`
}

type nvdConfig struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdNode struct {
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdCPEMatch struct {
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
}

type nvdReference struct {
	URL string `json:"url"`
}

func NewNVDParser(dataDir string) *NVDParser {
	return &NVDParser{dataDir: dataDir}
}

func (p *NVDParser) Name() string {
	return "NVD"
}

func (p *NVDParser) Parse(ctx context.Context) ([]SecurityRule, error) {
	nvdDir := filepath.Join(p.dataDir, "nvd")
	entries, err := os.ReadDir(nvdDir)
	if err != nil {
		return nil, fmt.Errorf("reading NVD directory: %w", err)
	}

	var allRules []SecurityRule
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || strings.HasPrefix(entry.Name(), "_") {
			continue
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		filePath := filepath.Join(nvdDir, entry.Name())
		rules, err := p.parseFile(filePath)
		if err != nil {
			continue
		}
		allRules = append(allRules, rules...)
	}

	return allRules, nil
}

func (p *NVDParser) parseFile(filePath string) ([]SecurityRule, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var nvdData nvdFile
	if err := json.Unmarshal(data, &nvdData); err != nil {
		return nil, err
	}

	var rules []SecurityRule
	for _, vuln := range nvdData.Vulnerabilities {
		rule := p.convertToRule(vuln.CVE)
		if rule != nil {
			rules = append(rules, *rule)
		}
	}

	return rules, nil
}

func (p *NVDParser) convertToRule(cve nvdCVE) *SecurityRule {
	description := p.getEnglishDescription(cve.Descriptions)
	if description == "" {
		return nil
	}

	cvssScore, severity := p.extractCVSS(cve.Metrics)
	cweIDs := p.extractCWEIDs(cve.Weaknesses)
	references := p.extractReferences(cve.References)
	affectedProduct, affectedVersions := p.extractAffectedInfo(cve.Configurations)
	category := mapCWEToCategory(cweIDs)

	return &SecurityRule{
		ID:          cve.ID,
		Source:      SourceNVD,
		Category:    category,
		Severity:    severity,
		Title:       fmt.Sprintf("%s - %s", cve.ID, truncateDescription(description, 100)),
		Description: description,
		CheckInstruction: GenerateCVECheckInstruction(
			cve.ID, description, affectedProduct, affectedVersions,
		),
		Languages:   []string{"all"},
		Frameworks:  []string{"all"},
		Platforms:   []string{"all"},
		AppliesTo:   AppliesToDependency,
		CVSSScore:   cvssScore,
		CVEIDs:      []string{cve.ID},
		CWEIDs:      cweIDs,
		References:  references,
		PublishedAt: cve.Published,
		UpdatedAt:   cve.LastModified,
		Tags:        buildNVDTags(severity, cweIDs),
	}
}

func (p *NVDParser) getEnglishDescription(descriptions []nvdDescription) string {
	for _, desc := range descriptions {
		if desc.Lang == "en" {
			return desc.Value
		}
	}
	if len(descriptions) > 0 {
		return descriptions[0].Value
	}
	return ""
}

func (p *NVDParser) extractCVSS(metrics nvdMetrics) (float64, string) {
	if len(metrics.CvssMetricV31) > 0 {
		score := metrics.CvssMetricV31[0].CvssData.BaseScore
		return score, cvssToSeverity(score)
	}
	if len(metrics.CvssMetricV30) > 0 {
		score := metrics.CvssMetricV30[0].CvssData.BaseScore
		return score, cvssToSeverity(score)
	}
	if len(metrics.CvssMetricV2) > 0 {
		score := metrics.CvssMetricV2[0].CvssData.BaseScore
		return score, cvssToSeverity(score)
	}
	return 0, SeverityInfo
}

func (p *NVDParser) extractCWEIDs(weaknesses []nvdWeakness) []string {
	var cweIDs []string
	for _, weakness := range weaknesses {
		for _, desc := range weakness.Description {
			if strings.HasPrefix(desc.Value, "CWE-") {
				cweIDs = append(cweIDs, desc.Value)
			}
		}
	}
	return cweIDs
}

func (p *NVDParser) extractReferences(refs []nvdReference) []string {
	var urls []string
	for _, ref := range refs {
		if len(urls) >= 5 {
			break
		}
		urls = append(urls, ref.URL)
	}
	return urls
}

func (p *NVDParser) extractAffectedInfo(configs []nvdConfig) (string, string) {
	for _, config := range configs {
		for _, node := range config.Nodes {
			for _, match := range node.CPEMatch {
				parts := strings.Split(match.Criteria, ":")
				if len(parts) >= 5 {
					product := parts[4]
					versions := ""
					if match.VersionStartIncluding != "" {
						versions += ">= " + match.VersionStartIncluding
					}
					if match.VersionEndExcluding != "" {
						if versions != "" {
							versions += ", "
						}
						versions += "< " + match.VersionEndExcluding
					}
					if match.VersionEndIncluding != "" {
						if versions != "" {
							versions += ", "
						}
						versions += "<= " + match.VersionEndIncluding
					}
					return product, versions
				}
			}
		}
	}
	return "", ""
}

func cvssToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func mapCWEToCategory(cweIDs []string) string {
	for _, cweID := range cweIDs {
		switch cweID {
		case "CWE-79", "CWE-80":
			return CategoryInjection
		case "CWE-89", "CWE-564":
			return CategoryInjection
		case "CWE-78", "CWE-77":
			return CategoryInjection
		case "CWE-22", "CWE-23":
			return CategoryInjection
		case "CWE-287", "CWE-306", "CWE-798":
			return CategoryAuthFailure
		case "CWE-862", "CWE-863", "CWE-284":
			return CategoryBrokenAccessControl
		case "CWE-327", "CWE-328", "CWE-326":
			return CategoryCryptographicFailure
		case "CWE-502", "CWE-829":
			return CategoryIntegrityFailure
		case "CWE-918":
			return CategorySSRF
		case "CWE-200", "CWE-209":
			return CategoryExposure
		case "CWE-400", "CWE-770":
			return CategoryDenialOfService
		case "CWE-269", "CWE-250":
			return CategoryPrivilegeEscalation
		}
	}
	return CategoryOther
}

func buildNVDTags(severity string, cweIDs []string) []string {
	tags := []string{"cve", severity}
	for _, cweID := range cweIDs {
		tags = append(tags, strings.ToLower(cweID))
	}
	return tags
}
