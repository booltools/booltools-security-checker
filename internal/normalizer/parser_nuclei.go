package normalizer

import (
	"archive/zip"
	"bufio"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

type NucleiParser struct {
	dataDir string
}

func NewNucleiParser(dataDir string) *NucleiParser {
	return &NucleiParser{dataDir: dataDir}
}

func (p *NucleiParser) Name() string {
	return "Nuclei"
}

func (p *NucleiParser) Parse(ctx context.Context) ([]SecurityRule, error) {
	zipPath := filepath.Join(p.dataDir, "nuclei-templates", "nuclei-templates.zip")

	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("opening nuclei templates zip: %w", err)
	}
	defer reader.Close()

	var rules []SecurityRule
	for _, file := range reader.File {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if !strings.HasSuffix(file.Name, ".yaml") && !strings.HasSuffix(file.Name, ".yml") {
			continue
		}

		if !isSecurityTemplate(file.Name) {
			continue
		}

		rule, err := p.parseTemplate(file)
		if err != nil {
			continue
		}
		if rule != nil {
			rules = append(rules, *rule)
		}
	}

	return rules, nil
}

func (p *NucleiParser) parseTemplate(file *zip.File) (*SecurityRule, error) {
	rc, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	var templateID, name, description, severity string
	var tags []string
	var cveIDs []string
	var cweIDs []string
	var references []string

	scanner := bufio.NewScanner(io.LimitReader(rc, 8192))
	inInfo := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "info:" {
			inInfo = true
			continue
		}

		if inInfo && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && trimmed != "" {
			break
		}

		if !inInfo {
			if strings.HasPrefix(trimmed, "id:") {
				templateID = strings.TrimSpace(strings.TrimPrefix(trimmed, "id:"))
			}
			continue
		}

		if strings.HasPrefix(trimmed, "name:") {
			name = strings.TrimSpace(strings.TrimPrefix(trimmed, "name:"))
		} else if strings.HasPrefix(trimmed, "description:") {
			description = strings.TrimSpace(strings.TrimPrefix(trimmed, "description:"))
		} else if strings.HasPrefix(trimmed, "severity:") {
			severity = strings.TrimSpace(strings.TrimPrefix(trimmed, "severity:"))
		} else if strings.HasPrefix(trimmed, "tags:") {
			tagStr := strings.TrimSpace(strings.TrimPrefix(trimmed, "tags:"))
			tags = strings.Split(tagStr, ",")
			for i := range tags {
				tags[i] = strings.TrimSpace(tags[i])
			}
		} else if strings.HasPrefix(trimmed, "cve-id:") {
			cveStr := strings.TrimSpace(strings.TrimPrefix(trimmed, "cve-id:"))
			cveIDs = append(cveIDs, cveStr)
		} else if strings.HasPrefix(trimmed, "cwe-id:") {
			cweStr := strings.TrimSpace(strings.TrimPrefix(trimmed, "cwe-id:"))
			cweIDs = append(cweIDs, cweStr)
		} else if strings.HasPrefix(trimmed, "- http") {
			references = append(references, strings.TrimPrefix(trimmed, "- "))
		}
	}

	if templateID == "" || name == "" {
		return nil, nil
	}

	normalizedSeverity := mapNucleiSeverity(severity)

	return &SecurityRule{
		ID:               fmt.Sprintf("nuclei-%s", templateID),
		Source:           SourceNuclei,
		Category:         inferNucleiCategory(tags),
		Severity:         normalizedSeverity,
		Title:            name,
		Description:      description,
		CheckInstruction: GenerateNucleiCheckInstruction(templateID, name, description, severity),
		Languages:        []string{"all"},
		Frameworks:       []string{"all"},
		Platforms:        []string{"all"},
		AppliesTo:        AppliesToInfrastructure,
		CVEIDs:           cveIDs,
		CWEIDs:           cweIDs,
		References:       references,
		Tags:             append(tags, "nuclei"),
	}, nil
}

func isSecurityTemplate(path string) bool {
	securityDirs := []string{"/cves/", "/vulnerabilities/", "/misconfiguration/", "/exposures/", "/default-logins/", "/security-misconfiguration/"}
	for _, dir := range securityDirs {
		if strings.Contains(path, dir) {
			return true
		}
	}
	return false
}

func mapNucleiSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func inferNucleiCategory(tags []string) string {
	for _, tag := range tags {
		switch strings.ToLower(tag) {
		case "sqli":
			return CategoryInjection
		case "xss":
			return CategoryInjection
		case "rce":
			return CategoryRemoteCodeExecution
		case "lfi", "rfi":
			return CategoryInjection
		case "ssrf":
			return CategorySSRF
		case "misconfig", "misconfiguration":
			return CategoryMisconfiguration
		case "exposure":
			return CategoryExposure
		case "auth-bypass":
			return CategoryBrokenAccessControl
		}
	}
	return CategoryOther
}
