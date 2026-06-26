package normalizer_test

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"

	"github.com/booltools/security-checker/internal/normalizer"
)

func TestCISAKEVParser(t *testing.T) {
	dataDir := t.TempDir()
	kevDir := filepath.Join(dataDir, "cisa-kev")
	_ = os.MkdirAll(kevDir, 0o755)

	catalog := map[string]interface{}{
		"vulnerabilities": []map[string]interface{}{
			{
				"cveID":                      "CVE-2021-44228",
				"vendorProject":              "Apache",
				"product":                    "Log4j",
				"vulnerabilityName":          "Apache Log4j2 RCE",
				"dateAdded":                  "2021-12-10",
				"shortDescription":           "Remote code execution in Apache Log4j2",
				"requiredAction":             "Update to version 2.17.1",
				"dueDate":                    "2021-12-24",
				"knownRansomwareCampaignUse": "Known",
			},
			{
				"cveID":                      "CVE-2023-00001",
				"vendorProject":              "TestVendor",
				"product":                    "TestProduct",
				"vulnerabilityName":          "Test Vulnerability",
				"dateAdded":                  "2023-01-15",
				"shortDescription":           "A test vulnerability description",
				"requiredAction":             "Apply patch",
				"dueDate":                    "2023-02-01",
				"knownRansomwareCampaignUse": "Unknown",
			},
		},
	}

	data, _ := json.Marshal(catalog)
	_ = os.WriteFile(filepath.Join(kevDir, "known_exploited_vulnerabilities.json"), data, 0o644)

	parser := normalizer.NewCISAKEVParser(dataDir)

	if parser.Name() != "CISA KEV" {
		t.Errorf("expected name 'CISA KEV', got %q", parser.Name())
	}

	rules, err := parser.Parse(context.Background())
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	first := rules[0]
	if first.ID != "CVE-2021-44228" {
		t.Errorf("expected ID CVE-2021-44228, got %s", first.ID)
	}
	if first.Source != normalizer.SourceCISAKEV {
		t.Errorf("expected source cisa_kev, got %s", first.Source)
	}
	if first.Severity != normalizer.SeverityCritical {
		t.Errorf("expected severity critical, got %s", first.Severity)
	}
	if !first.IsKEV {
		t.Error("expected IsKEV to be true")
	}
	if first.CheckInstruction == "" {
		t.Error("expected non-empty check instruction")
	}

	hasRansomware := false
	for _, tag := range first.Tags {
		if tag == "ransomware" {
			hasRansomware = true
		}
	}
	if !hasRansomware {
		t.Error("expected 'ransomware' tag for Known campaign")
	}
}

func TestEPSSParser_ParseScores(t *testing.T) {
	dataDir := t.TempDir()
	epssDir := filepath.Join(dataDir, "epss")
	_ = os.MkdirAll(epssDir, 0o755)

	csvContent := `#model_version:v2023.03.01,score_date:2023-03-01
cve,epss,percentile
CVE-2021-44228,0.97560,0.99990
CVE-2023-00001,0.00123,0.45000
CVE-2022-22965,0.87340,0.99800
`
	gzFile, _ := os.Create(filepath.Join(epssDir, "epss_scores.csv.gz"))
	writer := gzip.NewWriter(gzFile)
	_, _ = writer.Write([]byte(csvContent))
	writer.Close()
	gzFile.Close()

	parser := normalizer.NewEPSSParser(dataDir)

	if parser.Name() != "EPSS" {
		t.Errorf("expected name 'EPSS', got %q", parser.Name())
	}

	scores, err := parser.ParseScores(context.Background())
	if err != nil {
		t.Fatalf("ParseScores failed: %v", err)
	}

	if len(scores) != 3 {
		t.Fatalf("expected 3 scores, got %d", len(scores))
	}

	log4j, exists := scores["CVE-2021-44228"]
	if !exists {
		t.Fatal("CVE-2021-44228 not found in scores")
	}
	if log4j.Score < 0.97 || log4j.Score > 0.98 {
		t.Errorf("expected score ~0.9756, got %f", log4j.Score)
	}
	if log4j.Percentile < 0.99 {
		t.Errorf("expected percentile ~0.9999, got %f", log4j.Percentile)
	}
}

func TestExploitDBParser(t *testing.T) {
	dataDir := t.TempDir()
	edbDir := filepath.Join(dataDir, "exploitdb")
	_ = os.MkdirAll(edbDir, 0o755)

	csvContent := `id,description,platform,date_published,author,type,codes
12345,Buffer Overflow in FooApp,linux,2021-05-10,researcher,remote,CVE-2021-99999
67890,"SQL Injection in BarApp, v2",windows,2022-03-15,hacker,webapps,CVE-2022-11111;CVE-2022-11112
99999,No CVE Here,multiple,2023-01-01,anon,local,
`

	_ = os.WriteFile(filepath.Join(edbDir, "exploits.csv"), []byte(csvContent), 0o644)

	parser := normalizer.NewExploitDBParser(dataDir)

	if parser.Name() != "Exploit-DB" {
		t.Errorf("expected name 'Exploit-DB', got %q", parser.Name())
	}

	rules, err := parser.Parse(context.Background())
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(rules) != 3 {
		t.Fatalf("expected 3 rules (1 from first + 2 from second CVE), got %d", len(rules))
	}

	if rules[0].Source != normalizer.SourceExploitDB {
		t.Errorf("expected source exploitdb, got %s", rules[0].Source)
	}

	if len(rules[0].References) == 0 {
		t.Error("expected at least one reference URL")
	}
}

func TestCAPECParser(t *testing.T) {
	dataDir := t.TempDir()
	capecDir := filepath.Join(dataDir, "capec")
	_ = os.MkdirAll(capecDir, 0o755)

	type Mitigation struct {
		XMLName     xml.Name `xml:"Mitigation"`
		Description string   `xml:"Description"`
	}
	type AttackPattern struct {
		XMLName            xml.Name     `xml:"Attack_Pattern"`
		ID                 string       `xml:"ID,attr"`
		Name               string       `xml:"Name,attr"`
		Status             string       `xml:"Status,attr"`
		Description        string       `xml:"Description"`
		LikelihoodOfAttack string       `xml:"Likelihood_Of_Attack"`
		TypicalSeverity    string       `xml:"Typical_Severity"`
		Mitigations        struct {
			Items []Mitigation
		} `xml:"Mitigations"`
	}
	type Catalog struct {
		XMLName        xml.Name        `xml:"Attack_Pattern_Catalog"`
		AttackPatterns struct {
			Patterns []AttackPattern `xml:"Attack_Pattern"`
		} `xml:"Attack_Patterns"`
	}

	catalog := Catalog{}
	catalog.AttackPatterns.Patterns = []AttackPattern{
		{ID: "66", Name: "SQL Injection", Status: "Draft", Description: "SQL injection attack", LikelihoodOfAttack: "High", TypicalSeverity: "High"},
		{ID: "86", Name: "XSS via HTTP Headers", Status: "Draft", Description: "XSS via headers", LikelihoodOfAttack: "Medium", TypicalSeverity: "Medium"},
		{ID: "99", Name: "Deprecated Pattern", Status: "Deprecated", Description: "Should be skipped"},
	}

	xmlData, _ := xml.MarshalIndent(catalog, "", "  ")
	_ = os.WriteFile(filepath.Join(capecDir, "capec_latest.xml"), xmlData, 0o644)

	parser := normalizer.NewCAPECParser(dataDir)

	if parser.Name() != "CAPEC" {
		t.Errorf("expected name 'CAPEC', got %q", parser.Name())
	}

	rules, err := parser.Parse(context.Background())
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(rules) != 2 {
		t.Fatalf("expected 2 rules (deprecated should be skipped), got %d", len(rules))
	}

	if rules[0].ID != "CAPEC-66" {
		t.Errorf("expected CAPEC-66, got %s", rules[0].ID)
	}
	if rules[0].Severity != normalizer.SeverityHigh {
		t.Errorf("expected severity high, got %s", rules[0].Severity)
	}
}

func TestNVDParser(t *testing.T) {
	dataDir := t.TempDir()
	nvdDir := filepath.Join(dataDir, "nvd")
	_ = os.MkdirAll(nvdDir, 0o755)

	nvdData := map[string]interface{}{
		"vulnerabilities": []map[string]interface{}{
			{
				"cve": map[string]interface{}{
					"id":           "CVE-2021-44228",
					"published":    "2021-12-10T10:15:00.000",
					"lastModified": "2023-11-06T19:15:00.000",
					"descriptions": []map[string]interface{}{
						{"lang": "en", "value": "Apache Log4j2 remote code execution via JNDI lookup"},
					},
					"metrics": map[string]interface{}{
						"cvssMetricV31": []map[string]interface{}{
							{"cvssData": map[string]interface{}{"baseScore": 10.0, "baseSeverity": "CRITICAL"}},
						},
					},
					"weaknesses": []map[string]interface{}{
						{"description": []map[string]interface{}{{"lang": "en", "value": "CWE-502"}}},
					},
					"references": []map[string]interface{}{
						{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
					},
				},
			},
			{
				"cve": map[string]interface{}{
					"id":           "CVE-2023-99999",
					"published":    "2023-06-01T00:00:00.000",
					"lastModified": "2023-07-01T00:00:00.000",
					"descriptions": []map[string]interface{}{
						{"lang": "en", "value": "A medium severity test vulnerability"},
					},
					"metrics": map[string]interface{}{
						"cvssMetricV31": []map[string]interface{}{
							{"cvssData": map[string]interface{}{"baseScore": 5.5, "baseSeverity": "MEDIUM"}},
						},
					},
					"weaknesses":     []interface{}{},
					"configurations": []interface{}{},
					"references":     []interface{}{},
				},
			},
		},
	}

	data, _ := json.Marshal(nvdData)
	_ = os.WriteFile(filepath.Join(nvdDir, "cves_test.json"), data, 0o644)

	parser := normalizer.NewNVDParser(dataDir)

	if parser.Name() != "NVD" {
		t.Errorf("expected name 'NVD', got %q", parser.Name())
	}

	rules, err := parser.Parse(context.Background())
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	first := rules[0]
	if first.ID != "CVE-2021-44228" {
		t.Errorf("expected CVE-2021-44228, got %s", first.ID)
	}
	if first.CVSSScore != 10.0 {
		t.Errorf("expected CVSS 10.0, got %f", first.CVSSScore)
	}
	if first.Severity != normalizer.SeverityCritical {
		t.Errorf("expected critical severity, got %s", first.Severity)
	}
	if len(first.CWEIDs) != 1 || first.CWEIDs[0] != "CWE-502" {
		t.Errorf("expected CWE-502, got %v", first.CWEIDs)
	}
}

func TestCheckInstructionGeneration(t *testing.T) {
	tests := []struct {
		name     string
		generate func() string
	}{
		{
			name: "CVE check instruction",
			generate: func() string {
				return normalizer.GenerateCVECheckInstruction("CVE-2021-44228", "RCE in Log4j", "log4j-core", ">= 2.0, < 2.17.1")
			},
		},
		{
			name: "CWE check instruction",
			generate: func() string {
				return normalizer.GenerateCWECheckInstruction("CWE-79", "Cross-site Scripting", "XSS vulnerability")
			},
		},
		{
			name: "KEV check instruction",
			generate: func() string {
				return normalizer.GenerateKEVCheckInstruction("CVE-2021-44228", "Apache", "Log4j", "Update to 2.17.1")
			},
		},
		{
			name: "CAPEC check instruction",
			generate: func() string {
				return normalizer.GenerateCAPECCheckInstruction("CAPEC-66", "SQL Injection", "SQL injection attack")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.generate()
			if result == "" {
				t.Error("expected non-empty check instruction")
			}
			if len(result) < 20 {
				t.Errorf("check instruction too short: %q", result)
			}
		})
	}
}
