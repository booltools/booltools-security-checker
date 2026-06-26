package normalizer_test

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/booltools/security-checker/internal/normalizer"
)

func setupTestDatabase(t *testing.T) (*normalizer.Database, string) {
	t.Helper()

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_rules.db")

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	db, err := normalizer.NewDatabase(dbPath, logger)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}

	return db, dbPath
}

func TestNewDatabase_CreatesFile(t *testing.T) {
	db, dbPath := setupTestDatabase(t)
	defer db.Close()

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Fatal("database file was not created")
	}
}

func TestInsertBatch_InsertsRules(t *testing.T) {
	db, _ := setupTestDatabase(t)
	defer db.Close()

	rules := []normalizer.SecurityRule{
		{
			ID:               "CVE-2021-44228",
			Source:           normalizer.SourceNVD,
			Category:         normalizer.CategoryRemoteCodeExecution,
			Severity:         normalizer.SeverityCritical,
			Title:            "Log4Shell",
			Description:      "Apache Log4j2 RCE vulnerability",
			CheckInstruction: "Check for log4j-core dependency",
			Languages:        []string{"java"},
			Frameworks:       []string{"all"},
			Platforms:        []string{"all"},
			AppliesTo:        normalizer.AppliesToDependency,
			CVSSScore:        10.0,
			IsKEV:            true,
			CVEIDs:           []string{"CVE-2021-44228"},
			CWEIDs:           []string{"CWE-502"},
			Tags:             []string{"log4j", "rce", "critical"},
		},
		{
			ID:               "CVE-2023-12345",
			Source:           normalizer.SourceNVD,
			Category:         normalizer.CategoryInjection,
			Severity:         normalizer.SeverityHigh,
			Title:            "SQL Injection in FooLib",
			Description:      "SQL injection via user input",
			CheckInstruction: "Check for raw SQL queries",
			Languages:        []string{"python"},
			Frameworks:       []string{"django"},
			Platforms:        []string{"all"},
			AppliesTo:        normalizer.AppliesToCode,
			CVSSScore:        8.5,
			CVEIDs:           []string{"CVE-2023-12345"},
			CWEIDs:           []string{"CWE-89"},
			Tags:             []string{"sql-injection"},
		},
	}

	err := db.InsertBatch(rules)
	if err != nil {
		t.Fatalf("InsertBatch failed: %v", err)
	}

	count, err := db.Count()
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 rules, got %d", count)
	}
}

func TestInsertBatch_UpsertOnDuplicate(t *testing.T) {
	db, _ := setupTestDatabase(t)
	defer db.Close()

	rule := normalizer.SecurityRule{
		ID:               "CVE-2021-44228",
		Source:           normalizer.SourceNVD,
		Category:         normalizer.CategoryRemoteCodeExecution,
		Severity:         normalizer.SeverityCritical,
		Title:            "Log4Shell - Original",
		Description:      "Original description",
		CheckInstruction: "Original instruction",
		Languages:        []string{"java"},
		Frameworks:       []string{"all"},
		Platforms:        []string{"all"},
		AppliesTo:        normalizer.AppliesToDependency,
	}

	_ = db.InsertBatch([]normalizer.SecurityRule{rule})

	rule.Title = "Log4Shell - Updated"
	_ = db.InsertBatch([]normalizer.SecurityRule{rule})

	count, _ := db.Count()
	if count != 1 {
		t.Errorf("expected 1 rule after upsert, got %d", count)
	}

	result, err := db.GetRuleByID("CVE-2021-44228")
	if err != nil {
		t.Fatalf("GetRuleByID failed: %v", err)
	}
	if result.Title != "Log4Shell - Updated" {
		t.Errorf("expected updated title, got %q", result.Title)
	}
}

func TestGetRuleByID(t *testing.T) {
	db, _ := setupTestDatabase(t)
	defer db.Close()

	rules := []normalizer.SecurityRule{
		{
			ID:               "CWE-79",
			Source:           normalizer.SourceCWE,
			Category:         normalizer.CategoryInjection,
			Severity:         normalizer.SeverityHigh,
			Title:            "Cross-site Scripting (XSS)",
			Description:      "XSS weakness",
			CheckInstruction: "Check for unescaped output",
			Languages:        []string{"javascript", "python"},
			Frameworks:       []string{"all"},
			Platforms:        []string{"all"},
			AppliesTo:        normalizer.AppliesToCode,
			CWEIDs:           []string{"CWE-79"},
			Tags:             []string{"xss", "injection"},
		},
	}
	_ = db.InsertBatch(rules)

	result, err := db.GetRuleByID("CWE-79")
	if err != nil {
		t.Fatalf("GetRuleByID failed: %v", err)
	}

	if result.ID != "CWE-79" {
		t.Errorf("expected ID CWE-79, got %s", result.ID)
	}
	if result.Source != normalizer.SourceCWE {
		t.Errorf("expected source cwe, got %s", result.Source)
	}
	if len(result.Languages) != 2 {
		t.Errorf("expected 2 languages, got %d", len(result.Languages))
	}
	if len(result.Tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(result.Tags))
	}
}

func TestGetRuleByID_NotFound(t *testing.T) {
	db, _ := setupTestDatabase(t)
	defer db.Close()

	_, err := db.GetRuleByID("NONEXISTENT")
	if err == nil {
		t.Fatal("expected error for nonexistent rule, got nil")
	}
}

func TestQueryRules_FilterBySeverity(t *testing.T) {
	db, _ := setupTestDatabase(t)
	defer db.Close()

	rules := []normalizer.SecurityRule{
		{ID: "R1", Source: "nvd", Category: "injection", Severity: normalizer.SeverityCritical, Title: "Critical", Description: "d", CheckInstruction: "c", Languages: []string{"all"}, Frameworks: []string{"all"}, Platforms: []string{"all"}, AppliesTo: "all", CVSSScore: 9.5},
		{ID: "R2", Source: "nvd", Category: "injection", Severity: normalizer.SeverityHigh, Title: "High", Description: "d", CheckInstruction: "c", Languages: []string{"all"}, Frameworks: []string{"all"}, Platforms: []string{"all"}, AppliesTo: "all", CVSSScore: 7.5},
		{ID: "R3", Source: "nvd", Category: "injection", Severity: normalizer.SeverityLow, Title: "Low", Description: "d", CheckInstruction: "c", Languages: []string{"all"}, Frameworks: []string{"all"}, Platforms: []string{"all"}, AppliesTo: "all", CVSSScore: 2.0},
	}
	_ = db.InsertBatch(rules)

	results, err := db.QueryRules(normalizer.QueryFilter{Severity: normalizer.SeverityCritical})
	if err != nil {
		t.Fatalf("QueryRules failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 critical rule, got %d", len(results))
	}
	if results[0].ID != "R1" {
		t.Errorf("expected R1, got %s", results[0].ID)
	}
}

func TestQueryRules_FilterByLanguage(t *testing.T) {
	db, _ := setupTestDatabase(t)
	defer db.Close()

	rules := []normalizer.SecurityRule{
		{ID: "R1", Source: "nvd", Category: "injection", Severity: "high", Title: "Go rule", Description: "d", CheckInstruction: "c", Languages: []string{"go"}, Frameworks: []string{"all"}, Platforms: []string{"all"}, AppliesTo: "all"},
		{ID: "R2", Source: "nvd", Category: "injection", Severity: "high", Title: "Python rule", Description: "d", CheckInstruction: "c", Languages: []string{"python"}, Frameworks: []string{"all"}, Platforms: []string{"all"}, AppliesTo: "all"},
		{ID: "R3", Source: "nvd", Category: "injection", Severity: "high", Title: "All rule", Description: "d", CheckInstruction: "c", Languages: []string{"all"}, Frameworks: []string{"all"}, Platforms: []string{"all"}, AppliesTo: "all"},
	}
	_ = db.InsertBatch(rules)

	results, err := db.QueryRules(normalizer.QueryFilter{Languages: []string{"go"}})
	if err != nil {
		t.Fatalf("QueryRules failed: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 rules (go + all), got %d", len(results))
	}
}

func TestQueryRules_LimitAndOffset(t *testing.T) {
	db, _ := setupTestDatabase(t)
	defer db.Close()

	var rules []normalizer.SecurityRule
	for i := 0; i < 10; i++ {
		rules = append(rules, normalizer.SecurityRule{
			ID: "R" + string(rune('A'+i)), Source: "nvd", Category: "other", Severity: "medium",
			Title: "Rule", Description: "d", CheckInstruction: "c",
			Languages: []string{"all"}, Frameworks: []string{"all"}, Platforms: []string{"all"}, AppliesTo: "all",
		})
	}
	_ = db.InsertBatch(rules)

	results, err := db.QueryRules(normalizer.QueryFilter{Limit: 3, Offset: 2})
	if err != nil {
		t.Fatalf("QueryRules failed: %v", err)
	}
	if len(results) != 3 {
		t.Errorf("expected 3 rules with limit, got %d", len(results))
	}
}

func TestSearchRules(t *testing.T) {
	db, _ := setupTestDatabase(t)
	defer db.Close()

	rules := []normalizer.SecurityRule{
		{ID: "CVE-2021-44228", Source: "nvd", Category: "rce", Severity: "critical", Title: "Log4Shell RCE", Description: "Apache Log4j remote code execution", CheckInstruction: "c", Languages: []string{"java"}, Frameworks: []string{"all"}, Platforms: []string{"all"}, AppliesTo: "dependency", Tags: []string{"log4j", "rce"}},
		{ID: "CVE-2023-99999", Source: "nvd", Category: "injection", Severity: "high", Title: "SQL Injection", Description: "Generic SQL injection", CheckInstruction: "c", Languages: []string{"python"}, Frameworks: []string{"all"}, Platforms: []string{"all"}, AppliesTo: "code"},
	}
	_ = db.InsertBatch(rules)

	results, err := db.SearchRules("log4j", 10)
	if err != nil {
		t.Fatalf("SearchRules failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result for log4j, got %d", len(results))
	}
	if len(results) > 0 && results[0].ID != "CVE-2021-44228" {
		t.Errorf("expected CVE-2021-44228, got %s", results[0].ID)
	}
}

func TestCountBySource(t *testing.T) {
	db, _ := setupTestDatabase(t)
	defer db.Close()

	rules := []normalizer.SecurityRule{
		{ID: "R1", Source: "nvd", Category: "other", Severity: "high", Title: "t", Description: "d", CheckInstruction: "c", Languages: []string{"all"}, Frameworks: []string{"all"}, Platforms: []string{"all"}, AppliesTo: "all"},
		{ID: "R2", Source: "nvd", Category: "other", Severity: "high", Title: "t", Description: "d", CheckInstruction: "c", Languages: []string{"all"}, Frameworks: []string{"all"}, Platforms: []string{"all"}, AppliesTo: "all"},
		{ID: "R3", Source: "cisa_kev", Category: "other", Severity: "critical", Title: "t", Description: "d", CheckInstruction: "c", Languages: []string{"all"}, Frameworks: []string{"all"}, Platforms: []string{"all"}, AppliesTo: "all"},
	}
	_ = db.InsertBatch(rules)

	counts, err := db.CountBySource()
	if err != nil {
		t.Fatalf("CountBySource failed: %v", err)
	}
	if counts["nvd"] != 2 {
		t.Errorf("expected 2 nvd rules, got %d", counts["nvd"])
	}
	if counts["cisa_kev"] != 1 {
		t.Errorf("expected 1 cisa_kev rule, got %d", counts["cisa_kev"])
	}
}
