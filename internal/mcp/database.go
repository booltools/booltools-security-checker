package mcp

import (
	"fmt"
	"log/slog"

	"github.com/booltools/security-checker/internal/normalizer"
)

type RulesDatabase struct {
	db     *normalizer.Database
	logger *slog.Logger
}

func NewRulesDatabase(dbPath string, logger *slog.Logger) (*RulesDatabase, error) {
	db, err := normalizer.NewDatabase(dbPath, logger)
	if err != nil {
		return nil, fmt.Errorf("opening rules database: %w", err)
	}
	return &RulesDatabase{db: db, logger: logger}, nil
}

func (rd *RulesDatabase) Close() error {
	return rd.db.Close()
}

func (rd *RulesDatabase) QueryRules(filter normalizer.QueryFilter) ([]normalizer.SecurityRule, error) {
	return rd.db.QueryRules(filter)
}

func (rd *RulesDatabase) CountFiltered(filter normalizer.QueryFilter) (int, error) {
	return rd.db.CountFiltered(filter)
}

func (rd *RulesDatabase) GetRuleByID(id string) (*normalizer.SecurityRule, error) {
	return rd.db.GetRuleByID(id)
}

func (rd *RulesDatabase) SearchRules(query string, limit int) ([]normalizer.SecurityRule, error) {
	return rd.db.SearchRules(query, limit)
}

func (rd *RulesDatabase) GetCategoryCounts(filter normalizer.QueryFilter) (map[string]int, error) {
	rules, err := rd.db.QueryRules(normalizer.QueryFilter{
		Languages:               filter.Languages,
		Sources:                 filter.Sources,
		Severity:                filter.Severity,
		MinSeverity:             filter.MinSeverity,
		AppliesTo:               filter.AppliesTo,
		ExcludeCategories:       filter.ExcludeCategories,
		ExcludeSourceCategories: filter.ExcludeSourceCategories,
		Limit:                   10000,
	})
	if err != nil {
		return nil, err
	}

	counts := make(map[string]int)
	for _, rule := range rules {
		counts[rule.Category]++
	}
	return counts, nil
}
