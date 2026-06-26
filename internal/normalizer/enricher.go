package normalizer

import (
	"context"
	"fmt"
	"log/slog"
)

type Enricher struct {
	database *Database
	dataDir  string
	logger   *slog.Logger
}

func NewEnricher(database *Database, dataDir string, logger *slog.Logger) *Enricher {
	return &Enricher{
		database: database,
		dataDir:  dataDir,
		logger:   logger,
	}
}

func (e *Enricher) Run(ctx context.Context) error {
	e.logger.Info("starting enrichment phase")

	if err := e.enrichWithEPSS(ctx); err != nil {
		e.logger.Warn("EPSS enrichment failed", "error", err)
	}

	if err := e.enrichWithKEV(ctx); err != nil {
		e.logger.Warn("KEV enrichment failed", "error", err)
	}

	e.logger.Info("enrichment complete")
	return nil
}

func (e *Enricher) enrichWithEPSS(ctx context.Context) error {
	parser := NewEPSSParser(e.dataDir)
	scores, err := parser.ParseScores(ctx)
	if err != nil {
		return fmt.Errorf("parsing EPSS scores: %w", err)
	}

	e.logger.Info("EPSS scores loaded", "total", len(scores))

	transaction, err := e.database.db.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer transaction.Rollback()

	statement, err := transaction.Prepare("UPDATE security_rules SET epss_score = ? WHERE id = ?")
	if err != nil {
		return fmt.Errorf("preparing EPSS update statement: %w", err)
	}
	defer statement.Close()

	updatedCount := 0
	for cveID, entry := range scores {
		result, err := statement.Exec(entry.Score, cveID)
		if err != nil {
			continue
		}
		rowsAffected, _ := result.RowsAffected()
		if rowsAffected > 0 {
			updatedCount++
		}
	}

	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("committing EPSS enrichment: %w", err)
	}

	e.logger.Info("EPSS enrichment complete", "rules_updated", updatedCount)
	return nil
}

func (e *Enricher) enrichWithKEV(ctx context.Context) error {
	parser := NewCISAKEVParser(e.dataDir)
	kevRules, err := parser.Parse(ctx)
	if err != nil {
		return fmt.Errorf("parsing KEV data: %w", err)
	}

	e.logger.Info("KEV entries loaded", "total", len(kevRules))

	transaction, err := e.database.db.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer transaction.Rollback()

	statement, err := transaction.Prepare("UPDATE security_rules SET is_kev = TRUE, severity = 'critical' WHERE id = ?")
	if err != nil {
		return fmt.Errorf("preparing KEV update statement: %w", err)
	}
	defer statement.Close()

	updatedCount := 0
	for _, rule := range kevRules {
		for _, cveID := range rule.CVEIDs {
			result, err := statement.Exec(cveID)
			if err != nil {
				continue
			}
			rowsAffected, _ := result.RowsAffected()
			if rowsAffected > 0 {
				updatedCount++
			}
		}
	}

	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("committing KEV enrichment: %w", err)
	}

	e.logger.Info("KEV enrichment complete", "rules_updated", updatedCount)
	return nil
}
