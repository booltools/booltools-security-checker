package normalizer

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

type Parser interface {
	Name() string
	Parse(ctx context.Context) ([]SecurityRule, error)
}

type Normalizer struct {
	database *Database
	parsers  []Parser
	logger   *slog.Logger
	dataDir  string
}

func NewNormalizer(database *Database, dataDir string, logger *slog.Logger) *Normalizer {
	return &Normalizer{
		database: database,
		logger:   logger,
		dataDir:  dataDir,
	}
}

func (n *Normalizer) RegisterParser(parser Parser) {
	n.parsers = append(n.parsers, parser)
}

func (n *Normalizer) Run(ctx context.Context) error {
	startTime := time.Now()
	totalRules := 0

	for _, parser := range n.parsers {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n.logger.Info("parsing source", "parser", parser.Name())
		parserStart := time.Now()

		rules, err := parser.Parse(ctx)
		if err != nil {
			n.logger.Error("parser failed", "parser", parser.Name(), "error", err)
			continue
		}

		if len(rules) == 0 {
			n.logger.Warn("parser produced no rules", "parser", parser.Name())
			continue
		}

		if err := n.database.InsertBatch(rules); err != nil {
			n.logger.Error("failed to insert rules", "parser", parser.Name(), "error", err)
			continue
		}

		totalRules += len(rules)
		n.logger.Info("parser completed",
			"parser", parser.Name(),
			"rules", len(rules),
			"duration", time.Since(parserStart).Round(time.Millisecond),
		)
	}

	n.logger.Info("normalization complete",
		"total_rules", totalRules,
		"duration", time.Since(startTime).Round(time.Millisecond),
	)

	counts, err := n.database.CountBySource()
	if err == nil {
		for source, count := range counts {
			fmt.Printf("  %-20s %d rules\n", source, count)
		}
	}

	return nil
}
