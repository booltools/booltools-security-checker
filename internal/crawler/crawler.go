package crawler

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/booltools/security-checker/internal/config"
	"github.com/booltools/security-checker/internal/storage"
)

type Source interface {
	Name() string
	Download(ctx context.Context) (*DownloadResult, error)
}

type DownloadResult struct {
	Source       string
	FilesWritten int
	BytesTotal   int64
	Duration     time.Duration
	Error        error
}

type Orchestrator struct {
	config  *config.Config
	writer  *storage.Writer
	logger  *slog.Logger
	sources []Source
}

func NewOrchestrator(cfg *config.Config, logger *slog.Logger) *Orchestrator {
	writer := storage.NewWriter(cfg.OutputDir)

	return &Orchestrator{
		config: cfg,
		writer: writer,
		logger: logger,
	}
}

func (o *Orchestrator) RegisterSource(source Source) {
	o.sources = append(o.sources, source)
}

func (o *Orchestrator) Writer() *storage.Writer {
	return o.writer
}

func (o *Orchestrator) Run(ctx context.Context, sourceFilter []string) ([]DownloadResult, error) {
	sourcesToRun := o.filterSources(sourceFilter)

	if len(sourcesToRun) == 0 {
		return nil, fmt.Errorf("no sources to run (check filter or enabled status)")
	}

	o.logger.Info("starting crawler",
		"total_sources", len(sourcesToRun),
		"concurrency", o.config.Concurrency,
	)

	results := make([]DownloadResult, len(sourcesToRun))
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(o.config.Concurrency)

	for index, source := range sourcesToRun {
		index := index
		source := source

		group.Go(func() error {
			o.logger.Info("downloading source", "source", source.Name())
			startTime := time.Now()

			result, err := source.Download(groupCtx)
			if err != nil {
				o.logger.Error("source download failed",
					"source", source.Name(),
					"error", err,
					"duration", time.Since(startTime),
				)
				results[index] = DownloadResult{
					Source:   source.Name(),
					Duration: time.Since(startTime),
					Error:    err,
				}
				return nil
			}

			result.Duration = time.Since(startTime)
			results[index] = *result

			o.logger.Info("source download completed",
				"source", source.Name(),
				"files", result.FilesWritten,
				"bytes", result.BytesTotal,
				"duration", result.Duration,
			)

			return nil
		})
	}

	if err := group.Wait(); err != nil {
		return results, fmt.Errorf("orchestrator run failed: %w", err)
	}

	return results, nil
}

func (o *Orchestrator) filterSources(filter []string) []Source {
	if len(filter) == 0 {
		return o.sources
	}

	filterSet := make(map[string]bool, len(filter))
	for _, name := range filter {
		filterSet[name] = true
	}

	var filtered []Source
	for _, source := range o.sources {
		if filterSet[source.Name()] {
			filtered = append(filtered, source)
		}
	}

	return filtered
}
