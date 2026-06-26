package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/booltools/security-checker/internal/config"
	"github.com/booltools/security-checker/internal/crawler"
	"github.com/booltools/security-checker/internal/source"
)

func main() {
	configPath := flag.String("config", "config/sources.yaml", "Path to sources configuration file")
	outputDir := flag.String("output-dir", "", "Override output directory from config")
	sourcesFlag := flag.String("source", "", "Comma-separated list of source names to download (empty = all enabled)")
	sinceFlag := flag.String("since", "", "Only fetch data modified since this date (ISO 8601: 2024-01-01)")
	verbose := flag.Bool("verbose", false, "Enable debug logging")
	listSources := flag.Bool("list", false, "List all available sources and exit")

	flag.Parse()

	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	if *outputDir != "" {
		cfg.OutputDir = *outputDir
	}

	if *listSources {
		printAvailableSources(cfg)
		return
	}

	var sinceTime *time.Time
	if *sinceFlag != "" {
		parsed, parseErr := time.Parse("2006-01-02", *sinceFlag)
		if parseErr != nil {
			logger.Error("invalid --since date format, use YYYY-MM-DD", "error", parseErr)
			os.Exit(1)
		}
		sinceTime = &parsed
	}

	var sourceFilter []string
	if *sourcesFlag != "" {
		sourceFilter = strings.Split(*sourcesFlag, ",")
		for index := range sourceFilter {
			sourceFilter[index] = strings.TrimSpace(sourceFilter[index])
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChannel
		logger.Info("received shutdown signal, cancelling downloads...")
		cancel()
	}()

	orchestrator := crawler.NewOrchestrator(cfg, logger)
	registerSources(orchestrator, cfg, logger, sinceTime)

	results, err := orchestrator.Run(ctx, sourceFilter)
	if err != nil {
		logger.Error("crawler failed", "error", err)
		os.Exit(1)
	}

	printResults(results, logger)
}

func registerSources(orchestrator *crawler.Orchestrator, cfg *config.Config, logger *slog.Logger, sinceTime *time.Time) {
	writer := orchestrator.Writer()

	enabledSources := cfg.EnabledSources()

	if sourceCfg, exists := enabledSources["cisa_kev"]; exists {
		httpClient := createHTTPClient(cfg, sourceCfg, logger)
		orchestrator.RegisterSource(source.NewCISAKEVSource(sourceCfg, httpClient, writer))
	}

	if sourceCfg, exists := enabledSources["epss"]; exists {
		httpClient := createHTTPClient(cfg, sourceCfg, logger)
		orchestrator.RegisterSource(source.NewEPSSSource(sourceCfg, httpClient, writer))
	}

	if sourceCfg, exists := enabledSources["exploitdb"]; exists {
		httpClient := createHTTPClient(cfg, sourceCfg, logger)
		orchestrator.RegisterSource(source.NewExploitDBSource(sourceCfg, httpClient, writer))
	}

	if sourceCfg, exists := enabledSources["mitre_attack"]; exists {
		httpClient := createHTTPClient(cfg, sourceCfg, logger)
		orchestrator.RegisterSource(source.NewMITREAttackSource(sourceCfg, httpClient, writer))
	}

	if sourceCfg, exists := enabledSources["capec"]; exists {
		httpClient := createHTTPClient(cfg, sourceCfg, logger)
		orchestrator.RegisterSource(source.NewCAPECSource(sourceCfg, httpClient, writer))
	}

	if sourceCfg, exists := enabledSources["nvd"]; exists {
		httpClient := createHTTPClient(cfg, sourceCfg, logger)
		nvdSource := source.NewNVDSource(sourceCfg, httpClient, writer, logger)
		if sinceTime != nil {
			nvdSource.SetSince(*sinceTime)
		}
		orchestrator.RegisterSource(nvdSource)
	}

	if sourceCfg, exists := enabledSources["cwe"]; exists {
		httpClient := createHTTPClient(cfg, sourceCfg, logger)
		orchestrator.RegisterSource(source.NewCWESource(sourceCfg, httpClient, writer, logger))
	}

	if sourceCfg, exists := enabledSources["github_advisory"]; exists {
		httpClient := createHTTPClient(cfg, sourceCfg, logger)
		ghSource := source.NewGitHubAdvisorySource(sourceCfg, httpClient, writer, logger)
		if sinceTime != nil {
			ghSource.SetSince(*sinceTime)
		}
		orchestrator.RegisterSource(ghSource)
	}

	if sourceCfg, exists := enabledSources["osv"]; exists {
		httpClient := createHTTPClient(cfg, sourceCfg, logger)
		orchestrator.RegisterSource(source.NewOSVSource(sourceCfg, httpClient, writer, logger))
	}

	if sourceCfg, exists := enabledSources["nuclei_templates"]; exists {
		httpClient := createHTTPClient(cfg, sourceCfg, logger)
		orchestrator.RegisterSource(source.NewNucleiSource(sourceCfg, httpClient, writer))
	}

	if sourceCfg, exists := enabledSources["seclists"]; exists {
		httpClient := createHTTPClient(cfg, sourceCfg, logger)
		orchestrator.RegisterSource(source.NewSecListsSource(sourceCfg, httpClient, writer))
	}

	if sourceCfg, exists := enabledSources["vulners"]; exists {
		httpClient := createHTTPClient(cfg, sourceCfg, logger)
		orchestrator.RegisterSource(source.NewVulnersSource(sourceCfg, httpClient, writer, logger))
	}
}

func createHTTPClient(cfg *config.Config, sourceCfg config.SourceConfig, logger *slog.Logger) *crawler.HTTPClient {
	return crawler.NewHTTPClient(crawler.HTTPClientConfig{
		Timeout:            cfg.RequestTimeout,
		RateLimitPerSecond: sourceCfg.RateLimitPerSecond,
		MaxAttempts:        cfg.RetryMaxAttempts,
		BaseDelay:          cfg.RetryBaseDelay,
		Logger:             logger,
	})
}

func printAvailableSources(cfg *config.Config) {
	fmt.Println("Available security data sources:")
	fmt.Println()
	for key, sourceCfg := range cfg.Sources {
		status := "disabled"
		if sourceCfg.Enabled {
			status = "enabled"
		}
		fmt.Printf("  %-20s [%s] %s\n", key, status, sourceCfg.Description)
	}
	fmt.Println()
	fmt.Printf("Total: %d sources (%d enabled)\n", len(cfg.Sources), len(cfg.EnabledSources()))
}

func printResults(results []crawler.DownloadResult, logger *slog.Logger) {
	fmt.Println()
	fmt.Println("=== Download Results ===")
	fmt.Println()

	var successCount, failCount int
	var totalBytes int64

	for _, result := range results {
		if result.Error != nil {
			failCount++
			fmt.Printf("  FAIL  %-25s %s\n", result.Source, result.Error)
		} else {
			successCount++
			totalBytes += result.BytesTotal
			fmt.Printf("  OK    %-25s %d files, %s, %s\n",
				result.Source,
				result.FilesWritten,
				formatBytes(result.BytesTotal),
				result.Duration.Round(time.Millisecond),
			)
		}
	}

	fmt.Println()
	fmt.Printf("Summary: %d succeeded, %d failed, %s total\n", successCount, failCount, formatBytes(totalBytes))
}

func formatBytes(bytes int64) string {
	const (
		kilobyte = 1024
		megabyte = kilobyte * 1024
		gigabyte = megabyte * 1024
	)

	switch {
	case bytes >= gigabyte:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(gigabyte))
	case bytes >= megabyte:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(megabyte))
	case bytes >= kilobyte:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(kilobyte))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
