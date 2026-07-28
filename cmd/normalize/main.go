package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/booltools/security-checker/internal/normalizer"
)

func main() {
	dataDir := flag.String("data-dir", "./data", "Directory containing downloaded security data")
	outputDB := flag.String("output", "", "Output SQLite database path (default: <data-dir>/security_rules.db)")
	verbose := flag.Bool("verbose", false, "Enable debug logging")

	flag.Parse()

	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))

	dbPath := *outputDB
	if dbPath == "" {
		dbPath = filepath.Join(".", "security_rules.db")
	}

	os.Remove(dbPath)
	os.Remove(dbPath + "-wal")
	os.Remove(dbPath + "-shm")

	database, err := normalizer.NewDatabase(dbPath, logger)
	if err != nil {
		logger.Error("failed to create database", "error", err)
		os.Exit(1)
	}
	defer database.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChannel
		logger.Info("received shutdown signal, stopping...")
		cancel()
	}()

	norm := normalizer.NewNormalizer(database, *dataDir, logger)

	norm.RegisterParser(normalizer.NewCISAKEVParser(*dataDir))
	norm.RegisterParser(normalizer.NewExploitDBParser(*dataDir))
	norm.RegisterParser(normalizer.NewNVDParser(*dataDir))
	norm.RegisterParser(normalizer.NewCWEParser(*dataDir))
	norm.RegisterParser(normalizer.NewMITREAttackParser(*dataDir))
	norm.RegisterParser(normalizer.NewCAPECParser(*dataDir))
	norm.RegisterParser(normalizer.NewNucleiParser(*dataDir))
	norm.RegisterParser(normalizer.NewGitHubAdvisoryParser(*dataDir))
	norm.RegisterParser(normalizer.NewOSVParser(*dataDir))
	norm.RegisterParser(normalizer.NewSecretsParser())
	norm.RegisterParser(normalizer.NewIaCParser())
	norm.RegisterParser(normalizer.NewContainerParser())
	norm.RegisterParser(normalizer.NewSASTPatternParser())

	startTime := time.Now()
	logger.Info("starting normalization pipeline", "data_dir", *dataDir, "output", dbPath)

	if err := norm.Run(ctx); err != nil {
		logger.Error("normalization failed", "error", err)
		os.Exit(1)
	}

	enricher := normalizer.NewEnricher(database, *dataDir, logger)
	if err := enricher.Run(ctx); err != nil {
		logger.Warn("enrichment had errors", "error", err)
	}

	totalCount, _ := database.Count()
	fmt.Printf("\nDatabase created: %s\n", dbPath)
	fmt.Printf("Total rules: %d\n", totalCount)
	fmt.Printf("Duration: %s\n", time.Since(startTime).Round(time.Millisecond))
}
