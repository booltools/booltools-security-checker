package normalizer

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type EPSSParser struct {
	dataDir string
}

type EPSSEntry struct {
	CVEID      string
	Score      float64
	Percentile float64
}

func NewEPSSParser(dataDir string) *EPSSParser {
	return &EPSSParser{dataDir: dataDir}
}

func (p *EPSSParser) Name() string {
	return "EPSS"
}

func (p *EPSSParser) Parse(ctx context.Context) ([]SecurityRule, error) {
	return nil, nil
}

func (p *EPSSParser) ParseScores(ctx context.Context) (map[string]EPSSEntry, error) {
	filePath := filepath.Join(p.dataDir, "epss", "epss_scores.csv.gz")
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening EPSS file: %w", err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("creating gzip reader: %w", err)
	}
	defer gzReader.Close()

	scores := make(map[string]EPSSEntry)
	scanner := bufio.NewScanner(gzReader)

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "cve,") {
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) < 3 {
			continue
		}

		cveID := strings.TrimSpace(parts[0])
		score, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		if err != nil {
			continue
		}
		percentile, err := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
		if err != nil {
			continue
		}

		scores[cveID] = EPSSEntry{
			CVEID:      cveID,
			Score:      score,
			Percentile: percentile,
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning EPSS CSV: %w", err)
	}

	return scores, nil
}
