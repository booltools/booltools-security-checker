package source

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/booltools/security-checker/internal/config"
	"github.com/booltools/security-checker/internal/crawler"
	"github.com/booltools/security-checker/internal/storage"
)

type VulnersSource struct {
	config     config.SourceConfig
	httpClient *crawler.HTTPClient
	writer     *storage.Writer
	logger     *slog.Logger
}

var defaultVulnersCollections = []string{
	"cve",
	"exploitdb",
	"metasploit",
}

func NewVulnersSource(cfg config.SourceConfig, httpClient *crawler.HTTPClient, writer *storage.Writer, logger *slog.Logger) *VulnersSource {
	return &VulnersSource{
		config:     cfg,
		httpClient: httpClient,
		writer:     writer,
		logger:     logger,
	}
}

func (s *VulnersSource) Name() string {
	return s.config.Name
}

func (s *VulnersSource) Download(ctx context.Context) (*crawler.DownloadResult, error) {
	apiKey := s.config.ResolveAPIKey()
	if apiKey == "" {
		return nil, fmt.Errorf("VULNERS_API_KEY environment variable is required for Vulners source")
	}

	headers := map[string]string{
		s.config.AuthHeader: apiKey,
	}

	var totalBytes int64
	filesWritten := 0

	for _, collection := range defaultVulnersCollections {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		url := fmt.Sprintf("%s?type=%s", s.config.URL, collection)
		s.logger.Debug("fetching Vulners collection", "collection", collection)

		response, err := s.httpClient.Get(ctx, url, headers)
		if err != nil {
			s.logger.Warn("failed to fetch Vulners collection",
				"collection", collection,
				"error", err,
			)
			continue
		}

		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			s.logger.Warn("failed to read Vulners response",
				"collection", collection,
				"error", err,
			)
			continue
		}

		var rawJSON json.RawMessage
		if err := json.Unmarshal(body, &rawJSON); err != nil {
			s.logger.Warn("invalid JSON from Vulners",
				"collection", collection,
				"error", err,
			)
			continue
		}

		filename := fmt.Sprintf("%s.json", collection)
		bytesWritten, err := s.writer.WriteFile(s.config.OutputSubdir, filename, jsonReader(body))
		if err != nil {
			return nil, fmt.Errorf("writing Vulners collection %s: %w", collection, err)
		}

		totalBytes += bytesWritten
		filesWritten++
	}

	metadata := storage.DownloadMetadata{
		Source:       s.config.Name,
		URL:          s.config.URL,
		DownloadedAt: time.Now().UTC(),
		BytesWritten: totalBytes,
		FilePath:     s.writer.FilePath(s.config.OutputSubdir, ""),
	}
	_ = s.writer.WriteMetadata(s.config.OutputSubdir, metadata)

	return &crawler.DownloadResult{
		Source:       s.config.Name,
		FilesWritten: filesWritten,
		BytesTotal:   totalBytes,
	}, nil
}
