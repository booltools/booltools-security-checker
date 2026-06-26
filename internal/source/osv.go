package source

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/booltools/security-checker/internal/config"
	"github.com/booltools/security-checker/internal/crawler"
	"github.com/booltools/security-checker/internal/storage"
)

type OSVSource struct {
	config     config.SourceConfig
	httpClient *crawler.HTTPClient
	writer     *storage.Writer
	logger     *slog.Logger
}

func NewOSVSource(cfg config.SourceConfig, httpClient *crawler.HTTPClient, writer *storage.Writer, logger *slog.Logger) *OSVSource {
	return &OSVSource{
		config:     cfg,
		httpClient: httpClient,
		writer:     writer,
		logger:     logger,
	}
}

func (s *OSVSource) Name() string {
	return s.config.Name
}

func (s *OSVSource) Download(ctx context.Context) (*crawler.DownloadResult, error) {
	ecosystems := s.config.Ecosystems
	if len(ecosystems) == 0 {
		ecosystems = []string{"Go", "npm", "PyPI", "Maven", "NuGet"}
	}

	var totalBytes int64
	filesWritten := 0

	for _, ecosystem := range ecosystems {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		url := fmt.Sprintf("%s/%s/all.zip", s.config.BaseURL, ecosystem)
		filename := fmt.Sprintf("%s.zip", ecosystem)

		s.logger.Debug("downloading OSV ecosystem", "ecosystem", ecosystem)

		file, err := s.writer.CreateFile(s.config.OutputSubdir, filename)
		if err != nil {
			return nil, fmt.Errorf("creating file for ecosystem %s: %w", ecosystem, err)
		}

		headers := map[string]string{
			"Accept": "application/zip",
		}

		bytesWritten, err := s.httpClient.Download(ctx, url, headers, file)
		file.Close()
		if err != nil {
			s.logger.Warn("failed to download OSV ecosystem",
				"ecosystem", ecosystem,
				"error", err,
			)
			continue
		}

		totalBytes += bytesWritten
		filesWritten++

		s.logger.Debug("OSV ecosystem downloaded",
			"ecosystem", ecosystem,
			"bytes", bytesWritten,
		)
	}

	metadata := storage.DownloadMetadata{
		Source:       s.config.Name,
		URL:          s.config.BaseURL,
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
