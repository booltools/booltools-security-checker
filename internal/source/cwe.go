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

type CWESource struct {
	config     config.SourceConfig
	httpClient *crawler.HTTPClient
	writer     *storage.Writer
	logger     *slog.Logger
}

type cweVersionResponse struct {
	ContentVersion string `json:"content_version"`
}

func NewCWESource(cfg config.SourceConfig, httpClient *crawler.HTTPClient, writer *storage.Writer, logger *slog.Logger) *CWESource {
	return &CWESource{
		config:     cfg,
		httpClient: httpClient,
		writer:     writer,
		logger:     logger,
	}
}

func (s *CWESource) Name() string {
	return s.config.Name
}

func (s *CWESource) Download(ctx context.Context) (*crawler.DownloadResult, error) {
	var totalBytes int64
	filesWritten := 0

	versionURL := s.config.URL + "cwe/version"
	versionResp, err := s.httpClient.Get(ctx, versionURL, nil)
	if err != nil {
		return nil, fmt.Errorf("fetching CWE version: %w", err)
	}

	versionBody, err := io.ReadAll(versionResp.Body)
	versionResp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("reading CWE version response: %w", err)
	}

	bytesWritten, err := s.writer.WriteFile(s.config.OutputSubdir, "version.json", jsonReader(versionBody))
	if err != nil {
		return nil, fmt.Errorf("writing CWE version: %w", err)
	}
	totalBytes += bytesWritten
	filesWritten++

	var versionData cweVersionResponse
	_ = json.Unmarshal(versionBody, &versionData)
	s.logger.Info("CWE version fetched", "version", versionData.ContentVersion)

	topViews := []struct {
		id       string
		filename string
	}{
		{"1425", "top25_2025.json"},
		{"1450", "owasp_top10_2025.json"},
		{"1000", "research_concepts.json"},
	}

	for _, view := range topViews {
		viewURL := fmt.Sprintf("%scwe/view/%s", s.config.URL, view.id)
		s.logger.Debug("fetching CWE view", "view_id", view.id)

		response, err := s.httpClient.Get(ctx, viewURL, nil)
		if err != nil {
			s.logger.Warn("failed to fetch CWE view", "view_id", view.id, "error", err)
			continue
		}

		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			s.logger.Warn("failed to read CWE view body", "view_id", view.id, "error", err)
			continue
		}

		bytesWritten, err = s.writer.WriteFile(s.config.OutputSubdir, view.filename, jsonReader(body))
		if err != nil {
			return nil, fmt.Errorf("writing CWE view %s: %w", view.id, err)
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
