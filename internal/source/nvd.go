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

type NVDSource struct {
	config     config.SourceConfig
	httpClient *crawler.HTTPClient
	writer     *storage.Writer
	logger     *slog.Logger
	since      *time.Time
}

type nvdResponse struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Vulnerabilities json.RawMessage `json:"vulnerabilities"`
}

func NewNVDSource(cfg config.SourceConfig, httpClient *crawler.HTTPClient, writer *storage.Writer, logger *slog.Logger) *NVDSource {
	return &NVDSource{
		config:     cfg,
		httpClient: httpClient,
		writer:     writer,
		logger:     logger,
	}
}

func (s *NVDSource) SetSince(since time.Time) {
	s.since = &since
}

func (s *NVDSource) Name() string {
	return s.config.Name
}

func (s *NVDSource) Download(ctx context.Context) (*crawler.DownloadResult, error) {
	pageSize := s.config.PageSize
	if pageSize == 0 {
		pageSize = 2000
	}

	headers := make(map[string]string)
	apiKey := s.config.ResolveAPIKey()
	if apiKey != "" {
		headers[s.config.AuthHeader] = apiKey
	}

	startIndex := 0
	totalResults := -1
	filesWritten := 0
	var totalBytes int64

	for {
		url := fmt.Sprintf("%s?startIndex=%d&resultsPerPage=%d", s.config.URL, startIndex, pageSize)
		if s.since != nil {
			url += fmt.Sprintf("&lastModStartDate=%s&lastModEndDate=%s",
				s.since.Format("2006-01-02T15:04:05.000"),
				time.Now().UTC().Format("2006-01-02T15:04:05.000"),
			)
		}

		s.logger.Debug("fetching NVD page", "start_index", startIndex, "page_size", pageSize)

		response, err := s.httpClient.Get(ctx, url, headers)
		if err != nil {
			return nil, fmt.Errorf("fetching NVD page at index %d: %w", startIndex, err)
		}

		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("reading NVD response body: %w", err)
		}

		var nvdResp nvdResponse
		if err := json.Unmarshal(body, &nvdResp); err != nil {
			return nil, fmt.Errorf("parsing NVD response: %w", err)
		}

		if totalResults == -1 {
			totalResults = nvdResp.TotalResults
			s.logger.Info("NVD total results", "total", totalResults)
		}

		filename := fmt.Sprintf("cves_%06d.json", startIndex)
		bytesWritten, err := s.writer.WriteFile(s.config.OutputSubdir, filename, io.NopCloser(
			jsonReader(body),
		))
		if err != nil {
			return nil, fmt.Errorf("writing NVD page file: %w", err)
		}

		totalBytes += bytesWritten
		filesWritten++

		startIndex += nvdResp.ResultsPerPage
		if startIndex >= totalResults {
			break
		}
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
