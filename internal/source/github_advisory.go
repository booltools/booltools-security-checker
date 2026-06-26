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

type GitHubAdvisorySource struct {
	config     config.SourceConfig
	httpClient *crawler.HTTPClient
	writer     *storage.Writer
	logger     *slog.Logger
	since      *time.Time
}

type githubAdvisory struct {
	GHSAID      string `json:"ghsa_id"`
	CVEID       string `json:"cve_id"`
	Summary     string `json:"summary"`
	Severity    string `json:"severity"`
	PublishedAt string `json:"published_at"`
	UpdatedAt   string `json:"updated_at"`
}

func NewGitHubAdvisorySource(cfg config.SourceConfig, httpClient *crawler.HTTPClient, writer *storage.Writer, logger *slog.Logger) *GitHubAdvisorySource {
	return &GitHubAdvisorySource{
		config:     cfg,
		httpClient: httpClient,
		writer:     writer,
		logger:     logger,
	}
}

func (s *GitHubAdvisorySource) SetSince(since time.Time) {
	s.since = &since
}

func (s *GitHubAdvisorySource) Name() string {
	return s.config.Name
}

func (s *GitHubAdvisorySource) Download(ctx context.Context) (*crawler.DownloadResult, error) {
	token := s.config.ResolveAPIKey()
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN environment variable is required for GitHub Advisory source")
	}

	headers := map[string]string{
		"Authorization":        "Bearer " + token,
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}

	pageSize := s.config.PageSize
	if pageSize == 0 {
		pageSize = 100
	}

	var allAdvisories []json.RawMessage
	cursor := ""
	pageNumber := 0

	for {
		url := fmt.Sprintf("%s?per_page=%d&type=reviewed", s.config.URL, pageSize)
		if cursor != "" {
			url += "&after=" + cursor
		}
		if s.since != nil {
			url += "&updated=" + s.since.Format("2006-01-02T15:04:05Z")
		}

		s.logger.Debug("fetching GitHub advisories page", "page", pageNumber)

		response, err := s.httpClient.Get(ctx, url, headers)
		if err != nil {
			return nil, fmt.Errorf("fetching GitHub advisories page %d: %w", pageNumber, err)
		}

		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("reading GitHub advisories response: %w", err)
		}

		var advisories []json.RawMessage
		if err := json.Unmarshal(body, &advisories); err != nil {
			return nil, fmt.Errorf("parsing GitHub advisories response: %w", err)
		}

		if len(advisories) == 0 {
			break
		}

		allAdvisories = append(allAdvisories, advisories...)
		pageNumber++

		if len(advisories) < pageSize {
			break
		}

		var lastAdvisory githubAdvisory
		if err := json.Unmarshal(advisories[len(advisories)-1], &lastAdvisory); err == nil {
			cursor = lastAdvisory.GHSAID
		} else {
			break
		}

		if pageNumber >= 50 {
			s.logger.Warn("GitHub advisory download capped at 50 pages", "total_fetched", len(allAdvisories))
			break
		}
	}

	s.logger.Info("GitHub advisories fetched", "total", len(allAdvisories))

	combinedData, err := json.Marshal(allAdvisories)
	if err != nil {
		return nil, fmt.Errorf("marshaling combined advisories: %w", err)
	}

	bytesWritten, err := s.writer.WriteFile(s.config.OutputSubdir, "advisories.json", jsonReader(combinedData))
	if err != nil {
		return nil, fmt.Errorf("writing advisories file: %w", err)
	}

	metadata := storage.DownloadMetadata{
		Source:       s.config.Name,
		URL:          s.config.URL,
		DownloadedAt: time.Now().UTC(),
		BytesWritten: bytesWritten,
		FilePath:     s.writer.FilePath(s.config.OutputSubdir, "advisories.json"),
	}
	_ = s.writer.WriteMetadata(s.config.OutputSubdir, metadata)

	return &crawler.DownloadResult{
		Source:       s.config.Name,
		FilesWritten: 1,
		BytesTotal:   bytesWritten,
	}, nil
}
