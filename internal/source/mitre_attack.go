package source

import (
	"context"
	"fmt"
	"path"
	"time"

	"github.com/booltools/security-checker/internal/config"
	"github.com/booltools/security-checker/internal/crawler"
	"github.com/booltools/security-checker/internal/storage"
)

type MITREAttackSource struct {
	config     config.SourceConfig
	httpClient *crawler.HTTPClient
	writer     *storage.Writer
}

func NewMITREAttackSource(cfg config.SourceConfig, httpClient *crawler.HTTPClient, writer *storage.Writer) *MITREAttackSource {
	return &MITREAttackSource{
		config:     cfg,
		httpClient: httpClient,
		writer:     writer,
	}
}

func (s *MITREAttackSource) Name() string {
	return s.config.Name
}

func (s *MITREAttackSource) Download(ctx context.Context) (*crawler.DownloadResult, error) {
	var totalBytes int64
	filesWritten := 0

	for _, url := range s.config.URLs {
		filename := path.Base(url)

		file, err := s.writer.CreateFile(s.config.OutputSubdir, filename)
		if err != nil {
			return nil, fmt.Errorf("creating file for %s: %w", url, err)
		}

		bytesWritten, err := s.httpClient.Download(ctx, url, nil, file)
		file.Close()
		if err != nil {
			return nil, fmt.Errorf("downloading %s: %w", url, err)
		}

		totalBytes += bytesWritten
		filesWritten++
	}

	metadata := storage.DownloadMetadata{
		Source:       s.config.Name,
		URL:          fmt.Sprintf("%d URLs", len(s.config.URLs)),
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
