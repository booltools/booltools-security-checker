package source

import (
	"context"
	"time"

	"github.com/booltools/security-checker/internal/config"
	"github.com/booltools/security-checker/internal/crawler"
	"github.com/booltools/security-checker/internal/storage"
)

type EPSSSource struct {
	config     config.SourceConfig
	httpClient *crawler.HTTPClient
	writer     *storage.Writer
}

func NewEPSSSource(cfg config.SourceConfig, httpClient *crawler.HTTPClient, writer *storage.Writer) *EPSSSource {
	return &EPSSSource{
		config:     cfg,
		httpClient: httpClient,
		writer:     writer,
	}
}

func (s *EPSSSource) Name() string {
	return s.config.Name
}

func (s *EPSSSource) Download(ctx context.Context) (*crawler.DownloadResult, error) {
	file, err := s.writer.CreateFile(s.config.OutputSubdir, s.config.OutputFilename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	headers := map[string]string{
		"Accept": "application/gzip",
	}

	bytesWritten, err := s.httpClient.Download(ctx, s.config.URL, headers, file)
	if err != nil {
		return nil, err
	}

	metadata := storage.DownloadMetadata{
		Source:       s.config.Name,
		URL:          s.config.URL,
		DownloadedAt: time.Now().UTC(),
		BytesWritten: bytesWritten,
		FilePath:     file.Name(),
	}
	_ = s.writer.WriteMetadata(s.config.OutputSubdir, metadata)

	return &crawler.DownloadResult{
		Source:       s.config.Name,
		FilesWritten: 1,
		BytesTotal:   bytesWritten,
	}, nil
}
