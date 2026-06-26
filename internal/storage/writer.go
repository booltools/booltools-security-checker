package storage

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type DownloadMetadata struct {
	Source       string    `json:"source"`
	URL          string    `json:"url"`
	DownloadedAt time.Time `json:"downloaded_at"`
	BytesWritten int64     `json:"bytes_written"`
	FilePath     string    `json:"file_path"`
}

type Writer struct {
	baseDir string
}

func NewWriter(baseDir string) *Writer {
	return &Writer{baseDir: baseDir}
}

func (w *Writer) EnsureDir(subdir string) (string, error) {
	dirPath := filepath.Join(w.baseDir, subdir)
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return "", fmt.Errorf("creating directory %s: %w", dirPath, err)
	}
	return dirPath, nil
}

func (w *Writer) CreateFile(subdir string, filename string) (*os.File, error) {
	dirPath, err := w.EnsureDir(subdir)
	if err != nil {
		return nil, err
	}

	filePath := filepath.Join(dirPath, filename)
	file, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("creating file %s: %w", filePath, err)
	}

	return file, nil
}

func (w *Writer) WriteFile(subdir string, filename string, reader io.Reader) (int64, error) {
	file, err := w.CreateFile(subdir, filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	bytesWritten, err := io.Copy(file, reader)
	if err != nil {
		return bytesWritten, fmt.Errorf("writing to %s: %w", file.Name(), err)
	}

	return bytesWritten, nil
}

func (w *Writer) WriteGzip(subdir string, filename string, reader io.Reader) (int64, error) {
	file, err := w.CreateFile(subdir, filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	gzWriter := gzip.NewWriter(file)
	defer gzWriter.Close()

	bytesWritten, err := io.Copy(gzWriter, reader)
	if err != nil {
		return bytesWritten, fmt.Errorf("writing gzip to %s: %w", file.Name(), err)
	}

	return bytesWritten, nil
}

func (w *Writer) WriteJSON(subdir string, filename string, data interface{}) (int64, error) {
	file, err := w.CreateFile(subdir, filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(data); err != nil {
		return 0, fmt.Errorf("encoding JSON to %s: %w", file.Name(), err)
	}

	info, err := file.Stat()
	if err != nil {
		return 0, nil
	}

	return info.Size(), nil
}

func (w *Writer) WriteMetadata(subdir string, metadata DownloadMetadata) error {
	_, err := w.WriteJSON(subdir, "_metadata.json", metadata)
	return err
}

func (w *Writer) FilePath(subdir string, filename string) string {
	return filepath.Join(w.baseDir, subdir, filename)
}
