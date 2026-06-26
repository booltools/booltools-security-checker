package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	OutputDir        string                  `yaml:"output_dir"`
	Concurrency      int                     `yaml:"concurrency"`
	RequestTimeout   time.Duration           `yaml:"request_timeout"`
	RetryMaxAttempts int                     `yaml:"retry_max_attempts"`
	RetryBaseDelay   time.Duration           `yaml:"retry_base_delay"`
	Sources          map[string]SourceConfig `yaml:"sources"`
}

type SourceConfig struct {
	Enabled            bool     `yaml:"enabled"`
	Name               string   `yaml:"name"`
	Description        string   `yaml:"description"`
	URL                string   `yaml:"url"`
	URLs               []string `yaml:"urls"`
	BaseURL            string   `yaml:"base_url"`
	EcosystemsURL      string   `yaml:"ecosystems_url"`
	Format             string   `yaml:"format"`
	AuthType           string   `yaml:"auth_type"`
	AuthHeader         string   `yaml:"auth_header"`
	APIKeyEnv          string   `yaml:"api_key_env"`
	RateLimitPerSecond float64  `yaml:"rate_limit_per_second"`
	OutputSubdir       string   `yaml:"output_subdir"`
	OutputFilename     string   `yaml:"output_filename"`
	Paginated          bool     `yaml:"paginated"`
	PageSize           int      `yaml:"page_size"`
	Ecosystems         []string `yaml:"ecosystems"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	config := &Config{
		OutputDir:        "./data",
		Concurrency:      4,
		RequestTimeout:   120 * time.Second,
		RetryMaxAttempts: 3,
		RetryBaseDelay:   2 * time.Second,
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return config, nil
}

func (c *Config) validate() error {
	if c.OutputDir == "" {
		return fmt.Errorf("output_dir is required")
	}
	if c.Concurrency < 1 {
		return fmt.Errorf("concurrency must be at least 1")
	}

	for key, source := range c.Sources {
		if source.Name == "" {
			return fmt.Errorf("source %q: name is required", key)
		}
		if source.URL == "" && len(source.URLs) == 0 && source.BaseURL == "" {
			return fmt.Errorf("source %q: url, urls, or base_url is required", key)
		}
		if source.OutputSubdir == "" {
			return fmt.Errorf("source %q: output_subdir is required", key)
		}
	}

	return nil
}

func (c *Config) EnabledSources() map[string]SourceConfig {
	enabled := make(map[string]SourceConfig)
	for key, source := range c.Sources {
		if source.Enabled {
			enabled[key] = source
		}
	}
	return enabled
}

func (s *SourceConfig) ResolveAPIKey() string {
	if s.APIKeyEnv == "" {
		return ""
	}
	return os.Getenv(s.APIKeyEnv)
}
