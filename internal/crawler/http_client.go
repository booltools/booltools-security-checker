package crawler

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

type HTTPClient struct {
	client      *http.Client
	rateLimiter *rate.Limiter
	maxAttempts int
	baseDelay   time.Duration
	logger      *slog.Logger
}

type HTTPClientConfig struct {
	Timeout            time.Duration
	RateLimitPerSecond float64
	MaxAttempts        int
	BaseDelay          time.Duration
	Logger             *slog.Logger
}

func NewHTTPClient(config HTTPClientConfig) *HTTPClient {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.MaxAttempts < 1 {
		config.MaxAttempts = 3
	}
	if config.BaseDelay == 0 {
		config.BaseDelay = 2 * time.Second
	}
	if config.Timeout == 0 {
		config.Timeout = 120 * time.Second
	}

	var limiter *rate.Limiter
	if config.RateLimitPerSecond > 0 {
		limiter = rate.NewLimiter(rate.Limit(config.RateLimitPerSecond), 1)
	}

	return &HTTPClient{
		client: &http.Client{
			Timeout: config.Timeout,
		},
		rateLimiter: limiter,
		maxAttempts: config.MaxAttempts,
		baseDelay:   config.BaseDelay,
		logger:      config.Logger,
	}
}

func (h *HTTPClient) Do(ctx context.Context, request *http.Request) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt < h.maxAttempts; attempt++ {
		if attempt > 0 {
			delay := h.calculateBackoff(attempt)
			h.logger.Debug("retrying request",
				"url", request.URL.String(),
				"attempt", attempt+1,
				"delay", delay,
			)

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		if h.rateLimiter != nil {
			if err := h.rateLimiter.Wait(ctx); err != nil {
				return nil, fmt.Errorf("rate limiter wait: %w", err)
			}
		}

		response, err := h.client.Do(request.WithContext(ctx))
		if err != nil {
			lastErr = fmt.Errorf("request failed (attempt %d): %w", attempt+1, err)
			continue
		}

		if response.StatusCode == http.StatusTooManyRequests ||
			response.StatusCode >= http.StatusInternalServerError {
			lastErr = fmt.Errorf("server returned status %d (attempt %d)", response.StatusCode, attempt+1)
			response.Body.Close()
			continue
		}

		if response.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 512))
			response.Body.Close()
			return nil, fmt.Errorf("unexpected status %d: %s", response.StatusCode, string(body))
		}

		return response, nil
	}

	return nil, fmt.Errorf("all %d attempts exhausted: %w", h.maxAttempts, lastErr)
}

func (h *HTTPClient) Get(ctx context.Context, url string, headers map[string]string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", url, err)
	}

	request.Header.Set("User-Agent", "booltools-security-checker/1.0")
	request.Header.Set("Accept", "application/json")

	for key, value := range headers {
		request.Header.Set(key, value)
	}

	return h.Do(ctx, request)
}

func (h *HTTPClient) Download(ctx context.Context, url string, headers map[string]string, writer io.Writer) (int64, error) {
	response, err := h.Get(ctx, url, headers)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()

	bytesWritten, err := io.Copy(writer, response.Body)
	if err != nil {
		return bytesWritten, fmt.Errorf("downloading from %s: %w", url, err)
	}

	return bytesWritten, nil
}

func (h *HTTPClient) calculateBackoff(attempt int) time.Duration {
	backoff := float64(h.baseDelay) * math.Pow(2, float64(attempt-1))
	maxBackoff := 60 * time.Second
	if time.Duration(backoff) > maxBackoff {
		return maxBackoff
	}
	return time.Duration(backoff)
}
