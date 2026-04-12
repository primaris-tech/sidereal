package export

import (
	"context"
	"fmt"
	"math"
	"time"
)

// RetryConfig controls exponential backoff behavior.
type RetryConfig struct {
	// InitialInterval is the first retry delay. Default: 5s.
	InitialInterval time.Duration

	// MaxInterval is the maximum delay between retries. Default: 5m.
	MaxInterval time.Duration

	// MaxElapsedTime is the total time window for retries. Default: 24h.
	MaxElapsedTime time.Duration

	// MaxRetries is the maximum number of retry attempts. Default: 10.
	MaxRetries int
}

// DefaultRetryConfig returns the default retry configuration.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		InitialInterval: 5 * time.Second,
		MaxInterval:     5 * time.Minute,
		MaxElapsedTime:  24 * time.Hour,
		MaxRetries:      10,
	}
}

// RetryableBackend wraps an AuditExportBackend with exponential backoff retry.
type RetryableBackend struct {
	backend AuditExportBackend
	config  RetryConfig
}

// NewRetryableBackend wraps the given backend with retry logic.
func NewRetryableBackend(backend AuditExportBackend, config RetryConfig) *RetryableBackend {
	return &RetryableBackend{
		backend: backend,
		config:  config,
	}
}

// Export attempts to export the record, retrying with exponential backoff on failure.
func (r *RetryableBackend) Export(ctx context.Context, record AuditRecord) error {
	start := time.Now()
	var lastErr error

	for attempt := 0; attempt <= r.config.MaxRetries; attempt++ {
		if time.Since(start) > r.config.MaxElapsedTime {
			return fmt.Errorf("export to %s: max elapsed time exceeded after %d attempts: %w",
				r.backend.Name(), attempt, lastErr)
		}

		err := r.backend.Export(ctx, record)
		if err == nil {
			return nil
		}
		lastErr = err

		if attempt == r.config.MaxRetries {
			break
		}

		delay := backoffDelay(attempt, r.config.InitialInterval, r.config.MaxInterval)

		select {
		case <-ctx.Done():
			return fmt.Errorf("export to %s: context cancelled during retry: %w", r.backend.Name(), ctx.Err())
		case <-time.After(delay):
		}
	}

	return fmt.Errorf("export to %s: exhausted %d retries: %w",
		r.backend.Name(), r.config.MaxRetries, lastErr)
}

// Name delegates to the wrapped backend.
func (r *RetryableBackend) Name() string {
	return r.backend.Name()
}

// backoffDelay calculates the delay for the given attempt using exponential backoff.
func backoffDelay(attempt int, initial, max time.Duration) time.Duration {
	delay := time.Duration(float64(initial) * math.Pow(2, float64(attempt)))
	if delay > max {
		delay = max
	}
	return delay
}
