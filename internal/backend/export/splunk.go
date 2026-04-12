package export

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SplunkConfig holds configuration for the Splunk HEC export backend.
type SplunkConfig struct {
	// Endpoint is the Splunk HEC URL (e.g., "https://splunk.example.com:8088").
	Endpoint string

	// Token is the HEC authentication token.
	Token string

	// Index is the target Splunk index. Optional.
	Index string

	// Source is the Splunk source field. Defaults to "sidereal".
	Source string

	// SourceType is the Splunk sourcetype field. Defaults to "sidereal:probe".
	SourceType string

	// Serializer is the format serializer to use. Defaults to JSON.
	Serializer FormatSerializer
}

// SplunkBackend exports audit records to Splunk via HTTP Event Collector.
type SplunkBackend struct {
	config SplunkConfig
	client *http.Client
}

// splunkEvent is the HEC event envelope.
type splunkEvent struct {
	Time       int64       `json:"time"`
	Source     string      `json:"source"`
	SourceType string      `json:"sourcetype"`
	Index      string      `json:"index,omitempty"`
	Event      interface{} `json:"event"`
}

// NewSplunkBackend creates a new Splunk HEC export backend.
func NewSplunkBackend(config SplunkConfig) *SplunkBackend {
	if config.Source == "" {
		config.Source = "sidereal"
	}
	if config.SourceType == "" {
		config.SourceType = "sidereal:probe"
	}
	if config.Serializer == nil {
		config.Serializer = &JSONSerializer{}
	}

	return &SplunkBackend{
		config: config,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		},
	}
}

// Export sends the audit record to Splunk HEC.
func (b *SplunkBackend) Export(ctx context.Context, record AuditRecord) error {
	payload, err := b.config.Serializer.Serialize(record)
	if err != nil {
		return fmt.Errorf("splunk: serialization failed: %w", err)
	}

	// Wrap in HEC event envelope.
	event := splunkEvent{
		Time:       record.Timestamp.Unix(),
		Source:     b.config.Source,
		SourceType: b.config.SourceType,
		Index:      b.config.Index,
		Event:      json.RawMessage(payload),
	}

	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("splunk: failed to marshal HEC event: %w", err)
	}

	url := b.config.Endpoint + "/services/collector/event"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("splunk: failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Splunk "+b.config.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("splunk: request failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("splunk: HEC returned status %d", resp.StatusCode)
	}

	return nil
}

func (b *SplunkBackend) Name() string { return "splunk" }
