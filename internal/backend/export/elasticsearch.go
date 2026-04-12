package export

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ElasticsearchConfig holds configuration for the Elasticsearch export backend.
type ElasticsearchConfig struct {
	// Endpoint is the Elasticsearch URL (e.g., "https://es.example.com:9200").
	Endpoint string

	// Index is the target index name. Defaults to "sidereal-proberesults".
	Index string

	// APIKey is the Elasticsearch API key for authentication.
	APIKey string

	// Serializer is the format serializer to use. Defaults to JSON.
	Serializer FormatSerializer
}

// ElasticsearchBackend exports audit records to Elasticsearch via the index API.
type ElasticsearchBackend struct {
	config ElasticsearchConfig
	client *http.Client
}

// NewElasticsearchBackend creates a new Elasticsearch export backend.
func NewElasticsearchBackend(config ElasticsearchConfig) *ElasticsearchBackend {
	if config.Index == "" {
		config.Index = "sidereal-proberesults"
	}
	if config.Serializer == nil {
		config.Serializer = &JSONSerializer{}
	}

	return &ElasticsearchBackend{
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

// Export sends the audit record to Elasticsearch.
func (b *ElasticsearchBackend) Export(ctx context.Context, record AuditRecord) error {
	payload, err := b.config.Serializer.Serialize(record)
	if err != nil {
		return fmt.Errorf("elasticsearch: serialization failed: %w", err)
	}

	url := fmt.Sprintf("%s/%s/_doc/%s", b.config.Endpoint, b.config.Index, record.ProbeID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("elasticsearch: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", b.config.Serializer.ContentType())
	if b.config.APIKey != "" {
		req.Header.Set("Authorization", "ApiKey "+b.config.APIKey)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("elasticsearch: request failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("elasticsearch: index API returned status %d", resp.StatusCode)
	}

	return nil
}

func (b *ElasticsearchBackend) Name() string { return "elasticsearch" }
