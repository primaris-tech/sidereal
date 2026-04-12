// Package webhook implements HTTP clients for delivering incident notifications
// to external IR systems (ServiceNow, JIRA, or generic HTTP POST endpoints).
package webhook

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

// IncidentPayload is the JSON body delivered to the IR webhook endpoint.
type IncidentPayload struct {
	// IncidentName is the Kubernetes resource name of the SiderealIncident.
	IncidentName string `json:"incidentName"`

	// ProbeType is the probe surface that detected the failure.
	ProbeType string `json:"probeType"`

	// TargetNamespace is where the control failure was detected.
	TargetNamespace string `json:"targetNamespace"`

	// Outcome is the raw probe outcome.
	Outcome string `json:"outcome"`

	// ControlEffectiveness is the derived effectiveness.
	ControlEffectiveness string `json:"controlEffectiveness"`

	// Severity is the incident severity (Critical, High, Medium, Low).
	Severity string `json:"severity"`

	// Description is a human-readable description.
	Description string `json:"description"`

	// ControlID is the primary NIST 800-53 control.
	ControlID string `json:"controlId,omitempty"`

	// MitreID is the MITRE ATT&CK technique ID.
	MitreID string `json:"mitreId,omitempty"`

	// ProbeResultRef is the name of the triggering SiderealProbeResult.
	ProbeResultRef string `json:"probeResultRef"`

	// Timestamp is when the incident was created.
	Timestamp time.Time `json:"timestamp"`
}

// Config holds configuration for the IR webhook client.
type Config struct {
	// URL is the webhook endpoint.
	URL string

	// AuthToken is an optional bearer token for authentication.
	AuthToken string

	// AuthHeader is the header name for the token. Defaults to "Authorization".
	AuthHeader string

	// Timeout is the HTTP request timeout. Defaults to 30s.
	Timeout time.Duration

	// HTTPClient allows injecting a custom HTTP client (for testing).
	HTTPClient *http.Client
}

// Client delivers incident notifications to an IR webhook endpoint.
type Client struct {
	config Config
	client *http.Client
}

// NewClient creates a new webhook client.
func NewClient(config Config) *Client {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.AuthHeader == "" {
		config.AuthHeader = "Authorization"
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: config.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		}
	}

	return &Client{
		config: config,
		client: httpClient,
	}
}

// Deliver sends the incident payload to the configured webhook endpoint.
// Returns nil on success (2xx response), or an error on failure.
func (c *Client) Deliver(ctx context.Context, payload IncidentPayload) error {
	if c.config.URL == "" {
		return fmt.Errorf("webhook: no URL configured")
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("webhook: failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "sidereal-incident-webhook/1.0")

	if c.config.AuthToken != "" {
		req.Header.Set(c.config.AuthHeader, c.config.AuthToken)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: request failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: endpoint returned status %d", resp.StatusCode)
	}

	return nil
}
