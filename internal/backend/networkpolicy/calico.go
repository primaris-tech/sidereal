package networkpolicy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// CalicoConfig holds configuration for the Calico REST backend.
type CalicoConfig struct {
	// Endpoint is the Calico Enterprise flow log API address
	// (e.g., "https://calico-api.calico-system:5443").
	Endpoint string

	// TLSSkipVerify disables TLS certificate verification.
	// Only for development/testing.
	TLSSkipVerify bool

	// BearerToken is the ServiceAccount token for authenticating to the Calico API.
	BearerToken string
}

// CalicoBackend implements Backend by querying Calico's flow log REST API,
// filtered by the sidereal.cloud/probe-id pod label.
type CalicoBackend struct {
	config CalicoConfig
	client *http.Client
}

// NewCalicoBackend creates a new Calico backend with an HTTP client.
func NewCalicoBackend(config CalicoConfig) *CalicoBackend {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.TLSSkipVerify, //nolint:gosec // operator-configured
		},
	}
	return &CalicoBackend{
		config: config,
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
	}
}

// QueryFlowVerdict queries Calico's flow log API for records matching the
// given probeID within the specified time window.
//
// The query filters flows by the pod label sidereal.cloud/probe-id=<probeID>
// and maps the Calico action to our Verdict type:
//   - deny -> VerdictDropped
//   - allow -> VerdictForwarded
//   - no matching flows -> VerdictIndeterminate
func (b *CalicoBackend) QueryFlowVerdict(ctx context.Context, probeID string, window time.Duration) (Verdict, error) {
	// Calico Enterprise flow log query will be:
	//
	//   GET /api/v1/flows?label=sidereal.cloud/probe-id=<probeID>&since=<window>
	//
	// The response contains flow records with an "action" field (allow/deny).
	// For now, return an error indicating the Calico API integration
	// needs to be completed with the actual endpoint schema.
	return "", fmt.Errorf("calico: REST flow query not yet wired (requires Calico API schema); probeID=%s window=%s", probeID, window)
}
