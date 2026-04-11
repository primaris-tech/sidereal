package networkpolicy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// TCPInferenceConfig holds configuration for the TCP inference backend.
type TCPInferenceConfig struct {
	// TargetHost is the ClusterIP or DNS name to connect to.
	TargetHost string

	// TargetPort is the TCP port to connect to.
	TargetPort int

	// ConnectTimeout is how long to wait for the TCP connection before
	// inferring the traffic was dropped. Defaults to 5 seconds.
	ConnectTimeout time.Duration
}

// TCPInferenceBackend implements Backend by attempting a TCP connection
// and interpreting the result. This works with any CNI since it doesn't
// require an observability layer.
//
// Inference rules:
//   - Timeout (i/o timeout, context deadline) -> InferredDropped
//   - Connection established                  -> InferredForwarded
//   - Connection refused (RST)                -> Indeterminate
//     (RST can indicate either a NetworkPolicy reset or simply a closed port)
type TCPInferenceBackend struct {
	config TCPInferenceConfig

	// dialFn is the function used to establish TCP connections.
	// Defaults to net.DialTimeout. Overridable for testing.
	dialFn func(network, address string, timeout time.Duration) (net.Conn, error)
}

// NewTCPInferenceBackend creates a new TCP inference backend.
func NewTCPInferenceBackend(config TCPInferenceConfig) *TCPInferenceBackend {
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = 5 * time.Second
	}
	return &TCPInferenceBackend{
		config: config,
		dialFn: net.DialTimeout,
	}
}

// QueryFlowVerdict attempts a TCP connection and infers the NetworkPolicy verdict.
// The probeID and window parameters are not used for TCP inference (they exist
// for CNI-backend compatibility) since the inference is immediate.
func (b *TCPInferenceBackend) QueryFlowVerdict(ctx context.Context, _ string, _ time.Duration) (Verdict, error) {
	addr := fmt.Sprintf("%s:%d", b.config.TargetHost, b.config.TargetPort)

	conn, err := b.dialFn("tcp", addr, b.config.ConnectTimeout)
	if err != nil {
		if isTimeoutError(err) {
			return VerdictInferredDropped, nil
		}
		if isConnectionRefused(err) {
			return VerdictIndeterminate, nil
		}
		return "", fmt.Errorf("tcp inference: unexpected dial error to %s: %w", addr, err)
	}

	conn.Close()
	return VerdictInferredForwarded, nil
}

// isTimeoutError checks if the error indicates a connection timeout.
func isTimeoutError(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

// isConnectionRefused checks if the error indicates connection refused (RST).
func isConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
