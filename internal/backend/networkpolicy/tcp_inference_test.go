package networkpolicy

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"
)

// timeoutError implements net.Error with Timeout() = true.
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return false }

// connRefusedError wraps syscall.ECONNREFUSED in a net.OpError.
func connRefusedError() error {
	return &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Addr: &net.TCPAddr{
			IP:   net.ParseIP("10.0.0.1"),
			Port: 80,
		},
		Err: &net.OpError{
			Op:  "connect",
			Net: "tcp",
			Err: fmt.Errorf("connect: %w", syscall.ECONNREFUSED),
		},
	}
}

// fakeConn is a minimal net.Conn for testing successful connections.
type fakeConn struct{ net.Conn }

func (c *fakeConn) Close() error { return nil }

func TestTCPInference_Timeout(t *testing.T) {
	backend := NewTCPInferenceBackend(TCPInferenceConfig{
		TargetHost:     "10.0.0.1",
		TargetPort:     80,
		ConnectTimeout: 1 * time.Second,
	})
	backend.dialFn = func(_, _ string, _ time.Duration) (net.Conn, error) {
		return nil, &timeoutError{}
	}

	verdict, err := backend.QueryFlowVerdict(context.Background(), "probe-1", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict != VerdictInferredDropped {
		t.Errorf("expected InferredDropped, got %q", verdict)
	}
}

func TestTCPInference_Established(t *testing.T) {
	backend := NewTCPInferenceBackend(TCPInferenceConfig{
		TargetHost:     "10.0.0.1",
		TargetPort:     80,
		ConnectTimeout: 1 * time.Second,
	})
	backend.dialFn = func(_, _ string, _ time.Duration) (net.Conn, error) {
		return &fakeConn{}, nil
	}

	verdict, err := backend.QueryFlowVerdict(context.Background(), "probe-2", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict != VerdictInferredForwarded {
		t.Errorf("expected InferredForwarded, got %q", verdict)
	}
}

func TestTCPInference_ConnectionRefused(t *testing.T) {
	backend := NewTCPInferenceBackend(TCPInferenceConfig{
		TargetHost:     "10.0.0.1",
		TargetPort:     80,
		ConnectTimeout: 1 * time.Second,
	})
	backend.dialFn = func(_, _ string, _ time.Duration) (net.Conn, error) {
		return nil, connRefusedError()
	}

	verdict, err := backend.QueryFlowVerdict(context.Background(), "probe-3", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict != VerdictIndeterminate {
		t.Errorf("expected Indeterminate for connection refused, got %q", verdict)
	}
}

func TestTCPInference_UnexpectedError(t *testing.T) {
	backend := NewTCPInferenceBackend(TCPInferenceConfig{
		TargetHost:     "10.0.0.1",
		TargetPort:     80,
		ConnectTimeout: 1 * time.Second,
	})
	backend.dialFn = func(_, _ string, _ time.Duration) (net.Conn, error) {
		return nil, fmt.Errorf("DNS resolution failed")
	}

	_, err := backend.QueryFlowVerdict(context.Background(), "probe-4", 0)
	if err == nil {
		t.Error("expected error for unexpected dial failure")
	}
}

func TestTCPInference_DefaultTimeout(t *testing.T) {
	backend := NewTCPInferenceBackend(TCPInferenceConfig{
		TargetHost: "10.0.0.1",
		TargetPort: 80,
		// ConnectTimeout left at zero — should default to 5s.
	})
	if backend.config.ConnectTimeout != 5*time.Second {
		t.Errorf("expected 5s default timeout, got %v", backend.config.ConnectTimeout)
	}
}
