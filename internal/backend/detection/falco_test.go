package detection

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// mockFalcoResponse implements FalcoResponse for testing.
type mockFalcoResponse struct {
	time         *timestamppb.Timestamp
	rule         string
	output       string
	priority     int32
	outputFields map[string]string
}

func (r *mockFalcoResponse) GetTime() *timestamppb.Timestamp   { return r.time }
func (r *mockFalcoResponse) GetRule() string                    { return r.rule }
func (r *mockFalcoResponse) GetOutput() string                  { return r.output }
func (r *mockFalcoResponse) GetPriority() int32                 { return r.priority }
func (r *mockFalcoResponse) GetOutputFields() map[string]string { return r.outputFields }

// mockFalcoStream implements FalcoOutputStream for testing.
type mockFalcoStream struct {
	responses []FalcoResponse
	idx       int
}

func (s *mockFalcoStream) Recv() (FalcoResponse, error) {
	if s.idx >= len(s.responses) {
		return nil, io.EOF
	}
	resp := s.responses[s.idx]
	s.idx++
	return resp, nil
}

func newMockStreamFn(responses []FalcoResponse) func(ctx context.Context, conn *grpc.ClientConn, since time.Time) (FalcoOutputStream, error) {
	return func(_ context.Context, _ *grpc.ClientConn, _ time.Time) (FalcoOutputStream, error) {
		return &mockFalcoStream{responses: responses}, nil
	}
}

func TestFalcoBackend_Detected(t *testing.T) {
	now := time.Now()
	responses := []FalcoResponse{
		&mockFalcoResponse{
			time:     timestamppb.New(now),
			rule:     "Escape to Host via unshare",
			output:   "probe-abc detected unshare",
			priority: 2, // Critical
			outputFields: map[string]string{
				"k8s.pod.name":            "detection-probe-xyz",
				"k8s.ns.name":             "sidereal-system",
				"sidereal.cloud/probe-id": "probe-abc",
			},
		},
	}

	backend := NewFalcoBackendWithStream(newMockStreamFn(responses))
	alerts, err := backend.QueryAlerts(context.Background(), "probe-abc", 60*time.Second)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].RuleName != "Escape to Host via unshare" {
		t.Errorf("unexpected rule: %q", alerts[0].RuleName)
	}
	if alerts[0].PodName != "detection-probe-xyz" {
		t.Errorf("unexpected pod: %q", alerts[0].PodName)
	}
	if alerts[0].Priority != "Critical" {
		t.Errorf("unexpected priority: %q", alerts[0].Priority)
	}
}

func TestFalcoBackend_NoMatch(t *testing.T) {
	responses := []FalcoResponse{
		&mockFalcoResponse{
			time:     timestamppb.New(time.Now()),
			rule:     "Write below binary dir",
			output:   "some other alert",
			priority: 4,
			outputFields: map[string]string{
				"k8s.pod.name": "unrelated-pod",
			},
		},
	}

	backend := NewFalcoBackendWithStream(newMockStreamFn(responses))
	alerts, err := backend.QueryAlerts(context.Background(), "probe-abc", 60*time.Second)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts, got %d", len(alerts))
	}
}

func TestFalcoBackend_ExpiredAlert(t *testing.T) {
	// Alert timestamp is before the window.
	oldTime := time.Now().Add(-5 * time.Minute)
	responses := []FalcoResponse{
		&mockFalcoResponse{
			time:     timestamppb.New(oldTime),
			rule:     "old alert",
			output:   "probe-abc old event",
			priority: 4,
			outputFields: map[string]string{
				"sidereal.cloud/probe-id": "probe-abc",
			},
		},
	}

	backend := NewFalcoBackendWithStream(newMockStreamFn(responses))
	alerts, err := backend.QueryAlerts(context.Background(), "probe-abc", 60*time.Second)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts (expired), got %d", len(alerts))
	}
}

func TestFalcoBackend_StreamError(t *testing.T) {
	streamFn := func(_ context.Context, _ *grpc.ClientConn, _ time.Time) (FalcoOutputStream, error) {
		return nil, fmt.Errorf("connection refused")
	}

	backend := NewFalcoBackendWithStream(streamFn)
	_, err := backend.QueryAlerts(context.Background(), "probe-abc", 60*time.Second)

	if err == nil {
		t.Error("expected error for stream creation failure")
	}
}

func TestFalcoBackend_OutputMatch(t *testing.T) {
	// Probe ID found in output string but not in output fields.
	responses := []FalcoResponse{
		&mockFalcoResponse{
			time:         timestamppb.New(time.Now()),
			rule:         "Suspicious exec",
			output:       "exec detected in pod with label probe-id=probe-abc",
			priority:     4,
			outputFields: map[string]string{},
		},
	}

	backend := NewFalcoBackendWithStream(newMockStreamFn(responses))
	alerts, err := backend.QueryAlerts(context.Background(), "probe-abc", 60*time.Second)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Errorf("expected 1 alert via output match, got %d", len(alerts))
	}
}

func TestFalcoBackend_NoStreamFn(t *testing.T) {
	backend := &FalcoBackend{}
	_, err := backend.QueryAlerts(context.Background(), "probe-abc", 60*time.Second)

	if err == nil {
		t.Error("expected error when streamFn is nil")
	}
}

func TestFalcoBackend_Close(t *testing.T) {
	backend := &FalcoBackend{}
	if err := backend.Close(); err != nil {
		t.Errorf("Close on nil conn should not error: %v", err)
	}
}

func TestContainsProbeID(t *testing.T) {
	tests := []struct {
		name     string
		fields   map[string]string
		output   string
		probeID  string
		expected bool
	}{
		{"in fields", map[string]string{"sidereal.cloud/probe-id": "p1"}, "", "p1", true},
		{"in output", map[string]string{}, "alert for p1", "p1", true},
		{"no match", map[string]string{"other": "value"}, "unrelated", "p1", false},
		{"nil fields", nil, "p1 in output", "p1", true},
		{"nil fields no match", nil, "nothing", "p1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsProbeID(tt.fields, tt.output, tt.probeID)
			if got != tt.expected {
				t.Errorf("containsProbeID() = %v, want %v", got, tt.expected)
			}
		})
	}
}
