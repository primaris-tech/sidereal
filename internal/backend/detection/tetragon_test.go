package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"google.golang.org/grpc"
)

// mockTetragonEvent implements TetragonEvent for testing.
type mockTetragonEvent struct {
	processExec   TetragonProcess
	processKprobe TetragonKprobe
	time          time.Time
}

func (e *mockTetragonEvent) GetProcessExec() TetragonProcess   { return e.processExec }
func (e *mockTetragonEvent) GetProcessKprobe() TetragonKprobe { return e.processKprobe }
func (e *mockTetragonEvent) GetTime() time.Time                { return e.time }

// mockTetragonStream implements TetragonEventStream for testing.
type mockTetragonStream struct {
	events []TetragonEvent
	idx    int
}

func (s *mockTetragonStream) Recv() (TetragonEvent, error) {
	if s.idx >= len(s.events) {
		return nil, io.EOF
	}
	event := s.events[s.idx]
	s.idx++
	return event, nil
}

func newMockTetragonStreamFn(events []TetragonEvent) func(ctx context.Context, conn *grpc.ClientConn, since time.Time) (TetragonEventStream, error) {
	return func(_ context.Context, _ *grpc.ClientConn, _ time.Time) (TetragonEventStream, error) {
		return &mockTetragonStream{events: events}, nil
	}
}

func TestTetragonBackend_ProcessExecDetected(t *testing.T) {
	events := []TetragonEvent{
		&mockTetragonEvent{
			time: time.Now(),
			processExec: TetragonProcess{
				Binary:    "/bin/sh",
				Arguments: "-c whoami",
				PodName:   "detection-probe-xyz",
				Namespace: "sidereal-system",
				Labels: map[string]string{
					"sidereal.cloud/probe-id": "probe-abc",
				},
			},
		},
	}

	backend := NewTetragonBackendWithStream(newMockTetragonStreamFn(events))
	alerts, err := backend.QueryAlerts(context.Background(), "probe-abc", 60*time.Second)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].RuleName != "process_exec:/bin/sh" {
		t.Errorf("unexpected rule: %q", alerts[0].RuleName)
	}
	if alerts[0].PodName != "detection-probe-xyz" {
		t.Errorf("unexpected pod: %q", alerts[0].PodName)
	}
}

func TestTetragonBackend_KprobeDetected(t *testing.T) {
	events := []TetragonEvent{
		&mockTetragonEvent{
			time: time.Now(),
			processKprobe: TetragonKprobe{
				FunctionName: "__x64_sys_unshare",
				PodName:      "detection-probe-xyz",
				Namespace:    "sidereal-system",
				Labels: map[string]string{
					"sidereal.cloud/probe-id": "probe-abc",
				},
			},
		},
	}

	backend := NewTetragonBackendWithStream(newMockTetragonStreamFn(events))
	alerts, err := backend.QueryAlerts(context.Background(), "probe-abc", 60*time.Second)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].RuleName != "kprobe:__x64_sys_unshare" {
		t.Errorf("unexpected rule: %q", alerts[0].RuleName)
	}
}

func TestTetragonBackend_NoMatch(t *testing.T) {
	events := []TetragonEvent{
		&mockTetragonEvent{
			time: time.Now(),
			processExec: TetragonProcess{
				Binary:    "/usr/bin/ls",
				PodName:   "unrelated-pod",
				Namespace: "default",
				Labels: map[string]string{
					"app": "web",
				},
			},
		},
	}

	backend := NewTetragonBackendWithStream(newMockTetragonStreamFn(events))
	alerts, err := backend.QueryAlerts(context.Background(), "probe-abc", 60*time.Second)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts, got %d", len(alerts))
	}
}

func TestTetragonBackend_ExpiredEvent(t *testing.T) {
	events := []TetragonEvent{
		&mockTetragonEvent{
			time: time.Now().Add(-5 * time.Minute),
			processExec: TetragonProcess{
				Binary:  "/bin/sh",
				PodName: "detection-probe-xyz",
				Labels: map[string]string{
					"sidereal.cloud/probe-id": "probe-abc",
				},
			},
		},
	}

	backend := NewTetragonBackendWithStream(newMockTetragonStreamFn(events))
	alerts, err := backend.QueryAlerts(context.Background(), "probe-abc", 60*time.Second)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts (expired), got %d", len(alerts))
	}
}

func TestTetragonBackend_StreamError(t *testing.T) {
	streamFn := func(_ context.Context, _ *grpc.ClientConn, _ time.Time) (TetragonEventStream, error) {
		return nil, fmt.Errorf("connection refused")
	}

	backend := NewTetragonBackendWithStream(streamFn)
	_, err := backend.QueryAlerts(context.Background(), "probe-abc", 60*time.Second)

	if err == nil {
		t.Error("expected error for stream creation failure")
	}
}

func TestTetragonBackend_NoStreamFn(t *testing.T) {
	backend := &TetragonBackend{}
	_, err := backend.QueryAlerts(context.Background(), "probe-abc", 60*time.Second)

	if err == nil {
		t.Error("expected error when streamFn is nil")
	}
}

func TestTetragonBackend_Close(t *testing.T) {
	backend := &TetragonBackend{}
	if err := backend.Close(); err != nil {
		t.Errorf("Close on nil conn should not error: %v", err)
	}
}

func TestLabelsMatchProbeID(t *testing.T) {
	tests := []struct {
		name     string
		labels   map[string]string
		probeID  string
		expected bool
	}{
		{"exact match", map[string]string{"sidereal.cloud/probe-id": "p1"}, "p1", true},
		{"substring match", map[string]string{"app": "contains-p1-here"}, "p1", true},
		{"no match", map[string]string{"app": "web"}, "p1", false},
		{"nil labels", nil, "p1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := labelsMatchProbeID(tt.labels, tt.probeID)
			if got != tt.expected {
				t.Errorf("labelsMatchProbeID() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseTetragonJSON_ProcessExec(t *testing.T) {
	event := map[string]interface{}{
		"process_exec": map[string]interface{}{
			"process": map[string]interface{}{
				"binary":    "/bin/sh",
				"arguments": "-c id",
				"pod": map[string]interface{}{
					"name":      "probe-pod",
					"namespace": "sidereal-system",
					"labels": map[string]string{
						"sidereal.cloud/probe-id": "p1",
					},
				},
			},
		},
		"time": "2026-01-15T10:30:00Z",
	}
	data, _ := json.Marshal(event)

	alert, err := ParseTetragonJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alert.RuleName != "process_exec:/bin/sh" {
		t.Errorf("unexpected rule: %q", alert.RuleName)
	}
	if alert.PodName != "probe-pod" {
		t.Errorf("unexpected pod: %q", alert.PodName)
	}
}

func TestParseTetragonJSON_Kprobe(t *testing.T) {
	event := map[string]interface{}{
		"process_kprobe": map[string]interface{}{
			"function_name": "__x64_sys_unshare",
			"process": map[string]interface{}{
				"pod": map[string]interface{}{
					"name":      "probe-pod",
					"namespace": "sidereal-system",
					"labels":    map[string]string{},
				},
			},
		},
		"time": "2026-01-15T10:30:00Z",
	}
	data, _ := json.Marshal(event)

	alert, err := ParseTetragonJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alert.RuleName != "kprobe:__x64_sys_unshare" {
		t.Errorf("unexpected rule: %q", alert.RuleName)
	}
}

func TestParseTetragonJSON_Invalid(t *testing.T) {
	_, err := ParseTetragonJSON([]byte("not json{"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseTetragonJSON_UnknownType(t *testing.T) {
	event := map[string]interface{}{
		"some_other_event": "data",
		"time":             "2026-01-15T10:30:00Z",
	}
	data, _ := json.Marshal(event)

	_, err := ParseTetragonJSON(data)
	if err == nil {
		t.Error("expected error for unrecognized event type")
	}
}
