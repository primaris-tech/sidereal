package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TetragonConfig holds configuration for the Tetragon gRPC backend.
type TetragonConfig struct {
	// Endpoint is the Tetragon gRPC address (e.g., "tetragon.kube-system:54321").
	Endpoint string
}

// TetragonEventStream abstracts the Tetragon gRPC event stream for testing.
type TetragonEventStream interface {
	Recv() (TetragonEvent, error)
}

// TetragonEvent abstracts a single Tetragon event.
type TetragonEvent interface {
	GetProcessExec() TetragonProcess
	GetProcessKprobe() TetragonKprobe
	GetTime() time.Time
}

// TetragonProcess represents a process exec event from Tetragon.
type TetragonProcess struct {
	Binary    string
	Arguments string
	PodName   string
	Namespace string
	Labels    map[string]string
}

// TetragonKprobe represents a kprobe event from Tetragon.
type TetragonKprobe struct {
	FunctionName string
	PodName      string
	Namespace    string
	Labels       map[string]string
}

// TetragonBackend implements Backend by querying Tetragon's gRPC event
// stream (tetragon.FineGuidanceSensors/GetEvents) for events matching
// the probe's pod label.
//
// The Tetragon gRPC API schema:
//
//	service FineGuidanceSensors {
//	    rpc GetEvents(GetEventsRequest) returns (stream GetEventsResponse);
//	}
//
// Events include ProcessExec, ProcessKprobe, ProcessTracepoint, etc.
// We filter by pod labels containing sidereal.cloud/probe-id.
//
// Until the Tetragon protobuf definitions are vendored, the production
// gRPC path is not operational. The streamFn injection point allows full
// testing of the event matching logic.
type TetragonBackend struct {
	config TetragonConfig
	conn   *grpc.ClientConn

	// streamFn creates a Tetragon event stream. In production this will use
	// the generated Tetragon gRPC client. For testing, inject a mock stream.
	streamFn func(ctx context.Context, conn *grpc.ClientConn, since time.Time) (TetragonEventStream, error)
}

// NewTetragonBackend creates a new Tetragon backend and establishes a gRPC connection.
func NewTetragonBackend(ctx context.Context, config TetragonConfig) (*TetragonBackend, error) {
	conn, err := grpc.NewClient(
		config.Endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("tetragon: failed to connect to %s: %w", config.Endpoint, err)
	}
	return &TetragonBackend{
		config: config,
		conn:   conn,
	}, nil
}

// NewTetragonBackendWithStream creates a Tetragon backend with an injected
// stream function, used for testing without a real Tetragon gRPC server.
func NewTetragonBackendWithStream(streamFn func(ctx context.Context, conn *grpc.ClientConn, since time.Time) (TetragonEventStream, error)) *TetragonBackend {
	return &TetragonBackend{
		streamFn: streamFn,
	}
}

// QueryAlerts queries Tetragon for events matching the given probeID within
// the specified time window.
func (b *TetragonBackend) QueryAlerts(ctx context.Context, probeID string, window time.Duration) ([]Alert, error) {
	if b.streamFn == nil {
		return nil, fmt.Errorf("tetragon: gRPC stream not configured (vendor Tetragon protobufs to enable production path)")
	}

	since := time.Now().Add(-window)

	stream, err := b.streamFn(ctx, b.conn, since)
	if err != nil {
		return nil, fmt.Errorf("tetragon: failed to create event stream: %w", err)
	}

	var alerts []Alert
	for {
		event, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return alerts, fmt.Errorf("tetragon: stream recv error: %w", err)
		}

		alert, match := matchTetragonEvent(event, probeID, since)
		if match {
			alerts = append(alerts, alert)
		}
	}

	return alerts, nil
}

// matchTetragonEvent checks if a Tetragon event matches our probe.
func matchTetragonEvent(event TetragonEvent, probeID string, since time.Time) (Alert, bool) {
	eventTime := event.GetTime()
	if eventTime.Before(since) {
		return Alert{}, false
	}

	// Check process exec events.
	proc := event.GetProcessExec()
	if proc.PodName != "" {
		if labelsMatchProbeID(proc.Labels, probeID) {
			return Alert{
				RuleName:  fmt.Sprintf("process_exec:%s", proc.Binary),
				Timestamp: eventTime,
				PodName:   proc.PodName,
				Namespace: proc.Namespace,
				Labels:    proc.Labels,
				Priority:  "Warning",
				Output:    fmt.Sprintf("exec %s %s", proc.Binary, proc.Arguments),
			}, true
		}
	}

	// Check kprobe events.
	kprobe := event.GetProcessKprobe()
	if kprobe.FunctionName != "" {
		if labelsMatchProbeID(kprobe.Labels, probeID) {
			return Alert{
				RuleName:  fmt.Sprintf("kprobe:%s", kprobe.FunctionName),
				Timestamp: eventTime,
				PodName:   kprobe.PodName,
				Namespace: kprobe.Namespace,
				Labels:    kprobe.Labels,
				Priority:  "Warning",
				Output:    fmt.Sprintf("kprobe %s", kprobe.FunctionName),
			}, true
		}
	}

	return Alert{}, false
}

// labelsMatchProbeID checks if the pod labels contain the probe ID.
func labelsMatchProbeID(labels map[string]string, probeID string) bool {
	if v, ok := labels["sidereal.cloud/probe-id"]; ok {
		return v == probeID
	}
	// Fallback: check if any label value contains the probe ID.
	for _, v := range labels {
		if strings.Contains(v, probeID) {
			return true
		}
	}
	return false
}

// Close releases the gRPC connection.
func (b *TetragonBackend) Close() error {
	if b.conn != nil {
		return b.conn.Close()
	}
	return nil
}

// ParseTetragonJSON parses a JSON-formatted Tetragon event (used when
// Tetragon is configured with JSON export instead of gRPC).
func ParseTetragonJSON(data []byte) (Alert, error) {
	var event struct {
		ProcessExec *struct {
			Process struct {
				Binary    string            `json:"binary"`
				Arguments string            `json:"arguments"`
				Pod       struct {
					Name      string            `json:"name"`
					Namespace string            `json:"namespace"`
					Labels    map[string]string `json:"labels"`
				} `json:"pod"`
			} `json:"process"`
		} `json:"process_exec"`
		ProcessKprobe *struct {
			FunctionName string `json:"function_name"`
			Process      struct {
				Pod struct {
					Name      string            `json:"name"`
					Namespace string            `json:"namespace"`
					Labels    map[string]string `json:"labels"`
				} `json:"pod"`
			} `json:"process"`
		} `json:"process_kprobe"`
		Time string `json:"time"`
	}

	if err := json.Unmarshal(data, &event); err != nil {
		return Alert{}, fmt.Errorf("tetragon: failed to parse JSON event: %w", err)
	}

	ts, _ := time.Parse(time.RFC3339Nano, event.Time)

	if event.ProcessExec != nil {
		proc := event.ProcessExec.Process
		return Alert{
			RuleName:  fmt.Sprintf("process_exec:%s", proc.Binary),
			Timestamp: ts,
			PodName:   proc.Pod.Name,
			Namespace: proc.Pod.Namespace,
			Labels:    proc.Pod.Labels,
			Output:    fmt.Sprintf("exec %s %s", proc.Binary, proc.Arguments),
		}, nil
	}

	if event.ProcessKprobe != nil {
		kp := event.ProcessKprobe
		return Alert{
			RuleName:  fmt.Sprintf("kprobe:%s", kp.FunctionName),
			Timestamp: ts,
			PodName:   kp.Process.Pod.Name,
			Namespace: kp.Process.Pod.Namespace,
			Labels:    kp.Process.Pod.Labels,
			Output:    fmt.Sprintf("kprobe %s", kp.FunctionName),
		}, nil
	}

	return Alert{}, fmt.Errorf("tetragon: no recognized event type in JSON")
}
