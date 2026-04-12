package detection

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// FalcoConfig holds configuration for the Falco gRPC backend.
type FalcoConfig struct {
	// Endpoint is the Falco gRPC output address (e.g., "falco-grpc.falco:50051").
	Endpoint string
}

// FalcoOutputStream abstracts the Falco gRPC output stream for testing.
type FalcoOutputStream interface {
	Recv() (FalcoResponse, error)
}

// FalcoResponse abstracts a single Falco output response.
type FalcoResponse interface {
	GetTime() *timestamppb.Timestamp
	GetRule() string
	GetOutput() string
	GetPriority() int32
	GetOutputFields() map[string]string
}

// FalcoBackend implements Backend by querying Falco's gRPC output service
// (falco.output.service/get) for alerts matching the probe's pod label.
//
// The Falco gRPC output API schema:
//
//	service output {
//	    rpc get(request) returns (stream response);
//	}
//	message request { }
//	message response {
//	    google.protobuf.Timestamp time = 1;
//	    priority priority = 2;
//	    string source = 3;
//	    string rule = 4;
//	    string output = 5;
//	    map<string, string> output_fields = 6;
//	    string hostname = 7;
//	    repeated string tags = 8;
//	}
//
// Until the Falco protobuf definitions are vendored, the production gRPC
// path is not operational. The streamFn injection point allows full testing
// of the alert matching and filtering logic.
type FalcoBackend struct {
	config FalcoConfig
	conn   *grpc.ClientConn

	// streamFn creates a Falco output stream. In production this will use
	// the generated Falco gRPC client. For testing, inject a mock stream.
	streamFn func(ctx context.Context, conn *grpc.ClientConn, since time.Time) (FalcoOutputStream, error)
}

// falcoPriorityNames maps Falco priority integers to human-readable names.
var falcoPriorityNames = map[int32]string{
	0: "Emergency",
	1: "Alert",
	2: "Critical",
	3: "Error",
	4: "Warning",
	5: "Notice",
	6: "Informational",
	7: "Debug",
}

// NewFalcoBackend creates a new Falco backend and establishes a gRPC connection.
func NewFalcoBackend(ctx context.Context, config FalcoConfig) (*FalcoBackend, error) {
	conn, err := grpc.NewClient(
		config.Endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("falco: failed to connect to %s: %w", config.Endpoint, err)
	}
	return &FalcoBackend{
		config: config,
		conn:   conn,
	}, nil
}

// NewFalcoBackendWithStream creates a Falco backend with an injected stream
// function, used for testing without a real Falco gRPC server.
func NewFalcoBackendWithStream(streamFn func(ctx context.Context, conn *grpc.ClientConn, since time.Time) (FalcoOutputStream, error)) *FalcoBackend {
	return &FalcoBackend{
		streamFn: streamFn,
	}
}

// QueryAlerts queries Falco for alerts matching the given probeID within
// the specified time window.
func (b *FalcoBackend) QueryAlerts(ctx context.Context, probeID string, window time.Duration) ([]Alert, error) {
	if b.streamFn == nil {
		return nil, fmt.Errorf("falco: gRPC stream not configured (vendor Falco protobufs to enable production path)")
	}

	since := time.Now().Add(-window)

	stream, err := b.streamFn(ctx, b.conn, since)
	if err != nil {
		return nil, fmt.Errorf("falco: failed to create output stream: %w", err)
	}

	var alerts []Alert
	for {
		resp, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return alerts, fmt.Errorf("falco: stream recv error: %w", err)
		}

		alert, match := matchFalcoResponse(resp, probeID, since)
		if match {
			alerts = append(alerts, alert)
		}
	}

	return alerts, nil
}

// matchFalcoResponse checks if a Falco response matches our probe and
// falls within the time window.
func matchFalcoResponse(resp FalcoResponse, probeID string, since time.Time) (Alert, bool) {
	ts := resp.GetTime()
	if ts != nil && ts.AsTime().Before(since) {
		return Alert{}, false
	}

	fields := resp.GetOutputFields()
	if !containsProbeID(fields, resp.GetOutput(), probeID) {
		return Alert{}, false
	}

	alertTime := time.Now()
	if ts != nil {
		alertTime = ts.AsTime()
	}

	priority := ""
	if name, ok := falcoPriorityNames[resp.GetPriority()]; ok {
		priority = name
	}

	return Alert{
		RuleName:  resp.GetRule(),
		Timestamp: alertTime,
		PodName:   fields["k8s.pod.name"],
		Namespace: fields["k8s.ns.name"],
		Labels:    fields,
		Priority:  priority,
		Output:    resp.GetOutput(),
	}, true
}

// containsProbeID checks if the probe ID appears in output fields or raw output.
func containsProbeID(fields map[string]string, output, probeID string) bool {
	for _, v := range fields {
		if strings.Contains(v, probeID) {
			return true
		}
	}
	return strings.Contains(output, probeID)
}

// Close releases the gRPC connection.
func (b *FalcoBackend) Close() error {
	if b.conn != nil {
		return b.conn.Close()
	}
	return nil
}
