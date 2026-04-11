package networkpolicy

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// HubbleConfig holds configuration for the Hubble gRPC backend.
type HubbleConfig struct {
	// Endpoint is the Hubble Relay gRPC address (e.g., "hubble-relay.kube-system:4245").
	Endpoint string
}

// HubbleBackend implements Backend by querying Hubble's observer.GetFlows()
// gRPC API, filtered by the sidereal.cloud/probe-id pod label.
type HubbleBackend struct {
	config HubbleConfig
	conn   *grpc.ClientConn
}

// NewHubbleBackend creates a new Hubble backend and establishes a gRPC connection.
func NewHubbleBackend(ctx context.Context, config HubbleConfig) (*HubbleBackend, error) {
	conn, err := grpc.NewClient(
		config.Endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("hubble: failed to connect to %s: %w", config.Endpoint, err)
	}
	return &HubbleBackend{
		config: config,
		conn:   conn,
	}, nil
}

// QueryFlowVerdict queries Hubble for flow records matching the given probeID
// within the specified time window.
//
// The query filters flows by the pod label sidereal.cloud/probe-id=<probeID>
// and maps the Hubble verdict to our Verdict type:
//   - DROPPED -> VerdictDropped
//   - FORWARDED -> VerdictForwarded
//   - no matching flows -> VerdictIndeterminate
func (b *HubbleBackend) QueryFlowVerdict(ctx context.Context, probeID string, window time.Duration) (Verdict, error) {
	// Hubble observer.GetFlows() integration requires the Hubble observer
	// protobuf definitions. The actual gRPC call will be:
	//
	//   client := observer.NewObserverClient(b.conn)
	//   req := &observer.GetFlowsRequest{
	//       Since: timestamppb.New(time.Now().Add(-window)),
	//       Whitelist: []*flow.FlowFilter{{
	//           SourcePod: []string{probeID},
	//       }},
	//   }
	//   stream, err := client.GetFlows(ctx, req)
	//
	// For now, return an error indicating the Hubble protobuf dependency
	// needs to be vendored before this backend is operational.
	return "", fmt.Errorf("hubble: gRPC observer query not yet wired (requires hubble protobuf vendor); probeID=%s window=%s", probeID, window)
}

// Close releases the gRPC connection.
func (b *HubbleBackend) Close() error {
	if b.conn != nil {
		return b.conn.Close()
	}
	return nil
}
