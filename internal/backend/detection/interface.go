// Package detection defines the backend interface for querying runtime
// security detection systems (Falco, Tetragon) to verify whether a
// detection probe's synthetic syscall pattern was observed and alerted on.
//
// The detection flow is split across two identities:
//  1. The detection probe (Rust binary) fires a synthetic syscall pattern and exits.
//  2. The controller independently queries the detection backend to verify the
//     alert was raised. This separation is a critical security property.
package detection

import (
	"context"
	"time"
)

// Alert represents a single detection event returned by the backend.
type Alert struct {
	// RuleName is the detection rule that fired (e.g., Falco rule name).
	RuleName string

	// Timestamp is when the alert was generated.
	Timestamp time.Time

	// PodName is the pod that triggered the alert.
	PodName string

	// Namespace is the namespace of the pod.
	Namespace string

	// Labels are the pod labels at alert time.
	Labels map[string]string

	// TechniqueID is the MITRE ATT&CK technique ID, if the backend tags it.
	TechniqueID string

	// Priority is the alert severity from the backend (e.g., "Warning", "Critical").
	Priority string

	// Output is the raw alert message from the backend.
	Output string
}

// Backend is the interface for querying detection backends.
// Implementations include Falco (gRPC) and Tetragon (gRPC).
type Backend interface {
	// QueryAlerts searches for detection alerts matching the given probeID
	// within the specified time window. The probeID corresponds to the
	// sidereal.cloud/probe-id label on the detection probe pod.
	QueryAlerts(ctx context.Context, probeID string, window time.Duration) ([]Alert, error)

	// Close releases any resources held by the backend.
	Close() error
}

// Outcome represents the detection verification result derived from
// backend query results.
type Outcome string

const (
	// OutcomeDetected means the backend reported alerts matching the probe,
	// indicating the detection layer is working.
	OutcomeDetected Outcome = "Detected"

	// OutcomeUndetected means the backend reported no alerts within the
	// verification window, indicating a detection gap.
	OutcomeUndetected Outcome = "Undetected"

	// OutcomeBackendUnreachable means the backend could not be queried.
	OutcomeBackendUnreachable Outcome = "BackendUnreachable"
)

// DeriveOutcome maps backend query results to a detection Outcome.
//
//   - alerts found with matching probeID -> Detected
//   - no alerts found within window      -> Undetected
//   - backend query error                -> BackendUnreachable
func DeriveOutcome(alerts []Alert, err error) Outcome {
	if err != nil {
		return OutcomeBackendUnreachable
	}
	if len(alerts) > 0 {
		return OutcomeDetected
	}
	return OutcomeUndetected
}
