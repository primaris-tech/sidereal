// Package networkpolicy defines the backend interface and verification modes
// for NetworkPolicy probe validation. Three verification modes are supported:
//
//   - cni-verdict: queries CNI observability (Hubble or Calico) for authoritative
//     flow verdicts (Dropped/Forwarded)
//   - tcp-inference: built-in TCP connection attempt that infers policy enforcement
//     from the connection result (timeout/reset/established)
//   - responder: deploys an ephemeral responder pod and sends traffic to verify
//     NetworkPolicy enforcement end-to-end
package networkpolicy

import (
	"context"
	"time"
)

// Verdict represents the result of a NetworkPolicy flow verification.
type Verdict string

const (
	// VerdictDropped indicates the CNI authoritatively reported the flow was dropped.
	VerdictDropped Verdict = "Dropped"

	// VerdictForwarded indicates the CNI authoritatively reported the flow was forwarded.
	VerdictForwarded Verdict = "Forwarded"

	// VerdictInferredDropped indicates a TCP connection attempt timed out or was
	// refused, inferring that a NetworkPolicy dropped the traffic.
	VerdictInferredDropped Verdict = "InferredDropped"

	// VerdictInferredForwarded indicates a TCP connection was established,
	// inferring that no NetworkPolicy blocked the traffic.
	VerdictInferredForwarded Verdict = "InferredForwarded"

	// VerdictIndeterminate indicates the verification could not determine whether
	// the flow was dropped or forwarded (e.g., TCP RST which could indicate either
	// a policy reset or a closed port).
	VerdictIndeterminate Verdict = "Indeterminate"
)

// IsEffective returns true if the verdict indicates NetworkPolicy enforcement
// is working (traffic was dropped as expected).
func (v Verdict) IsEffective() bool {
	return v == VerdictDropped || v == VerdictInferredDropped
}

// VerificationMode identifies how the NetworkPolicy probe verifies enforcement.
type VerificationMode string

const (
	// ModeCNIVerdict queries the CNI observability layer (Hubble or Calico).
	ModeCNIVerdict VerificationMode = "cni-verdict"

	// ModeTCPInference uses built-in TCP connection inference (works with any CNI).
	ModeTCPInference VerificationMode = "tcp-inference"

	// ModeResponder deploys an ephemeral responder pod for end-to-end verification.
	ModeResponder VerificationMode = "responder"
)

// Backend is the interface for querying NetworkPolicy flow verdicts.
// Implementations include Hubble (gRPC), Calico (REST), and the built-in
// tcp-inference and responder modes.
type Backend interface {
	// QueryFlowVerdict checks whether traffic from a probe execution was
	// dropped or forwarded. The probeID is used to correlate the flow with
	// the specific probe execution. The window defines how far back to search.
	QueryFlowVerdict(ctx context.Context, probeID string, window time.Duration) (Verdict, error)
}
