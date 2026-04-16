package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ProbeOutcome defines the raw outcome of a probe execution.
// +kubebuilder:validation:Enum=Pass;Fail;Detected;Undetected;Blocked;Rejected;Accepted;NotApplicable;BackendUnreachable;NotEnforced;Indeterminate;TamperedResult
type ProbeOutcome string

const (
	OutcomePass               ProbeOutcome = "Pass"
	OutcomeFail               ProbeOutcome = "Fail"
	OutcomeDetected           ProbeOutcome = "Detected"
	OutcomeUndetected         ProbeOutcome = "Undetected"
	OutcomeBlocked            ProbeOutcome = "Blocked"
	OutcomeRejected           ProbeOutcome = "Rejected"
	OutcomeAccepted           ProbeOutcome = "Accepted"
	OutcomeNotApplicable      ProbeOutcome = "NotApplicable"
	OutcomeBackendUnreachable ProbeOutcome = "BackendUnreachable"
	OutcomeNotEnforced        ProbeOutcome = "NotEnforced"
	OutcomeIndeterminate      ProbeOutcome = "Indeterminate"
	OutcomeTamperedResult     ProbeOutcome = "TamperedResult"
)

// ControlEffectiveness is the normalized control effectiveness derived from the raw outcome.
// +kubebuilder:validation:Enum=Effective;Ineffective;Degraded;Compromised
type ControlEffectiveness string

const (
	EffectivenessEffective   ControlEffectiveness = "Effective"
	EffectivenessIneffective ControlEffectiveness = "Ineffective"
	EffectivenessDegraded    ControlEffectiveness = "Degraded"
	EffectivenessCompromised ControlEffectiveness = "Compromised"
)

// DeriveControlEffectiveness maps a raw ProbeOutcome to its ControlEffectiveness.
// This mapping is deterministic and not configurable.
func DeriveControlEffectiveness(outcome ProbeOutcome) ControlEffectiveness {
	switch outcome {
	case OutcomePass, OutcomeDetected, OutcomeBlocked, OutcomeRejected:
		return EffectivenessEffective
	case OutcomeFail, OutcomeUndetected, OutcomeAccepted, OutcomeNotEnforced:
		return EffectivenessIneffective
	case OutcomeBackendUnreachable, OutcomeIndeterminate, OutcomeNotApplicable:
		return EffectivenessDegraded
	case OutcomeTamperedResult:
		return EffectivenessCompromised
	default:
		return EffectivenessDegraded
	}
}

// IntegrityStatus indicates whether the probe result passed HMAC verification.
// +kubebuilder:validation:Enum=Verified;TamperedResult
type IntegrityStatus string

const (
	IntegrityVerified       IntegrityStatus = "Verified"
	IntegrityTamperedResult IntegrityStatus = "TamperedResult"
)

// ExportStatus tracks the SIEM export state of a probe result.
// +kubebuilder:validation:Enum=Pending;Exported;Failed
type ExportStatus string

const (
	ExportStatusPending  ExportStatus = "Pending"
	ExportStatusExported ExportStatus = "Exported"
	ExportStatusFailed   ExportStatus = "Failed"
)

// ProbeResultProbeRef identifies the probe that produced this result.
type ProbeResultProbeRef struct {
	// ID is the unique execution identifier (UUID).
	ID string `json:"id"`

	// Profile is the probe profile.
	Profile ProbeProfile `json:"profile"`

	// TargetNamespace is the namespace that was probed.
	TargetNamespace string `json:"targetNamespace"`

	// AOAuthorizationRef is the authorization used (detection probes only).
	// +optional
	AOAuthorizationRef string `json:"aoAuthorizationRef,omitempty"`
}

// ProbeResultResult contains the probe's findings.
type ProbeResultResult struct {
	// Outcome is the raw probe outcome.
	Outcome ProbeOutcome `json:"outcome"`

	// ControlEffectiveness is the normalized effectiveness derived from the outcome.
	ControlEffectiveness ControlEffectiveness `json:"controlEffectiveness"`

	// ControlMappings maps framework IDs to control IDs for this result.
	// +optional
	ControlMappings map[string][]string `json:"controlMappings,omitempty"`

	// CrosswalkVersion is the version of the crosswalk data used to populate ControlMappings.
	// +optional
	CrosswalkVersion string `json:"crosswalkVersion,omitempty"`

	// NistControls is retained for backward compatibility. Populated identically to ControlMappings["nist-800-53"].
	// +optional
	NistControls []string `json:"nistControls,omitempty"`

	// MitreAttackID is the MITRE ATT&CK technique ID.
	// +optional
	MitreAttackID string `json:"mitreAttackId,omitempty"`

	// IntegrityStatus indicates HMAC verification result.
	IntegrityStatus IntegrityStatus `json:"integrityStatus"`

	// Detail is a human-readable description of the result.
	// +optional
	Detail string `json:"detail,omitempty"`

	// VerificationMode indicates the NetworkPolicy verification mode used (netpol probes only).
	// +optional
	VerificationMode string `json:"verificationMode,omitempty"`
}

// ProbeResultExecution contains execution metadata.
type ProbeResultExecution struct {
	// Timestamp is the RFC 3339 UTC nanosecond timestamp of execution start.
	Timestamp string `json:"timestamp"`

	// DurationMs is the execution duration in milliseconds.
	DurationMs int64 `json:"durationMs"`

	// JobName is the Kubernetes Job that ran this probe.
	JobName string `json:"jobName"`
}

// ProbeResultAudit contains audit export tracking.
type ProbeResultAudit struct {
	// ExportStatus tracks SIEM export state.
	// +kubebuilder:default=Pending
	ExportStatus ExportStatus `json:"exportStatus"`

	// ExportedAt is the RFC 3339 timestamp of successful export.
	// +optional
	ExportedAt string `json:"exportedAt,omitempty"`
}

// SiderealProbeResultSpec defines the content of a probe result audit record.
type SiderealProbeResultSpec struct {
	// Probe identifies the probe that produced this result.
	Probe ProbeResultProbeRef `json:"probe"`

	// Result contains the probe's findings.
	Result ProbeResultResult `json:"result"`

	// Execution contains execution metadata.
	Execution ProbeResultExecution `json:"execution"`

	// Audit contains export tracking.
	Audit ProbeResultAudit `json:"audit"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=spr
// +kubebuilder:printcolumn:name="Profile",type=string,JSONPath=`.spec.probe.profile`
// +kubebuilder:printcolumn:name="Namespace",type=string,JSONPath=`.spec.probe.targetNamespace`
// +kubebuilder:printcolumn:name="Outcome",type=string,JSONPath=`.spec.result.outcome`
// +kubebuilder:printcolumn:name="Effectiveness",type=string,JSONPath=`.spec.result.controlEffectiveness`
// +kubebuilder:printcolumn:name="Integrity",type=string,JSONPath=`.spec.result.integrityStatus`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SiderealProbeResult is an append-only audit record for a probe execution.
// Results are HMAC-verified and immutable after creation.
type SiderealProbeResult struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec SiderealProbeResultSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// SiderealProbeResultList contains a list of SiderealProbeResult.
type SiderealProbeResultList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SiderealProbeResult `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SiderealProbeResult{}, &SiderealProbeResultList{})
}
