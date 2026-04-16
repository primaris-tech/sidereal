package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// ProbeProfile defines the semantic validation profile for a probe.
// Built-in profiles are reserved by Sidereal. Custom profiles should use an
// organization-qualified identifier to avoid collisions.
// +kubebuilder:validation:MinLength=1
type ProbeProfile string

const (
	ProbeProfileRBAC      ProbeProfile = "rbac"
	ProbeProfileNetPol    ProbeProfile = "netpol"
	ProbeProfileAdmission ProbeProfile = "admission"
	ProbeProfileSecret    ProbeProfile = "secret"
	ProbeProfileDetection ProbeProfile = "detection"
)

// ProbeRunnerType defines how a probe is executed.
// +kubebuilder:validation:Enum=builtin;custom
type ProbeRunnerType string

const (
	ProbeRunnerBuiltin ProbeRunnerType = "builtin"
	ProbeRunnerCustom  ProbeRunnerType = "custom"
)

// ExecutionMode defines the operational mode for a probe.
// +kubebuilder:validation:Enum=dryRun;observe;enforce
type ExecutionMode string

const (
	// ExecutionModeDryRun validates configuration without executing probes.
	ExecutionModeDryRun ExecutionMode = "dryRun"
	// ExecutionModeObserve executes probes and records results but does not create incidents.
	ExecutionModeObserve ExecutionMode = "observe"
	// ExecutionModeEnforce executes probes with full incident creation and IR webhook delivery.
	ExecutionModeEnforce ExecutionMode = "enforce"
)

// SiderealProbeSpec defines the desired state of a SiderealProbe.
type SiderealProbeSpec struct {
	// Profile is the semantic validation profile this probe instantiates.
	// +kubebuilder:validation:Required
	Profile ProbeProfile `json:"profile"`

	// TargetNamespace is the explicit namespace to probe. Mutually exclusive with TargetNamespaceSelector.
	// +optional
	TargetNamespace string `json:"targetNamespace,omitempty"`

	// TargetNamespaceSelector selects namespaces by label. Mutually exclusive with TargetNamespace.
	// +optional
	TargetNamespaceSelector *metav1.LabelSelector `json:"targetNamespaceSelector,omitempty"`

	// ExecutionMode controls operational behavior: dryRun (default), observe, or enforce.
	// Transitioning to enforce requires the sidereal-live-executor role.
	// +kubebuilder:default=dryRun
	// +kubebuilder:validation:Required
	ExecutionMode ExecutionMode `json:"executionMode"`

	// IntervalSeconds is the time between probe executions.
	// +kubebuilder:validation:Minimum=300
	// +kubebuilder:validation:Maximum=86400
	// +kubebuilder:default=21600
	IntervalSeconds int32 `json:"intervalSeconds"`

	// VerificationWindowSeconds is the window for detection backend polling (detection probes only).
	// +kubebuilder:validation:Minimum=10
	// +kubebuilder:validation:Maximum=300
	// +kubebuilder:default=60
	// +optional
	VerificationWindowSeconds int32 `json:"verificationWindowSeconds,omitempty"`

	// ControlMappings declares the canonical control IDs this profile validates.
	// Sidereal treats nist-800-53 as the canonical key and derives other
	// framework mappings through SiderealFramework crosswalks.
	// +optional
	ControlMappings map[string][]string `json:"controlMappings,omitempty"`

	// MitreAttackID is the MITRE ATT&CK technique ID this probe validates against.
	// +optional
	MitreAttackID string `json:"mitreAttackId,omitempty"`

	// AOAuthorizationRef is the name of the SiderealAOAuthorization resource. Required for detection probes.
	// +optional
	AOAuthorizationRef string `json:"aoAuthorizationRef,omitempty"`

	// AdmissionProbe contains configuration specific to admission control probes.
	// +optional
	AdmissionProbe *AdmissionProbeConfig `json:"admissionProbe,omitempty"`

	// Runner configures how the selected profile is executed.
	// +optional
	Runner *ProbeRunnerSpec `json:"runner,omitempty"`
}

// AdmissionProbeConfig holds admission-specific probe configuration.
type AdmissionProbeConfig struct {
	// TargetPolicy is the name of the specific admission policy to test.
	// +optional
	TargetPolicy string `json:"targetPolicy,omitempty"`

	// KnownBadSpec is an operator-provided pod spec that should be rejected.
	// +optional
	KnownBadSpec *runtime.RawExtension `json:"knownBadSpec,omitempty"`
}

// ProbeRunnerSpec holds execution configuration for a probe profile.
type ProbeRunnerSpec struct {
	// Type selects the runner implementation. Built-in profiles default to
	// builtin if omitted.
	// +optional
	Type ProbeRunnerType `json:"type,omitempty"`

	// Custom holds configuration for operator-extensible custom runners.
	// Required when type=custom.
	// +optional
	Custom *CustomProbeConfig `json:"custom,omitempty"`
}

// CustomProbeConfig holds configuration for operator-extensible custom runners.
type CustomProbeConfig struct {
	// Image is the container image for the custom probe (must be digest-pinned and cosign-signed).
	// +kubebuilder:validation:Required
	Image string `json:"image"`

	// ServiceAccountName is the pre-registered ServiceAccount for this custom probe.
	// +kubebuilder:validation:Required
	ServiceAccountName string `json:"serviceAccountName"`

	// Config is opaque JSON configuration passed to the custom probe container.
	// +optional
	Config *runtime.RawExtension `json:"config,omitempty"`
}

// RunnerType returns the effective runner type for this probe spec.
func (s *SiderealProbeSpec) RunnerType() ProbeRunnerType {
	if s.Runner != nil && s.Runner.Type != "" {
		return s.Runner.Type
	}
	return ProbeRunnerBuiltin
}

// ProbeResultSummary is a compact summary of a recent probe result.
type ProbeResultSummary struct {
	// Timestamp is when the probe executed.
	Timestamp metav1.Time `json:"timestamp"`

	// Outcome is the raw probe outcome.
	Outcome string `json:"outcome"`

	// ControlEffectiveness is the derived effectiveness.
	ControlEffectiveness ControlEffectiveness `json:"controlEffectiveness"`

	// ResultName is the name of the SiderealProbeResult resource.
	ResultName string `json:"resultName"`
}

// SiderealProbeStatus defines the observed state of a SiderealProbe.
type SiderealProbeStatus struct {
	// LastExecutedAt is the timestamp of the most recent probe execution.
	// +optional
	LastExecutedAt *metav1.Time `json:"lastExecutedAt,omitempty"`

	// LastOutcome is the raw outcome of the most recent execution.
	// +optional
	LastOutcome string `json:"lastOutcome,omitempty"`

	// LastControlEffectiveness is the derived effectiveness of the most recent execution.
	// +optional
	LastControlEffectiveness ControlEffectiveness `json:"lastControlEffectiveness,omitempty"`

	// ConsecutiveFailures tracks consecutive non-Effective results.
	// +optional
	ConsecutiveFailures int32 `json:"consecutiveFailures,omitempty"`

	// RecentResults contains summaries of recent probe executions.
	// +optional
	RecentResults []ProbeResultSummary `json:"recentResults,omitempty"`

	// Conditions represent the latest available observations of the probe's state.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=sp
// +kubebuilder:printcolumn:name="Profile",type=string,JSONPath=`.spec.profile`
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.executionMode`
// +kubebuilder:printcolumn:name="Interval",type=integer,JSONPath=`.spec.intervalSeconds`
// +kubebuilder:printcolumn:name="Last Outcome",type=string,JSONPath=`.status.lastOutcome`
// +kubebuilder:printcolumn:name="Effectiveness",type=string,JSONPath=`.status.lastControlEffectiveness`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SiderealProbe is the Schema for the siderealprobes API.
// It defines a security control validation probe configuration.
type SiderealProbe struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SiderealProbeSpec   `json:"spec,omitempty"`
	Status SiderealProbeStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SiderealProbeList contains a list of SiderealProbe.
type SiderealProbeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SiderealProbe `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SiderealProbe{}, &SiderealProbeList{})
}
