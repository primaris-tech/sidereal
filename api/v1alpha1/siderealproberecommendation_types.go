package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RecommendationConfidence indicates how fully the probe was derivable from the source resource.
// +kubebuilder:validation:Enum=high;medium;low
type RecommendationConfidence string

const (
	ConfidenceHigh   RecommendationConfidence = "high"
	ConfidenceMedium RecommendationConfidence = "medium"
	ConfidenceLow    RecommendationConfidence = "low"
)

// RecommendationState tracks the lifecycle of a probe recommendation.
// +kubebuilder:validation:Enum=pending;promoted;dismissed;superseded
type RecommendationState string

const (
	RecommendationPending    RecommendationState = "pending"
	RecommendationPromoted   RecommendationState = "promoted"
	RecommendationDismissed  RecommendationState = "dismissed"
	RecommendationSuperseded RecommendationState = "superseded"
)

// SiderealProbeRecommendationSpec defines a discovery-generated probe suggestion.
type SiderealProbeRecommendationSpec struct {
	// SourceResource references the cluster resource that prompted this recommendation.
	// +kubebuilder:validation:Required
	SourceResource corev1.ObjectReference `json:"sourceResource"`

	// SourceResourceHash is a hash of the source resource for change detection.
	// +kubebuilder:validation:Required
	SourceResourceHash string `json:"sourceResourceHash"`

	// Confidence indicates how fully the probe was derivable from the source.
	// +kubebuilder:validation:Required
	Confidence RecommendationConfidence `json:"confidence"`

	// ProbeTemplate is the complete SiderealProbe spec to create if promoted.
	// Always has executionMode: dryRun.
	// +kubebuilder:validation:Required
	ProbeTemplate SiderealProbeSpec `json:"probeTemplate"`

	// Rationale explains why this probe was generated.
	// +kubebuilder:validation:Required
	Rationale string `json:"rationale"`

	// ControlMappings contains suggested multi-framework control mappings.
	// +optional
	ControlMappings map[string][]string `json:"controlMappings,omitempty"`
}

// SiderealProbeRecommendationStatus defines the observed state of the recommendation.
type SiderealProbeRecommendationStatus struct {
	// State tracks the lifecycle: pending, promoted, dismissed, or superseded.
	// +kubebuilder:default=pending
	State RecommendationState `json:"state"`

	// PromotedTo is the name of the SiderealProbe created when this recommendation was promoted.
	// +optional
	PromotedTo string `json:"promotedTo,omitempty"`

	// DismissedBy is the Kubernetes username of the principal who dismissed this recommendation.
	// +optional
	DismissedBy string `json:"dismissedBy,omitempty"`

	// DismissedReason is the reason for dismissal.
	// +optional
	DismissedReason string `json:"dismissedReason,omitempty"`

	// SupersededBy is the name of the newer recommendation that replaced this one.
	// +optional
	SupersededBy string `json:"supersededBy,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=sprec
// +kubebuilder:printcolumn:name="Source Kind",type=string,JSONPath=`.spec.sourceResource.kind`
// +kubebuilder:printcolumn:name="Source Name",type=string,JSONPath=`.spec.sourceResource.name`
// +kubebuilder:printcolumn:name="Confidence",type=string,JSONPath=`.spec.confidence`
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.state`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SiderealProbeRecommendation is a discovery-generated probe suggestion.
// The controller scans the cluster for existing security controls and generates
// recommendations that ISSOs can review and promote to active probes.
type SiderealProbeRecommendation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SiderealProbeRecommendationSpec   `json:"spec,omitempty"`
	Status SiderealProbeRecommendationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SiderealProbeRecommendationList contains a list of SiderealProbeRecommendation.
type SiderealProbeRecommendationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SiderealProbeRecommendation `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SiderealProbeRecommendation{}, &SiderealProbeRecommendationList{})
}
