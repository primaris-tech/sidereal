package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IncidentSeverity defines the severity of an incident.
// +kubebuilder:validation:Enum=Critical;High;Medium;Low
type IncidentSeverity string

const (
	SeverityCritical IncidentSeverity = "Critical"
	SeverityHigh     IncidentSeverity = "High"
	SeverityMedium   IncidentSeverity = "Medium"
	SeverityLow      IncidentSeverity = "Low"
)

// RemediationStatus tracks the remediation lifecycle of an incident.
// +kubebuilder:validation:Enum=Open;InProgress;Remediated;Accepted
type RemediationStatus string

const (
	RemediationOpen       RemediationStatus = "Open"
	RemediationInProgress RemediationStatus = "InProgress"
	RemediationRemediated RemediationStatus = "Remediated"
	RemediationAccepted   RemediationStatus = "Accepted"
)

// WebhookDeliveryStatus tracks IR webhook delivery state.
// +kubebuilder:validation:Enum=Pending;Delivered;Failed
type WebhookDeliveryStatus string

const (
	WebhookPending   WebhookDeliveryStatus = "Pending"
	WebhookDelivered WebhookDeliveryStatus = "Delivered"
	WebhookFailed    WebhookDeliveryStatus = "Failed"
)

// SiderealIncidentSpec defines the content of a control failure incident.
type SiderealIncidentSpec struct {
	// ProbeResultRef is the name of the SiderealProbeResult that triggered this incident.
	// +kubebuilder:validation:Required
	ProbeResultRef string `json:"probeResultRef"`

	// ControlID is the primary NIST 800-53 control ID.
	// +optional
	ControlID string `json:"controlId,omitempty"`

	// MitreID is the MITRE ATT&CK technique ID.
	// +optional
	MitreID string `json:"mitreId,omitempty"`

	// Description is a human-readable description of the incident.
	// +kubebuilder:validation:Required
	Description string `json:"description"`

	// Severity of the incident.
	// +kubebuilder:validation:Required
	Severity IncidentSeverity `json:"severity"`

	// TargetNamespace is the namespace where the control failure was detected.
	// +kubebuilder:validation:Required
	TargetNamespace string `json:"targetNamespace"`

	// ProbeType is the type of probe that detected the failure.
	// +kubebuilder:validation:Required
	ProbeType ProbeType `json:"probeType"`

	// ControlEffectiveness is the effectiveness at the time of incident creation.
	// +kubebuilder:validation:Required
	ControlEffectiveness ControlEffectiveness `json:"controlEffectiveness"`

	// RemediationStatus tracks the remediation lifecycle.
	// +kubebuilder:default=Open
	RemediationStatus RemediationStatus `json:"remediationStatus"`

	// WebhookDeliveryStatus tracks IR webhook delivery.
	// +kubebuilder:default=Pending
	WebhookDeliveryStatus WebhookDeliveryStatus `json:"webhookDeliveryStatus"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=si
// +kubebuilder:printcolumn:name="Severity",type=string,JSONPath=`.spec.severity`
// +kubebuilder:printcolumn:name="Probe Type",type=string,JSONPath=`.spec.probeType`
// +kubebuilder:printcolumn:name="Namespace",type=string,JSONPath=`.spec.targetNamespace`
// +kubebuilder:printcolumn:name="Remediation",type=string,JSONPath=`.spec.remediationStatus`
// +kubebuilder:printcolumn:name="Webhook",type=string,JSONPath=`.spec.webhookDeliveryStatus`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SiderealIncident is a control failure record created when a probe detects
// an ineffective or compromised control in enforce execution mode.
type SiderealIncident struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec SiderealIncidentSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// SiderealIncidentList contains a list of SiderealIncident.
type SiderealIncidentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SiderealIncident `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SiderealIncident{}, &SiderealIncidentList{})
}
