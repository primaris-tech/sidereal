package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SystemAlertReason defines why the alert was raised.
// +kubebuilder:validation:Enum=AdmissionPolicyMissing;SIEMExportDegraded;AuditWriteFailure;BaselineConfigurationDrift;TamperedResult;AOAuthorizationExpired;BackendUnreachable;UnexpectedNetworkFlow
type SystemAlertReason string

const (
	AlertReasonAdmissionPolicyMissing    SystemAlertReason = "AdmissionPolicyMissing"
	AlertReasonSIEMExportDegraded        SystemAlertReason = "SIEMExportDegraded"
	AlertReasonAuditWriteFailure         SystemAlertReason = "AuditWriteFailure"
	AlertReasonBaselineConfigurationDrift SystemAlertReason = "BaselineConfigurationDrift"
	AlertReasonTamperedResult            SystemAlertReason = "TamperedResult"
	AlertReasonAOAuthorizationExpired    SystemAlertReason = "AOAuthorizationExpired"
	AlertReasonBackendUnreachable        SystemAlertReason = "BackendUnreachable"
	AlertReasonUnexpectedNetworkFlow     SystemAlertReason = "UnexpectedNetworkFlow"
)

// SiderealSystemAlertSpec defines the content of a system degradation alert.
type SiderealSystemAlertSpec struct {
	// Reason categorizes the alert.
	// +kubebuilder:validation:Required
	Reason SystemAlertReason `json:"reason"`

	// Message is a human-readable description of the alert condition.
	// +kubebuilder:validation:Required
	Message string `json:"message"`

	// Acknowledged indicates whether an individual principal has acknowledged this alert.
	// +kubebuilder:default=false
	Acknowledged bool `json:"acknowledged"`

	// AcknowledgedBy is the Kubernetes username of the principal who acknowledged the alert.
	// Must be an individual user identity, not a shared ServiceAccount.
	// +optional
	AcknowledgedBy string `json:"acknowledgedBy,omitempty"`

	// AcknowledgedAt is the timestamp of acknowledgment.
	// +optional
	AcknowledgedAt *metav1.Time `json:"acknowledgedAt,omitempty"`

	// RemediationAction describes the action taken or planned to remediate the condition.
	// +optional
	RemediationAction string `json:"remediationAction,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=ssa
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.spec.reason`
// +kubebuilder:printcolumn:name="Acknowledged",type=boolean,JSONPath=`.spec.acknowledged`
// +kubebuilder:printcolumn:name="Acknowledged By",type=string,JSONPath=`.spec.acknowledgedBy`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SiderealSystemAlert indicates a degraded state in the Sidereal system.
// Unacknowledged alerts block probe scheduling until an individual principal
// acknowledges and provides a remediation action.
type SiderealSystemAlert struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec SiderealSystemAlertSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// SiderealSystemAlertList contains a list of SiderealSystemAlert.
type SiderealSystemAlertList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SiderealSystemAlert `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SiderealSystemAlert{}, &SiderealSystemAlertList{})
}
