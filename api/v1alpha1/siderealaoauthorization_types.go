package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SiderealAOAuthorizationSpec defines a time-bounded authorization for detection probes.
type SiderealAOAuthorizationSpec struct {
	// AOName is the name of the Authorizing Official (individual, not a role or team).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	AOName string `json:"aoName"`

	// AuthorizedTechniques is the list of MITRE ATT&CK technique IDs authorized for probing.
	// +kubebuilder:validation:MinItems=1
	AuthorizedTechniques []string `json:"authorizedTechniques"`

	// AuthorizedNamespaces is the list of namespaces where detection probes may execute.
	// No wildcards allowed.
	// +kubebuilder:validation:MinItems=1
	AuthorizedNamespaces []string `json:"authorizedNamespaces"`

	// ValidFrom is the start of the authorization window.
	// +kubebuilder:validation:Required
	ValidFrom metav1.Time `json:"validFrom"`

	// ExpiresAt is the end of the authorization window.
	// +kubebuilder:validation:Required
	ExpiresAt metav1.Time `json:"expiresAt"`

	// Justification is the stated reason for the authorization.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Justification string `json:"justification"`

	// CatalogVersion is the approved syscall catalog version reference.
	// +optional
	CatalogVersion string `json:"catalogVersion,omitempty"`
}

// SiderealAOAuthorizationStatus defines the observed state of the authorization.
type SiderealAOAuthorizationStatus struct {
	// Active is computed from the time bounds (validFrom <= now < expiresAt).
	Active bool `json:"active"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=sao
// +kubebuilder:printcolumn:name="AO",type=string,JSONPath=`.spec.aoName`
// +kubebuilder:printcolumn:name="Active",type=boolean,JSONPath=`.status.active`
// +kubebuilder:printcolumn:name="Expires",type=date,JSONPath=`.spec.expiresAt`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SiderealAOAuthorization is a time-bounded, technique-scoped, namespace-scoped
// authorization from an Authorizing Official for detection probe execution.
type SiderealAOAuthorization struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SiderealAOAuthorizationSpec   `json:"spec,omitempty"`
	Status SiderealAOAuthorizationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SiderealAOAuthorizationList contains a list of SiderealAOAuthorization.
type SiderealAOAuthorizationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SiderealAOAuthorization `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SiderealAOAuthorization{}, &SiderealAOAuthorizationList{})
}
