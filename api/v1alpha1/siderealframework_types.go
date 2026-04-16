package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// FrameworkMapping maps a (profile, NIST 800-53 control) pair to one or
// more framework-specific control IDs.
type FrameworkMapping struct {
	// Profile is the Sidereal probe profile this mapping applies to.
	// +kubebuilder:validation:Required
	Profile ProbeProfile `json:"profile"`

	// NISTControl is the NIST SP 800-53 Rev 5 control identifier (e.g., AC-3).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	NISTControl string `json:"nistControl"`

	// ControlIDs are the framework-specific control identifiers that correspond
	// to this NIST control for this probe type.
	// +kubebuilder:validation:MinItems=1
	ControlIDs []string `json:"controlIDs"`
}

// SiderealFrameworkSpec defines the desired state of a SiderealFramework.
type SiderealFrameworkSpec struct {
	// FrameworkID is the unique identifier for this compliance framework
	// (e.g., "cmmc", "hipaa", "nist-800-171"). Must match metadata.name.
	// Used as the key in crosswalk resolver output and in SiderealProbeResult
	// controlMappings.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	FrameworkID string `json:"frameworkID"`

	// FrameworkName is the human-readable name of the framework.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	FrameworkName string `json:"frameworkName"`

	// Version is the version of this crosswalk mapping (semver recommended).
	// Included in the crosswalkVersion field of SiderealProbeResult.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Version string `json:"version"`

	// Mappings is the list of (profile, nistControl) → controlIDs entries.
	// +kubebuilder:validation:MinItems=1
	Mappings []FrameworkMapping `json:"mappings"`
}

// SiderealFrameworkStatus defines the observed state of a SiderealFramework.
type SiderealFrameworkStatus struct {
	// LoadedAt is the timestamp when the framework was last successfully
	// loaded into the crosswalk resolver.
	// +optional
	LoadedAt *metav1.Time `json:"loadedAt,omitempty"`

	// MappingCount is the number of mapping entries currently loaded.
	// +optional
	MappingCount int32 `json:"mappingCount,omitempty"`

	// Conditions represent the latest available observations of the framework's
	// state. The Loaded condition is True when the framework is active in the
	// resolver.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=sf
// +kubebuilder:printcolumn:name="Framework ID",type=string,JSONPath=`.spec.frameworkID`
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.spec.version`
// +kubebuilder:printcolumn:name="Mappings",type=integer,JSONPath=`.status.mappingCount`
// +kubebuilder:printcolumn:name="Loaded",type=string,JSONPath=`.status.conditions[?(@.type=="Loaded")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SiderealFramework defines a compliance framework crosswalk, mapping
// (profile, NIST 800-53 control) pairs to framework-specific control IDs.
// Apply SiderealFramework resources to add, update, or remove compliance
// frameworks without restarting the controller.
type SiderealFramework struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SiderealFrameworkSpec   `json:"spec,omitempty"`
	Status SiderealFrameworkStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SiderealFrameworkList contains a list of SiderealFramework.
type SiderealFrameworkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SiderealFramework `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SiderealFramework{}, &SiderealFrameworkList{})
}
