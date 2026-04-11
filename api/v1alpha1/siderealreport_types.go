package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ReportType defines the type of report to generate.
// +kubebuilder:validation:Enum=continuous-monitoring;poam;coverage-matrix;evidence-package;executive-summary
type ReportType string

const (
	ReportTypeContinuousMonitoring ReportType = "continuous-monitoring"
	ReportTypePOAM                 ReportType = "poam"
	ReportTypeCoverageMatrix       ReportType = "coverage-matrix"
	ReportTypeEvidencePackage      ReportType = "evidence-package"
	ReportTypeExecutiveSummary     ReportType = "executive-summary"
)

// ReportFormat defines the output format of a generated report.
// +kubebuilder:validation:Enum=oscal-json;pdf;markdown;csv;zip
type ReportFormat string

const (
	ReportFormatOSCALJSON ReportFormat = "oscal-json"
	ReportFormatPDF       ReportFormat = "pdf"
	ReportFormatMarkdown  ReportFormat = "markdown"
	ReportFormatCSV       ReportFormat = "csv"
	ReportFormatZIP       ReportFormat = "zip"
)

// GenerationStatus indicates the outcome of the last report generation.
// +kubebuilder:validation:Enum=Success;Failed
type GenerationStatus string

const (
	GenerationSuccess GenerationStatus = "Success"
	GenerationFailed  GenerationStatus = "Failed"
)

// ReportTimeRange defines the time range for report data.
type ReportTimeRange struct {
	// From is the start of the reporting period. Defaults to last report or 30 days ago.
	// +optional
	From *metav1.Time `json:"from,omitempty"`

	// To is the end of the reporting period. Defaults to now.
	// +optional
	To *metav1.Time `json:"to,omitempty"`
}

// SiderealReportSpec defines the desired state of a scheduled report.
type SiderealReportSpec struct {
	// Type is the kind of report to generate.
	// +kubebuilder:validation:Required
	Type ReportType `json:"type"`

	// Schedule is a cron expression for automated generation (e.g., "0 0 1 * *" for monthly).
	// +optional
	Schedule string `json:"schedule,omitempty"`

	// Frameworks is the list of compliance frameworks to include in the report.
	// +optional
	Frameworks []string `json:"frameworks,omitempty"`

	// Format is the output format.
	// +kubebuilder:validation:Required
	Format ReportFormat `json:"format"`

	// OutputSecret is the Kubernetes Secret name where the generated report is stored.
	// +kubebuilder:validation:Required
	OutputSecret string `json:"outputSecret"`

	// Retention is the number of historical reports to keep.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=5
	// +optional
	Retention int32 `json:"retention,omitempty"`

	// TimeRange defines the reporting period.
	// +optional
	TimeRange *ReportTimeRange `json:"timeRange,omitempty"`
}

// SiderealReportStatus defines the observed state of a SiderealReport.
type SiderealReportStatus struct {
	// LastGeneratedAt is the timestamp of the last successful generation.
	// +optional
	LastGeneratedAt *metav1.Time `json:"lastGeneratedAt,omitempty"`

	// LastGenerationStatus indicates the outcome of the last generation attempt.
	// +optional
	LastGenerationStatus GenerationStatus `json:"lastGenerationStatus,omitempty"`

	// Conditions represent the latest available observations of the report's state.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=sr
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Format",type=string,JSONPath=`.spec.format`
// +kubebuilder:printcolumn:name="Schedule",type=string,JSONPath=`.spec.schedule`
// +kubebuilder:printcolumn:name="Last Generated",type=date,JSONPath=`.status.lastGeneratedAt`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.lastGenerationStatus`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SiderealReport defines a scheduled report generation configuration.
type SiderealReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SiderealReportSpec   `json:"spec,omitempty"`
	Status SiderealReportStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SiderealReportList contains a list of SiderealReport.
type SiderealReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SiderealReport `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SiderealReport{}, &SiderealReportList{})
}
