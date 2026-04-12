// Package export implements the SIEM audit export pipeline. It defines the
// AuditExportBackend interface for sending probe results to external systems
// (Splunk, Elasticsearch, S3) and the FormatSerializer interface for encoding
// records in various formats (JSON, CEF, LEEF, Syslog RFC 5424, OCSF).
//
// Each export target is configured with its own format. A single deployment
// can export JSON to Splunk AND OCSF to AWS Security Lake simultaneously.
package export

import (
	"context"
	"time"
)

// AuditRecord is the canonical representation of a probe result for export.
// Fields are drawn from SSP section 11.
type AuditRecord struct {
	// ProbeID is the unique probe execution identifier.
	ProbeID string `json:"probeId"`

	// ProbeType is the probe surface (rbac, netpol, admission, secret, detection, custom).
	ProbeType string `json:"probeType"`

	// Outcome is the raw probe outcome (Pass, Fail, Detected, etc.).
	Outcome string `json:"outcome"`

	// ControlEffectiveness is the derived effectiveness (Effective, Ineffective, Degraded, Compromised).
	ControlEffectiveness string `json:"controlEffectiveness"`

	// Timestamp is when the probe executed.
	Timestamp time.Time `json:"timestamp"`

	// ControlMappings maps framework IDs to control IDs.
	ControlMappings map[string][]string `json:"controlMappings,omitempty"`

	// CrosswalkVersion is the version of the crosswalk data used.
	CrosswalkVersion string `json:"crosswalkVersion,omitempty"`

	// IntegrityStatus is the HMAC verification result (Verified, TamperedResult).
	IntegrityStatus string `json:"integrityStatus"`

	// TargetNamespace is the namespace that was probed.
	TargetNamespace string `json:"targetNamespace"`

	// Detail is the human-readable result description.
	Detail string `json:"detail,omitempty"`

	// DurationMs is the probe execution duration in milliseconds.
	DurationMs int64 `json:"durationMs"`

	// ExportStatus tracks the export state (Pending, Exported, Failed).
	ExportStatus string `json:"exportStatus"`
}

// AuditExportBackend is the interface for exporting audit records to external systems.
type AuditExportBackend interface {
	// Export sends a single audit record to the external system.
	Export(ctx context.Context, record AuditRecord) error

	// Name returns the backend identifier (e.g., "splunk", "elasticsearch", "s3").
	Name() string
}

// FormatSerializer encodes an AuditRecord into a specific wire format.
type FormatSerializer interface {
	// Serialize encodes the audit record into the target format.
	Serialize(record AuditRecord) ([]byte, error)

	// ContentType returns the MIME type for the serialized format.
	ContentType() string

	// FormatName returns the format identifier (e.g., "json", "cef", "leef", "syslog", "ocsf").
	FormatName() string
}
