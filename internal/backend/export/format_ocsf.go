package export

import (
	"encoding/json"
)

// OCSFSerializer serializes audit records in OCSF v1.1 format, mapping to
// the Security Finding class (class_uid 2001). This is the format used by
// AWS Security Lake and Amazon Security Hub.
type OCSFSerializer struct{}

// ocsfSecurityFinding represents an OCSF v1.1 Security Finding event.
type ocsfSecurityFinding struct {
	ClassUID    int              `json:"class_uid"`
	ClassName   string           `json:"class_name"`
	CategoryUID int              `json:"category_uid"`
	TypeUID     int              `json:"type_uid"`
	TypeName    string           `json:"type_name"`
	SeverityID  int              `json:"severity_id"`
	Severity    string           `json:"severity"`
	ActivityID  int              `json:"activity_id"`
	ActivityName string          `json:"activity_name"`
	StatusID    int              `json:"status_id"`
	Status      string           `json:"status"`
	Time        int64            `json:"time"`
	Message     string           `json:"message,omitempty"`
	Finding     ocsfFinding      `json:"finding"`
	Resources   []ocsfResource   `json:"resources,omitempty"`
	Metadata    ocsfMetadata     `json:"metadata"`
	Unmapped    map[string]interface{} `json:"unmapped,omitempty"`
}

type ocsfFinding struct {
	Title       string `json:"title"`
	UID         string `json:"uid"`
	Description string `json:"desc,omitempty"`
	Types       []string `json:"types,omitempty"`
}

type ocsfResource struct {
	Type      string `json:"type"`
	Namespace string `json:"namespace,omitempty"`
	UID       string `json:"uid,omitempty"`
}

type ocsfMetadata struct {
	Version string      `json:"version"`
	Product ocsfProduct `json:"product"`
}

type ocsfProduct struct {
	Name      string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version   string `json:"version"`
}

func (s *OCSFSerializer) Serialize(record AuditRecord) ([]byte, error) {
	severityID, severity := ocsfSeverity(record.ControlEffectiveness)
	statusID, status := ocsfStatus(record.Outcome)

	finding := ocsfSecurityFinding{
		ClassUID:    2001,
		ClassName:   "Security Finding",
		CategoryUID: 2,
		TypeUID:     200101,
		TypeName:    "Security Finding: Create",
		SeverityID:  severityID,
		Severity:    severity,
		ActivityID:  1,
		ActivityName: "Create",
		StatusID:    statusID,
		Status:      status,
		Time:        record.Timestamp.UnixMilli(),
		Message:     record.Detail,
		Finding: ocsfFinding{
			Title:       record.ProbeType + " probe: " + record.Outcome,
			UID:         record.ProbeID,
			Description: record.Detail,
			Types:       []string{"Security Control Validation"},
		},
		Resources: []ocsfResource{
			{
				Type:      "Namespace",
				Namespace: record.TargetNamespace,
				UID:       record.ProbeID,
			},
		},
		Metadata: ocsfMetadata{
			Version: "1.1.0",
			Product: ocsfProduct{
				Name:      "Sidereal",
				VendorName: "Sidereal",
				Version:   "0.1.0",
			},
		},
		Unmapped: map[string]interface{}{
			"controlEffectiveness": record.ControlEffectiveness,
			"integrityStatus":     record.IntegrityStatus,
			"controlMappings":     record.ControlMappings,
			"crosswalkVersion":    record.CrosswalkVersion,
			"durationMs":          record.DurationMs,
		},
	}

	return json.Marshal(finding)
}

func (s *OCSFSerializer) ContentType() string { return "application/json" }
func (s *OCSFSerializer) FormatName() string  { return "ocsf" }

// ocsfSeverity maps ControlEffectiveness to OCSF severity_id and label.
func ocsfSeverity(effectiveness string) (int, string) {
	switch effectiveness {
	case "Effective":
		return 1, "Informational"
	case "Degraded":
		return 3, "Medium"
	case "Ineffective":
		return 4, "High"
	case "Compromised":
		return 5, "Critical"
	default:
		return 0, "Unknown"
	}
}

// ocsfStatus maps probe Outcome to OCSF status_id and label.
func ocsfStatus(outcome string) (int, string) {
	switch outcome {
	case "Pass", "Detected", "Blocked", "Rejected":
		return 1, "Success"
	case "Fail", "Undetected", "Accepted", "NotEnforced":
		return 2, "Failure"
	default:
		return 0, "Unknown"
	}
}
