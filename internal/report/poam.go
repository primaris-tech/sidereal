package report

import (
	"encoding/json"
	"fmt"
	"strings"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
)

// POAMEntry represents a single Plan of Action and Milestones entry.
type POAMEntry struct {
	IncidentName         string `json:"incidentName"`
	ControlID            string `json:"controlId,omitempty"`
	MitreID              string `json:"mitreId,omitempty"`
	Profile              string `json:"profile"`
	TargetNamespace      string `json:"targetNamespace"`
	Severity             string `json:"severity"`
	ControlEffectiveness string `json:"controlEffectiveness"`
	Description          string `json:"description"`
	RemediationStatus    string `json:"remediationStatus"`
	CreatedAt            string `json:"createdAt"`
}

// POAMReport is the POA&M output.
type POAMReport struct {
	ReportType string      `json:"reportType"`
	Entries    []POAMEntry `json:"entries"`
	TotalOpen  int         `json:"totalOpen"`
}

// GeneratePOAM produces a Plan of Action and Milestones from open incidents.
func GeneratePOAM(data *ReportData, format string, openOnly bool) ([]byte, error) {
	var entries []POAMEntry
	totalOpen := 0

	for _, incident := range data.Incidents {
		if openOnly && incident.Spec.RemediationStatus != siderealv1alpha1.RemediationOpen {
			continue
		}

		if incident.Spec.RemediationStatus == siderealv1alpha1.RemediationOpen {
			totalOpen++
		}

		entries = append(entries, POAMEntry{
			IncidentName:         incident.Name,
			ControlID:            incident.Spec.ControlID,
			MitreID:              incident.Spec.MitreID,
			Profile:              string(incident.Spec.Profile),
			TargetNamespace:      incident.Spec.TargetNamespace,
			Severity:             string(incident.Spec.Severity),
			ControlEffectiveness: string(incident.Spec.ControlEffectiveness),
			Description:          incident.Spec.Description,
			RemediationStatus:    string(incident.Spec.RemediationStatus),
			CreatedAt:            incident.CreationTimestamp.Format("2006-01-02T15:04:05Z"),
		})
	}

	report := POAMReport{
		ReportType: "poam",
		Entries:    entries,
		TotalOpen:  totalOpen,
	}

	switch format {
	case "csv":
		return renderPOAMCSV(entries), nil
	case "oscal-json", "json":
		return json.MarshalIndent(report, "", "  ")
	case "markdown":
		return renderPOAMMarkdown(report), nil
	default:
		return json.MarshalIndent(report, "", "  ")
	}
}

func renderPOAMCSV(entries []POAMEntry) []byte {
	var b strings.Builder
	b.WriteString("Incident,Control ID,MITRE ID,Profile,Namespace,Severity,Effectiveness,Status,Created\n")
	for _, e := range entries {
		b.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			e.IncidentName, e.ControlID, e.MitreID, e.Profile,
			e.TargetNamespace, e.Severity, e.ControlEffectiveness,
			e.RemediationStatus, e.CreatedAt))
	}
	return []byte(b.String())
}

func renderPOAMMarkdown(report POAMReport) []byte {
	var b strings.Builder
	b.WriteString("# Plan of Action and Milestones (POA&M)\n\n")
	b.WriteString(fmt.Sprintf("**Open Items:** %d\n\n", report.TotalOpen))

	if len(report.Entries) > 0 {
		b.WriteString("| Incident | Control | Severity | Namespace | Status |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, e := range report.Entries {
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
				e.IncidentName, e.ControlID, e.Severity,
				e.TargetNamespace, e.RemediationStatus))
		}
	} else {
		b.WriteString("No items to report.\n")
	}

	return []byte(b.String())
}
