package report

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ExecutiveSummaryReport is the AO/ISSO-facing summary that uses only
// controlEffectiveness (no raw outcomes).
type ExecutiveSummaryReport struct {
	ReportType    string                    `json:"reportType"`
	Period        string                    `json:"period"`
	Frameworks    []string                  `json:"frameworks"`
	Overall       EffectivenessDistribution `json:"overall"`
	ByProfile     []ProfileSummary          `json:"byProfile"`
	OpenIncidents int                       `json:"openIncidents"`
	Posture       string                    `json:"posture"`
}

// GenerateExecutiveSummary produces an executive summary for AO/ISSO consumption.
func GenerateExecutiveSummary(data *ReportData, format string) ([]byte, error) {
	dist := ComputeDistribution(data.Results)

	openIncidents := 0
	for _, inc := range data.Incidents {
		if inc.Spec.RemediationStatus == "Open" {
			openIncidents++
		}
	}

	report := ExecutiveSummaryReport{
		ReportType:    "executive-summary",
		Period:        fmt.Sprintf("%s to %s", data.TimeRange.From.Format("2006-01-02"), data.TimeRange.To.Format("2006-01-02")),
		Frameworks:    data.Frameworks,
		Overall:       dist,
		ByProfile:     ComputeProfileSummaries(data.Results),
		OpenIncidents: openIncidents,
		Posture:       computePosture(dist, openIncidents),
	}

	switch format {
	case "markdown":
		return renderExecutiveSummaryMarkdown(report), nil
	default:
		return json.MarshalIndent(report, "", "  ")
	}
}

// computePosture determines the overall security posture label.
func computePosture(dist EffectivenessDistribution, openIncidents int) string {
	if dist.Compromised > 0 {
		return "Critical"
	}
	if dist.Ineffective > 0 || openIncidents > 0 {
		return "At Risk"
	}
	if dist.Degraded > 0 {
		return "Degraded"
	}
	if dist.Total == 0 {
		return "No Data"
	}
	return "Healthy"
}

func renderExecutiveSummaryMarkdown(report ExecutiveSummaryReport) []byte {
	var b strings.Builder
	b.WriteString("# Executive Summary\n\n")
	b.WriteString(fmt.Sprintf("**Period:** %s\n\n", report.Period))
	b.WriteString(fmt.Sprintf("**Security Posture:** %s\n\n", report.Posture))
	b.WriteString(fmt.Sprintf("**Open Incidents:** %d\n\n", report.OpenIncidents))

	b.WriteString("## Control Effectiveness\n\n")
	b.WriteString("| Metric | Count |\n|---|---|\n")
	b.WriteString(fmt.Sprintf("| Total Validations | %d |\n", report.Overall.Total))
	b.WriteString(fmt.Sprintf("| Effective | %d |\n", report.Overall.Effective))
	b.WriteString(fmt.Sprintf("| Ineffective | %d |\n", report.Overall.Ineffective))
	b.WriteString(fmt.Sprintf("| Degraded | %d |\n", report.Overall.Degraded))
	b.WriteString(fmt.Sprintf("| Compromised | %d |\n", report.Overall.Compromised))

	if report.Overall.Total > 0 {
		pct := float64(report.Overall.Effective) / float64(report.Overall.Total) * 100
		b.WriteString(fmt.Sprintf("\n**Effectiveness Rate:** %.1f%%\n", pct))
	}

	return []byte(b.String())
}
