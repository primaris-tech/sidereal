package report

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ContinuousMonitoringReport is the continuous monitoring summary output.
type ContinuousMonitoringReport struct {
	ReportType string                    `json:"reportType"`
	Period     string                    `json:"period"`
	Frameworks []string                  `json:"frameworks"`
	Summary    EffectivenessDistribution `json:"summary"`
	ByProfile  []ProfileSummary          `json:"byProfile"`
	Controls   []ControlStatus           `json:"controls,omitempty"`
}

// GenerateContinuousMonitoring produces a continuous monitoring summary.
func GenerateContinuousMonitoring(data *ReportData, format string) ([]byte, error) {
	report := ContinuousMonitoringReport{
		ReportType: "continuous-monitoring",
		Period:     fmt.Sprintf("%s to %s", data.TimeRange.From.Format("2006-01-02"), data.TimeRange.To.Format("2006-01-02")),
		Frameworks: data.Frameworks,
		Summary:    ComputeDistribution(data.Results),
		ByProfile:  ComputeProfileSummaries(data.Results),
		Controls:   computeControlStatuses(data),
	}

	switch format {
	case "oscal-json", "json":
		return json.MarshalIndent(report, "", "  ")
	case "markdown":
		return renderContinuousMonitoringMarkdown(report), nil
	default:
		return json.MarshalIndent(report, "", "  ")
	}
}

func computeControlStatuses(data *ReportData) []ControlStatus {
	// Build a map of control -> results from probe control mappings.
	controlResults := make(map[string]*ControlStatus)

	for _, result := range data.Results {
		mappings := result.Spec.Result.ControlMappings
		for framework, controls := range mappings {
			for _, controlID := range controls {
				key := framework + "/" + controlID
				cs, ok := controlResults[key]
				if !ok {
					cs = &ControlStatus{
						ControlID:      controlID,
						Framework:      framework,
						Profile:        string(result.Spec.Probe.Profile),
						HasActiveProbe: true,
					}
					controlResults[key] = cs
				}
				cs.TotalExecutions++
				cs.LastOutcome = string(result.Spec.Result.Outcome)
				cs.LastEffectiveness = string(result.Spec.Result.ControlEffectiveness)
				if result.Spec.Result.ControlEffectiveness == "Effective" {
					cs.EffectiveCount++
				}
			}
		}
	}

	var statuses []ControlStatus
	for _, cs := range controlResults {
		if cs.TotalExecutions > 0 {
			cs.EffectivenessPercent = float64(cs.EffectiveCount) / float64(cs.TotalExecutions) * 100
		}
		statuses = append(statuses, *cs)
	}
	return statuses
}

func renderContinuousMonitoringMarkdown(report ContinuousMonitoringReport) []byte {
	var b strings.Builder
	b.WriteString("# Continuous Monitoring Summary\n\n")
	b.WriteString(fmt.Sprintf("**Period:** %s\n\n", report.Period))
	b.WriteString(fmt.Sprintf("**Frameworks:** %s\n\n", strings.Join(report.Frameworks, ", ")))

	b.WriteString("## Overall Effectiveness\n\n")
	b.WriteString(fmt.Sprintf("| Metric | Count |\n|---|---|\n"))
	b.WriteString(fmt.Sprintf("| Total Executions | %d |\n", report.Summary.Total))
	b.WriteString(fmt.Sprintf("| Effective | %d |\n", report.Summary.Effective))
	b.WriteString(fmt.Sprintf("| Ineffective | %d |\n", report.Summary.Ineffective))
	b.WriteString(fmt.Sprintf("| Degraded | %d |\n", report.Summary.Degraded))
	b.WriteString(fmt.Sprintf("| Compromised | %d |\n\n", report.Summary.Compromised))

	if len(report.ByProfile) > 0 {
		b.WriteString("## By Profile\n\n")
		b.WriteString("| Profile | Runs | Effective | Ineffective | Degraded | Compromised |\n")
		b.WriteString("|---|---|---|---|---|---|\n")
		for _, pt := range report.ByProfile {
			b.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %d | %d |\n",
				pt.Profile, pt.TotalRuns,
				pt.Distribution.Effective, pt.Distribution.Ineffective,
				pt.Distribution.Degraded, pt.Distribution.Compromised))
		}
	}

	return []byte(b.String())
}
