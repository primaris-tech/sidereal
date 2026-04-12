package report

import (
	"encoding/json"
	"fmt"
	"strings"
)

// CoverageMatrixReport shows which controls have active probes and their status.
type CoverageMatrixReport struct {
	ReportType string          `json:"reportType"`
	Frameworks []string        `json:"frameworks"`
	Controls   []ControlStatus `json:"controls"`
	Coverage   CoverageStats   `json:"coverage"`
}

// CoverageStats summarizes coverage across all controls.
type CoverageStats struct {
	TotalControls  int     `json:"totalControls"`
	CoveredByProbe int     `json:"coveredByProbe"`
	CoveragePercent float64 `json:"coveragePercent"`
}

// GenerateCoverageMatrix produces a control coverage matrix.
func GenerateCoverageMatrix(data *ReportData, format string) ([]byte, error) {
	controls := computeControlStatuses(data)

	// Filter by requested frameworks if specified.
	if len(data.Frameworks) > 0 {
		frameworkSet := make(map[string]bool)
		for _, f := range data.Frameworks {
			frameworkSet[f] = true
		}
		var filtered []ControlStatus
		for _, cs := range controls {
			if frameworkSet[cs.Framework] {
				filtered = append(filtered, cs)
			}
		}
		controls = filtered
	}

	covered := 0
	for _, cs := range controls {
		if cs.HasActiveProbe {
			covered++
		}
	}

	var coveragePercent float64
	if len(controls) > 0 {
		coveragePercent = float64(covered) / float64(len(controls)) * 100
	}

	report := CoverageMatrixReport{
		ReportType: "coverage-matrix",
		Frameworks: data.Frameworks,
		Controls:   controls,
		Coverage: CoverageStats{
			TotalControls:  len(controls),
			CoveredByProbe: covered,
			CoveragePercent: coveragePercent,
		},
	}

	switch format {
	case "csv":
		return renderCoverageCSV(controls), nil
	case "markdown":
		return renderCoverageMarkdown(report), nil
	default:
		return json.MarshalIndent(report, "", "  ")
	}
}

func renderCoverageCSV(controls []ControlStatus) []byte {
	var b strings.Builder
	b.WriteString("Framework,Control ID,Probe Type,Active,Executions,Effective,Effectiveness %\n")
	for _, cs := range controls {
		b.WriteString(fmt.Sprintf("%s,%s,%s,%t,%d,%d,%.1f\n",
			cs.Framework, cs.ControlID, cs.ProbeType,
			cs.HasActiveProbe, cs.TotalExecutions,
			cs.EffectiveCount, cs.EffectivenessPercent))
	}
	return []byte(b.String())
}

func renderCoverageMarkdown(report CoverageMatrixReport) []byte {
	var b strings.Builder
	b.WriteString("# Control Coverage Matrix\n\n")
	b.WriteString(fmt.Sprintf("**Frameworks:** %s\n\n", strings.Join(report.Frameworks, ", ")))
	b.WriteString(fmt.Sprintf("**Coverage:** %d/%d controls (%.1f%%)\n\n",
		report.Coverage.CoveredByProbe, report.Coverage.TotalControls, report.Coverage.CoveragePercent))

	if len(report.Controls) > 0 {
		b.WriteString("| Framework | Control | Probe Type | Executions | Effectiveness |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, cs := range report.Controls {
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %d | %.1f%% |\n",
				cs.Framework, cs.ControlID, cs.ProbeType,
				cs.TotalExecutions, cs.EffectivenessPercent))
		}
	}

	return []byte(b.String())
}
