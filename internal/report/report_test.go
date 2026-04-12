package report

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
)

func testTimeRange() TimeRange {
	return TimeRange{
		From: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 3, 31, 23, 59, 59, 0, time.UTC),
	}
}

func testResults() []siderealv1alpha1.SiderealProbeResult {
	return []siderealv1alpha1.SiderealProbeResult{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "result-1"},
			Spec: siderealv1alpha1.SiderealProbeResultSpec{
				Probe: siderealv1alpha1.ProbeResultProbeRef{
					ID: "probe-1", Type: "rbac", TargetNamespace: "production",
				},
				Result: siderealv1alpha1.ProbeResultResult{
					Outcome:              siderealv1alpha1.OutcomePass,
					ControlEffectiveness: siderealv1alpha1.EffectivenessEffective,
					ControlMappings:      map[string][]string{"nist-800-53": {"AC-3"}},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "result-2"},
			Spec: siderealv1alpha1.SiderealProbeResultSpec{
				Probe: siderealv1alpha1.ProbeResultProbeRef{
					ID: "probe-2", Type: "secret", TargetNamespace: "production",
				},
				Result: siderealv1alpha1.ProbeResultResult{
					Outcome:              siderealv1alpha1.OutcomeFail,
					ControlEffectiveness: siderealv1alpha1.EffectivenessIneffective,
					ControlMappings:      map[string][]string{"nist-800-53": {"AC-4"}},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "result-3"},
			Spec: siderealv1alpha1.SiderealProbeResultSpec{
				Probe: siderealv1alpha1.ProbeResultProbeRef{
					ID: "probe-3", Type: "rbac", TargetNamespace: "staging",
				},
				Result: siderealv1alpha1.ProbeResultResult{
					Outcome:              siderealv1alpha1.OutcomePass,
					ControlEffectiveness: siderealv1alpha1.EffectivenessEffective,
					ControlMappings:      map[string][]string{"nist-800-53": {"AC-3", "AC-6"}},
				},
			},
		},
	}
}

func testIncidents() []siderealv1alpha1.SiderealIncident {
	return []siderealv1alpha1.SiderealIncident{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "incident-1",
				CreationTimestamp: metav1.NewTime(time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)),
			},
			Spec: siderealv1alpha1.SiderealIncidentSpec{
				ProbeResultRef:        "result-2",
				ControlID:             "AC-4",
				ProbeType:             "secret",
				TargetNamespace:       "production",
				Severity:              siderealv1alpha1.SeverityHigh,
				ControlEffectiveness:  siderealv1alpha1.EffectivenessIneffective,
				Description:           "Cross-namespace secret access allowed",
				RemediationStatus:     siderealv1alpha1.RemediationOpen,
				WebhookDeliveryStatus: siderealv1alpha1.WebhookDelivered,
			},
		},
	}
}

func testData() *ReportData {
	return &ReportData{
		Results:    testResults(),
		Incidents:  testIncidents(),
		TimeRange:  testTimeRange(),
		Frameworks: []string{"nist-800-53"},
	}
}

// --- Distribution ---

func TestComputeDistribution(t *testing.T) {
	dist := ComputeDistribution(testResults())

	if dist.Total != 3 {
		t.Errorf("expected 3 total, got %d", dist.Total)
	}
	if dist.Effective != 2 {
		t.Errorf("expected 2 effective, got %d", dist.Effective)
	}
	if dist.Ineffective != 1 {
		t.Errorf("expected 1 ineffective, got %d", dist.Ineffective)
	}
}

func TestComputeProbeTypeSummaries(t *testing.T) {
	summaries := ComputeProbeTypeSummaries(testResults())

	if len(summaries) != 2 {
		t.Fatalf("expected 2 probe types, got %d", len(summaries))
	}

	byType := make(map[string]ProbeTypeSummary)
	for _, s := range summaries {
		byType[s.ProbeType] = s
	}

	rbac := byType["rbac"]
	if rbac.TotalRuns != 2 {
		t.Errorf("expected 2 rbac runs, got %d", rbac.TotalRuns)
	}
	if rbac.Distribution.Effective != 2 {
		t.Errorf("expected 2 effective rbac, got %d", rbac.Distribution.Effective)
	}
}

// --- Continuous Monitoring ---

func TestContinuousMonitoring_JSON(t *testing.T) {
	data, err := GenerateContinuousMonitoring(testData(), "json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report ContinuousMonitoringReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if report.Summary.Total != 3 {
		t.Errorf("expected 3 total, got %d", report.Summary.Total)
	}
	if len(report.Controls) == 0 {
		t.Error("expected control statuses")
	}
}

func TestContinuousMonitoring_Markdown(t *testing.T) {
	data, err := GenerateContinuousMonitoring(testData(), "markdown")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	md := string(data)
	if !strings.Contains(md, "# Continuous Monitoring Summary") {
		t.Error("missing markdown header")
	}
	if !strings.Contains(md, "Effective") {
		t.Error("missing effectiveness data in markdown")
	}
}

// --- POA&M ---

func TestPOAM_JSON(t *testing.T) {
	data, err := GeneratePOAM(testData(), "json", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report POAMReport
	json.Unmarshal(data, &report)

	if len(report.Entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(report.Entries))
	}
	if report.TotalOpen != 1 {
		t.Errorf("expected 1 open, got %d", report.TotalOpen)
	}
}

func TestPOAM_CSV(t *testing.T) {
	data, err := GeneratePOAM(testData(), "csv", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	csv := string(data)
	lines := strings.Split(strings.TrimSpace(csv), "\n")
	if len(lines) != 2 { // header + 1 entry
		t.Errorf("expected 2 CSV lines, got %d", len(lines))
	}
	if !strings.Contains(lines[0], "Incident") {
		t.Error("missing CSV header")
	}
}

func TestPOAM_OpenOnly(t *testing.T) {
	d := testData()
	// Add a remediated incident.
	d.Incidents = append(d.Incidents, siderealv1alpha1.SiderealIncident{
		ObjectMeta: metav1.ObjectMeta{Name: "incident-remediated"},
		Spec: siderealv1alpha1.SiderealIncidentSpec{
			ProbeType:         "rbac",
			Severity:          siderealv1alpha1.SeverityMedium,
			RemediationStatus: siderealv1alpha1.RemediationRemediated,
		},
	})

	data, _ := GeneratePOAM(d, "json", true)
	var report POAMReport
	json.Unmarshal(data, &report)

	if len(report.Entries) != 1 {
		t.Errorf("expected 1 open entry, got %d", len(report.Entries))
	}
}

// --- Coverage Matrix ---

func TestCoverageMatrix_JSON(t *testing.T) {
	data, err := GenerateCoverageMatrix(testData(), "json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report CoverageMatrixReport
	json.Unmarshal(data, &report)

	if len(report.Controls) == 0 {
		t.Error("expected control entries")
	}
	if report.Coverage.CoveredByProbe == 0 {
		t.Error("expected some coverage")
	}
}

func TestCoverageMatrix_Markdown(t *testing.T) {
	data, err := GenerateCoverageMatrix(testData(), "markdown")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(string(data), "# Control Coverage Matrix") {
		t.Error("missing markdown header")
	}
}

// --- Evidence Package ---

func TestEvidencePackage(t *testing.T) {
	data, err := GenerateEvidencePackage(testData(), EvidencePackageOptions{
		IncludeResults:   true,
		IncludeIncidents: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it's a valid ZIP.
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("invalid ZIP: %v", err)
	}

	fileNames := make(map[string]bool)
	for _, f := range r.File {
		fileNames[f.Name] = true
	}

	if !fileNames["manifest.json"] {
		t.Error("missing manifest.json in ZIP")
	}
	if !fileNames["summary.json"] {
		t.Error("missing summary.json in ZIP")
	}

	// Should have 3 results + 1 incident.
	resultCount := 0
	incidentCount := 0
	for name := range fileNames {
		if strings.HasPrefix(name, "results/") {
			resultCount++
		}
		if strings.HasPrefix(name, "incidents/") {
			incidentCount++
		}
	}
	if resultCount != 3 {
		t.Errorf("expected 3 result files, got %d", resultCount)
	}
	if incidentCount != 1 {
		t.Errorf("expected 1 incident file, got %d", incidentCount)
	}
}

func TestEvidencePackage_NoIncludes(t *testing.T) {
	data, err := GenerateEvidencePackage(testData(), EvidencePackageOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r, _ := zip.NewReader(bytes.NewReader(data), int64(len(data)))

	// Should only have manifest + summary.
	if len(r.File) != 2 {
		t.Errorf("expected 2 files (manifest + summary), got %d", len(r.File))
	}
}

// --- Executive Summary ---

func TestExecutiveSummary_JSON(t *testing.T) {
	data, err := GenerateExecutiveSummary(testData(), "json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report ExecutiveSummaryReport
	json.Unmarshal(data, &report)

	if report.Posture != "At Risk" {
		t.Errorf("expected posture 'At Risk' (has ineffective + open incident), got %q", report.Posture)
	}
	if report.OpenIncidents != 1 {
		t.Errorf("expected 1 open incident, got %d", report.OpenIncidents)
	}
}

func TestExecutiveSummary_Markdown(t *testing.T) {
	data, err := GenerateExecutiveSummary(testData(), "markdown")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	md := string(data)
	if !strings.Contains(md, "# Executive Summary") {
		t.Error("missing markdown header")
	}
	if !strings.Contains(md, "Security Posture") {
		t.Error("missing posture in markdown")
	}
}

func TestComputePosture(t *testing.T) {
	tests := []struct {
		name          string
		dist          EffectivenessDistribution
		openIncidents int
		expected      string
	}{
		{"healthy", EffectivenessDistribution{Total: 10, Effective: 10}, 0, "Healthy"},
		{"at risk - ineffective", EffectivenessDistribution{Total: 10, Effective: 8, Ineffective: 2}, 0, "At Risk"},
		{"at risk - open incidents", EffectivenessDistribution{Total: 10, Effective: 10}, 1, "At Risk"},
		{"degraded", EffectivenessDistribution{Total: 10, Effective: 8, Degraded: 2}, 0, "Degraded"},
		{"critical", EffectivenessDistribution{Total: 10, Effective: 8, Compromised: 2}, 0, "Critical"},
		{"no data", EffectivenessDistribution{}, 0, "No Data"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computePosture(tt.dist, tt.openIncidents)
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}
