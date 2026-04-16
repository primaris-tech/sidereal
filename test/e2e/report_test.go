package e2e

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/controller"
	"github.com/primaris-tech/sidereal/internal/report"
)

func TestReport_QueryReportData(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "report-data-"+uid)
	rootKey := createHMACRootSecret(t)

	// Create a probe and result for report data.
	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "report-data-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:         siderealv1alpha1.ProbeProfileRBAC,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
			ControlMappings: map[string][]string{
				"nist-800-53": {"AC-6(5)"},
			},
		},
	})

	probeID := uid + "rpt0-rpt0-rpt0-rpt0rpt0rpt0"
	simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeProfileRBAC),
		probe.Name, ns, string(siderealv1alpha1.OutcomePass), "Report data test", rootKey)

	waitForProbeResult(t, probeID, 10*time.Second)

	// Query report data.
	tr := report.TimeRange{
		From: time.Now().Add(-1 * time.Hour),
		To:   time.Now().Add(1 * time.Hour),
	}

	data, err := report.QueryReportData(ctx, k8sClient, tr, []string{"nist-800-53"})
	if err != nil {
		t.Fatalf("QueryReportData failed: %v", err)
	}

	if len(data.Results) == 0 {
		t.Error("expected at least one ProbeResult in report data")
	}
	if len(data.Probes) == 0 {
		t.Error("expected at least one Probe in report data")
	}
}

func TestReport_EffectivenessDistribution(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "report-dist-"+uid)
	rootKey := createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "report-dist-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:         siderealv1alpha1.ProbeProfileRBAC,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
		},
	})

	// Create Pass and Fail results.
	passID := uid + "rpas-rpas-rpas-rpasrpasrpas"
	simulateProbeResult(t, passID, string(siderealv1alpha1.ProbeProfileRBAC),
		probe.Name, ns, string(siderealv1alpha1.OutcomePass), "Pass result", rootKey)
	waitForProbeResult(t, passID, 10*time.Second)

	failID := uid + "rfal-rfal-rfal-rfalrfalrfal"
	simulateProbeResult(t, failID, string(siderealv1alpha1.ProbeProfileRBAC),
		probe.Name, ns, string(siderealv1alpha1.OutcomeFail), "Fail result", rootKey)
	waitForProbeResult(t, failID, 10*time.Second)

	// Query and verify distribution.
	tr := report.TimeRange{
		From: time.Now().Add(-1 * time.Hour),
		To:   time.Now().Add(1 * time.Hour),
	}

	data, err := report.QueryReportData(ctx, k8sClient, tr, nil)
	if err != nil {
		t.Fatalf("QueryReportData failed: %v", err)
	}

	dist := report.ComputeDistribution(data.Results)

	if dist.Total < 2 {
		t.Errorf("expected at least 2 results in distribution, got %d", dist.Total)
	}
	if dist.Effective < 1 {
		t.Error("expected at least 1 Effective result")
	}
	if dist.Ineffective < 1 {
		t.Error("expected at least 1 Ineffective result")
	}
}

func TestReport_ReportTypes(t *testing.T) {
	reportTypes := []siderealv1alpha1.ReportType{
		siderealv1alpha1.ReportTypeContinuousMonitoring,
		siderealv1alpha1.ReportTypePOAM,
		siderealv1alpha1.ReportTypeCoverageMatrix,
		siderealv1alpha1.ReportTypeEvidencePackage,
		siderealv1alpha1.ReportTypeExecutiveSummary,
	}

	for _, rt := range reportTypes {
		t.Run(string(rt), func(t *testing.T) {
			// Verify the report type is a valid enum value.
			switch rt {
			case siderealv1alpha1.ReportTypeContinuousMonitoring,
				siderealv1alpha1.ReportTypePOAM,
				siderealv1alpha1.ReportTypeCoverageMatrix,
				siderealv1alpha1.ReportTypeEvidencePackage,
				siderealv1alpha1.ReportTypeExecutiveSummary:
				// valid
			default:
				t.Errorf("unrecognized report type: %s", rt)
			}
		})
	}
}
