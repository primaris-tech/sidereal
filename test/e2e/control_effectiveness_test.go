package e2e

import (
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/controller"
)

func TestControlEffectiveness_OutcomeMapping(t *testing.T) {
	tests := []struct {
		name                string
		outcome             siderealv1alpha1.ProbeOutcome
		expectedEffectiveness siderealv1alpha1.ControlEffectiveness
	}{
		{"Pass is Effective", siderealv1alpha1.OutcomePass, siderealv1alpha1.EffectivenessEffective},
		{"Fail is Ineffective", siderealv1alpha1.OutcomeFail, siderealv1alpha1.EffectivenessIneffective},
		{"Detected is Effective", siderealv1alpha1.OutcomeDetected, siderealv1alpha1.EffectivenessEffective},
		{"Undetected is Ineffective", siderealv1alpha1.OutcomeUndetected, siderealv1alpha1.EffectivenessIneffective},
		{"Blocked is Effective", siderealv1alpha1.OutcomeBlocked, siderealv1alpha1.EffectivenessEffective},
		{"Rejected is Effective", siderealv1alpha1.OutcomeRejected, siderealv1alpha1.EffectivenessEffective},
		{"Accepted is Ineffective", siderealv1alpha1.OutcomeAccepted, siderealv1alpha1.EffectivenessIneffective},
		{"NotApplicable is Degraded", siderealv1alpha1.OutcomeNotApplicable, siderealv1alpha1.EffectivenessDegraded},
		{"BackendUnreachable is Degraded", siderealv1alpha1.OutcomeBackendUnreachable, siderealv1alpha1.EffectivenessDegraded},
		{"NotEnforced is Ineffective", siderealv1alpha1.OutcomeNotEnforced, siderealv1alpha1.EffectivenessIneffective},
		{"Indeterminate is Degraded", siderealv1alpha1.OutcomeIndeterminate, siderealv1alpha1.EffectivenessDegraded},
		{"TamperedResult is Compromised", siderealv1alpha1.OutcomeTamperedResult, siderealv1alpha1.EffectivenessCompromised},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			effectiveness := siderealv1alpha1.DeriveControlEffectiveness(tt.outcome)
			if effectiveness != tt.expectedEffectiveness {
				t.Errorf("outcome %s: expected %s, got %s", tt.outcome, tt.expectedEffectiveness, effectiveness)
			}
		})
	}
}

func TestControlEffectiveness_EndToEnd(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "eff-e2e-"+uid)
	rootKey := createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "eff-e2e-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			ProbeType:       siderealv1alpha1.ProbeTypeAdmission,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
			ControlMappings: map[string][]string{
				"nist-800-53": {"CM-7(5)"},
			},
		},
	})

	// Test Rejected outcome -> Effective.
	probeID := uid + "6666-6666-6666-666666666666"
	simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeTypeAdmission),
		probe.Name, ns, string(siderealv1alpha1.OutcomeRejected), "admission policy rejected request", rootKey)

	result := waitForProbeResult(t, probeID, 10*time.Second)

	if result.Spec.Result.ControlEffectiveness != siderealv1alpha1.EffectivenessEffective {
		t.Errorf("Rejected should map to Effective, got %s", result.Spec.Result.ControlEffectiveness)
	}

	// Verify effectiveness label.
	if result.Labels["sidereal.cloud/control-effectiveness"] != string(siderealv1alpha1.EffectivenessEffective) {
		t.Error("control-effectiveness label not set correctly")
	}

	// Verify control mappings are populated.
	if result.Spec.Result.ControlMappings == nil {
		t.Error("controlMappings should be populated")
	}
}

func TestControlEffectiveness_IncidentSeverityMapping(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "sev-map-"+uid)
	rootKey := createHMACRootSecret(t)

	tests := []struct {
		outcome          string
		effectiveness    siderealv1alpha1.ControlEffectiveness
		expectedSeverity siderealv1alpha1.IncidentSeverity
	}{
		{string(siderealv1alpha1.OutcomeTamperedResult), siderealv1alpha1.EffectivenessCompromised, siderealv1alpha1.SeverityCritical},
		{string(siderealv1alpha1.OutcomeFail), siderealv1alpha1.EffectivenessIneffective, siderealv1alpha1.SeverityHigh},
	}

	for i, tt := range tests {
		t.Run(string(tt.expectedSeverity), func(t *testing.T) {
			subUID := uniqueID()
			probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("sev-%s-%d", subUID, i),
					Namespace: controller.SystemNamespace,
				},
				Spec: siderealv1alpha1.SiderealProbeSpec{
					ProbeType:       siderealv1alpha1.ProbeTypeRBAC,
					TargetNamespace: ns,
					ExecutionMode:   siderealv1alpha1.ExecutionModeEnforce,
					IntervalSeconds: 300,
					ControlMappings: map[string][]string{
						"nist-800-53": {"AC-6(5)"},
					},
				},
			})

			probeID := subUID + fmt.Sprintf("%04d-0000-0000-000000000000", i)
			simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeTypeRBAC),
				probe.Name, ns, tt.outcome, "severity test", rootKey)

			incident := waitForIncident(t, probeID, 10*time.Second)

			if incident.Spec.Severity != tt.expectedSeverity {
				t.Errorf("expected severity %s, got %s", tt.expectedSeverity, incident.Spec.Severity)
			}
		})
	}
}
