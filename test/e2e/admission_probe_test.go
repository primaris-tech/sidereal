package e2e

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/controller"
)

// SAP: TEST-AC-04 (Admission probe - policy rejection)
func TestAdmissionProbe_PolicyRejection(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "adm-reject-"+uid)
	rootKey := createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "adm-reject-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			ProbeType:       siderealv1alpha1.ProbeTypeAdmission,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
			ControlMappings: map[string][]string{
				"nist-800-53": {"CM-7(5)", "CM-7(2)"},
			},
		},
	})

	probeID := uid + "bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeTypeAdmission),
		probe.Name, ns, string(siderealv1alpha1.OutcomeRejected), "Kyverno policy rejected known-bad spec", rootKey)

	result := waitForProbeResult(t, probeID, 10*time.Second)

	if result.Spec.Result.Outcome != siderealv1alpha1.OutcomeRejected {
		t.Errorf("expected Rejected, got %s", result.Spec.Result.Outcome)
	}
	if result.Spec.Result.ControlEffectiveness != siderealv1alpha1.EffectivenessEffective {
		t.Errorf("expected Effective, got %s", result.Spec.Result.ControlEffectiveness)
	}
}

func TestAdmissionProbe_PolicyNotEnforced(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "adm-notEnf-"+uid)
	rootKey := createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "adm-notEnf-" + uid,
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

	probeID := uid + "cccc-cccc-cccc-cccccccccccc"
	simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeTypeAdmission),
		probe.Name, ns, string(siderealv1alpha1.OutcomeAccepted), "Known-bad spec was accepted", rootKey)

	result := waitForProbeResult(t, probeID, 10*time.Second)

	if result.Spec.Result.Outcome != siderealv1alpha1.OutcomeAccepted {
		t.Errorf("expected Accepted, got %s", result.Spec.Result.Outcome)
	}
	if result.Spec.Result.ControlEffectiveness != siderealv1alpha1.EffectivenessIneffective {
		t.Errorf("expected Ineffective, got %s", result.Spec.Result.ControlEffectiveness)
	}
}

func TestAdmissionProbe_Indeterminate(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "adm-indet-"+uid)
	rootKey := createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "adm-indet-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			ProbeType:       siderealv1alpha1.ProbeTypeAdmission,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
		},
	})

	probeID := uid + "dddd-dddd-dddd-dddddddddddd"
	simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeTypeAdmission),
		probe.Name, ns, string(siderealv1alpha1.OutcomeIndeterminate), "No webhook evaluation in response", rootKey)

	result := waitForProbeResult(t, probeID, 10*time.Second)

	if result.Spec.Result.Outcome != siderealv1alpha1.OutcomeIndeterminate {
		t.Errorf("expected Indeterminate, got %s", result.Spec.Result.Outcome)
	}
	if result.Spec.Result.ControlEffectiveness != siderealv1alpha1.EffectivenessDegraded {
		t.Errorf("expected Degraded, got %s", result.Spec.Result.ControlEffectiveness)
	}
}
