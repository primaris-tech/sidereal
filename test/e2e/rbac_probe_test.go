package e2e

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/controller"
)

// SAP: TEST-AC-01 (RBAC probe)
func TestRBACProbe_DenyPathVerification(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "rbac-deny-"+uid)
	rootKey := createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rbac-deny-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:         siderealv1alpha1.ProbeProfileRBAC,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
			MitreAttackID:   "T1078.001",
			ControlMappings: map[string][]string{
				"nist-800-53": {"AC-6(5)", "AC-2"},
			},
		},
	})

	// Simulate a Pass result (deny path was enforced).
	probeID := uid + "7777-7777-7777-777777777777"
	simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeProfileRBAC),
		probe.Name, ns, string(siderealv1alpha1.OutcomePass), "SelfSubjectAccessReview denied as expected", rootKey)

	result := waitForProbeResult(t, probeID, 10*time.Second)

	if result.Spec.Result.Outcome != siderealv1alpha1.OutcomePass {
		t.Errorf("expected Pass, got %s", result.Spec.Result.Outcome)
	}
	if result.Spec.Result.ControlEffectiveness != siderealv1alpha1.EffectivenessEffective {
		t.Errorf("expected Effective, got %s", result.Spec.Result.ControlEffectiveness)
	}
	if result.Spec.Probe.TargetNamespace != ns {
		t.Errorf("expected target namespace %s, got %s", ns, result.Spec.Probe.TargetNamespace)
	}
}

// SAP: TEST-AC-01 (RBAC probe - allow path)
func TestRBACProbe_AllowPathVerification(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "rbac-allow-"+uid)
	rootKey := createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rbac-allow-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:         siderealv1alpha1.ProbeProfileRBAC,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeEnforce,
			IntervalSeconds: 300,
			ControlMappings: map[string][]string{
				"nist-800-53": {"AC-6(5)"},
			},
		},
	})

	// Simulate a Fail result (deny path was NOT enforced, access was allowed).
	probeID := uid + "8888-8888-8888-888888888888"
	simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeProfileRBAC),
		probe.Name, ns, string(siderealv1alpha1.OutcomeFail), "SelfSubjectAccessReview allowed unexpectedly", rootKey)

	result := waitForProbeResult(t, probeID, 10*time.Second)

	if result.Spec.Result.Outcome != siderealv1alpha1.OutcomeFail {
		t.Errorf("expected Fail, got %s", result.Spec.Result.Outcome)
	}
	if result.Spec.Result.ControlEffectiveness != siderealv1alpha1.EffectivenessIneffective {
		t.Errorf("expected Ineffective, got %s", result.Spec.Result.ControlEffectiveness)
	}

	// Enforce mode + Ineffective should create an incident.
	incident := waitForIncident(t, probeID, 10*time.Second)

	if incident.Spec.Profile != siderealv1alpha1.ProbeProfileRBAC {
		t.Errorf("expected probe type rbac, got %s", incident.Spec.Profile)
	}
	if incident.Spec.TargetNamespace != ns {
		t.Errorf("expected target namespace %s, got %s", ns, incident.Spec.TargetNamespace)
	}
}
