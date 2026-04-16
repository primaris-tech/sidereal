package e2e

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/controller"
)

func TestResultReconciler_CreatesProbeResult(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "result-ok-"+uid)
	rootKey := createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "result-ok-" + uid,
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

	probeID := uid + "0000-0000-0000-000000000000"
	simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeProfileRBAC),
		probe.Name, ns, string(siderealv1alpha1.OutcomePass), "RBAC deny verified", rootKey)

	result := waitForProbeResult(t, probeID, 10*time.Second)

	// Verify result fields.
	if result.Spec.Result.Outcome != siderealv1alpha1.OutcomePass {
		t.Errorf("expected outcome Pass, got %s", result.Spec.Result.Outcome)
	}
	if result.Spec.Result.ControlEffectiveness != siderealv1alpha1.EffectivenessEffective {
		t.Errorf("expected Effective, got %s", result.Spec.Result.ControlEffectiveness)
	}
	if result.Spec.Result.IntegrityStatus != siderealv1alpha1.IntegrityVerified {
		t.Errorf("expected integrity Verified, got %s", result.Spec.Result.IntegrityStatus)
	}
	if result.Spec.Probe.Profile != siderealv1alpha1.ProbeProfileRBAC {
		t.Errorf("expected probe type rbac, got %s", result.Spec.Probe.Profile)
	}
	if result.Spec.Probe.TargetNamespace != ns {
		t.Errorf("expected target namespace %s, got %s", ns, result.Spec.Probe.TargetNamespace)
	}
	if result.Spec.Audit.ExportStatus != siderealv1alpha1.ExportStatusPending {
		t.Errorf("expected export status Pending, got %s", result.Spec.Audit.ExportStatus)
	}
}

func TestResultReconciler_Idempotency(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "result-idem-"+uid)
	rootKey := createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "result-idem-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:         siderealv1alpha1.ProbeProfileRBAC,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
		},
	})

	probeID := uid + "1111-1111-1111-111111111111"
	simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeProfileRBAC),
		probe.Name, ns, string(siderealv1alpha1.OutcomePass), "first run", rootKey)

	result := waitForProbeResult(t, probeID, 10*time.Second)

	// Wait a bit and verify only one ProbeResult exists.
	time.Sleep(2 * time.Second)

	var results siderealv1alpha1.SiderealProbeResultList
	if err := k8sClient.List(ctx, &results,
		client.MatchingLabels{controller.FingerprintLabel: probeID},
	); err != nil {
		t.Fatalf("failed to list results: %v", err)
	}

	if len(results.Items) != 1 {
		t.Errorf("expected exactly 1 ProbeResult, got %d", len(results.Items))
	}

	_ = result
}
