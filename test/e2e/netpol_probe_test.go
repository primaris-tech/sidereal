package e2e

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/controller"
)

// SAP: TEST-AC-03 (NetworkPolicy probe)
func TestNetPolProbe_Blocked(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "netpol-blk-"+uid)
	rootKey := createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "netpol-blk-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			ProbeType:       siderealv1alpha1.ProbeTypeNetPol,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
			ControlMappings: map[string][]string{
				"nist-800-53": {"SC-7", "AC-4"},
			},
		},
	})

	probeID := uid + "eeee-eeee-eeee-eeeeeeeeeeee"
	simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeTypeNetPol),
		probe.Name, ns, string(siderealv1alpha1.OutcomeBlocked), "NetworkPolicy blocked cross-namespace flow", rootKey)

	result := waitForProbeResult(t, probeID, 10*time.Second)

	if result.Spec.Result.Outcome != siderealv1alpha1.OutcomeBlocked {
		t.Errorf("expected Blocked, got %s", result.Spec.Result.Outcome)
	}
	if result.Spec.Result.ControlEffectiveness != siderealv1alpha1.EffectivenessEffective {
		t.Errorf("expected Effective, got %s", result.Spec.Result.ControlEffectiveness)
	}
}

// SAP: TEST-SYS-04 (NetworkPolicy default-deny)
func TestNetPolProbe_NotEnforced(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "netpol-ne-"+uid)
	rootKey := createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "netpol-ne-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			ProbeType:       siderealv1alpha1.ProbeTypeNetPol,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
			ControlMappings: map[string][]string{
				"nist-800-53": {"SC-7"},
			},
		},
	})

	probeID := uid + "ffff-ffff-ffff-ffffffffffff"
	simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeTypeNetPol),
		probe.Name, ns, string(siderealv1alpha1.OutcomeNotEnforced), "NetworkPolicy not enforced by CNI", rootKey)

	result := waitForProbeResult(t, probeID, 10*time.Second)

	if result.Spec.Result.Outcome != siderealv1alpha1.OutcomeNotEnforced {
		t.Errorf("expected NotEnforced, got %s", result.Spec.Result.Outcome)
	}
	if result.Spec.Result.ControlEffectiveness != siderealv1alpha1.EffectivenessIneffective {
		t.Errorf("expected Ineffective, got %s", result.Spec.Result.ControlEffectiveness)
	}
}

func TestNetPolProbe_BackendUnreachable(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "netpol-bu-"+uid)
	rootKey := createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "netpol-bu-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			ProbeType:       siderealv1alpha1.ProbeTypeNetPol,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
		},
	})

	probeID := uid + "abab-abab-abab-abababababab"
	simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeTypeNetPol),
		probe.Name, ns, string(siderealv1alpha1.OutcomeBackendUnreachable), "Hubble endpoint unreachable", rootKey)

	result := waitForProbeResult(t, probeID, 10*time.Second)

	if result.Spec.Result.ControlEffectiveness != siderealv1alpha1.EffectivenessDegraded {
		t.Errorf("expected Degraded, got %s", result.Spec.Result.ControlEffectiveness)
	}
}
