package e2e

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/controller"
)

// SAP: TEST-AC-02 (Secret probe - cross-namespace access denial)
func TestSecretProbe_CrossNamespaceDenial(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "secret-deny-"+uid)
	rootKey := createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret-deny-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:         siderealv1alpha1.ProbeProfileSecret,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
			ControlMappings: map[string][]string{
				"nist-800-53": {"SC-28", "AC-3"},
			},
		},
	})

	probeID := uid + "9999-9999-9999-999999999999"
	simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeProfileSecret),
		probe.Name, ns, string(siderealv1alpha1.OutcomePass), "Cross-namespace Secret read denied", rootKey)

	result := waitForProbeResult(t, probeID, 10*time.Second)

	if result.Spec.Result.Outcome != siderealv1alpha1.OutcomePass {
		t.Errorf("expected Pass, got %s", result.Spec.Result.Outcome)
	}
	if result.Spec.Probe.Profile != siderealv1alpha1.ProbeProfileSecret {
		t.Errorf("expected secret probe type, got %s", result.Spec.Probe.Profile)
	}
}

func TestSecretProbe_AccessAllowed(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "secret-allow-"+uid)
	rootKey := createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret-allow-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:         siderealv1alpha1.ProbeProfileSecret,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeEnforce,
			IntervalSeconds: 300,
			ControlMappings: map[string][]string{
				"nist-800-53": {"SC-28"},
			},
		},
	})

	probeID := uid + "aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeProfileSecret),
		probe.Name, ns, string(siderealv1alpha1.OutcomeFail), "Cross-namespace Secret read was permitted", rootKey)

	result := waitForProbeResult(t, probeID, 10*time.Second)

	if result.Spec.Result.ControlEffectiveness != siderealv1alpha1.EffectivenessIneffective {
		t.Errorf("expected Ineffective, got %s", result.Spec.Result.ControlEffectiveness)
	}

	incident := waitForIncident(t, probeID, 10*time.Second)
	if incident.Spec.Severity != siderealv1alpha1.SeverityHigh {
		t.Errorf("expected High severity, got %s", incident.Spec.Severity)
	}
}
