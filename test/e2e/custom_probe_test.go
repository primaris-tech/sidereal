package e2e

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/controller"
)

func TestCustomProbe_ExecutesWithRegisteredSA(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "custom-ok-"+uid)
	rootKey := createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "custom-ok-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			ProbeType:       siderealv1alpha1.ProbeTypeCustom,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
			CustomProbe: &siderealv1alpha1.CustomProbeConfig{
				Image:              "ghcr.io/primaris-tech/custom-probe@sha256:abcdef1234567890",
				ServiceAccountName: "sidereal-probe-custom-test",
				Config:             &runtime.RawExtension{Raw: []byte(`{"checkType":"compliance"}`)},
			},
			ControlMappings: map[string][]string{
				"nist-800-53": {"CA-7"},
			},
		},
	})

	probeID := uid + "caca-caca-caca-cacacacacaca"
	simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeTypeCustom),
		probe.Name, ns, string(siderealv1alpha1.OutcomePass), "Custom compliance check passed", rootKey)

	result := waitForProbeResult(t, probeID, 10*time.Second)

	if result.Spec.Result.Outcome != siderealv1alpha1.OutcomePass {
		t.Errorf("expected Pass, got %s", result.Spec.Result.Outcome)
	}
	if result.Spec.Probe.Type != siderealv1alpha1.ProbeTypeCustom {
		t.Errorf("expected custom probe type, got %s", result.Spec.Probe.Type)
	}
}

func TestCustomProbe_SameSecurityControls(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "custom-sec-"+uid)
	rootKey := createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "custom-sec-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			ProbeType:       siderealv1alpha1.ProbeTypeCustom,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeEnforce,
			IntervalSeconds: 300,
			CustomProbe: &siderealv1alpha1.CustomProbeConfig{
				Image:              "ghcr.io/primaris-tech/custom-probe@sha256:abcdef1234567890",
				ServiceAccountName: "sidereal-probe-custom-test",
			},
			ControlMappings: map[string][]string{
				"nist-800-53": {"CA-7"},
			},
		},
	})

	// Custom probes produce the same result types and go through the same HMAC pipeline.
	probeID := uid + "cbcb-cbcb-cbcb-cbcbcbcbcbcb"
	simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeTypeCustom),
		probe.Name, ns, string(siderealv1alpha1.OutcomeFail), "Custom check failed", rootKey)

	result := waitForProbeResult(t, probeID, 10*time.Second)

	// Verify HMAC integrity applies to custom probes too.
	if result.Spec.Result.IntegrityStatus != siderealv1alpha1.IntegrityVerified {
		t.Errorf("expected IntegrityVerified for custom probe, got %s", result.Spec.Result.IntegrityStatus)
	}

	// Verify incident creation works for custom probes in enforce mode.
	incident := waitForIncident(t, probeID, 10*time.Second)
	if incident.Spec.ProbeType != siderealv1alpha1.ProbeTypeCustom {
		t.Errorf("expected custom probe type in incident, got %s", incident.Spec.ProbeType)
	}
}
