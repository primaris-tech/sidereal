package e2e

import (
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/controller"
)

func TestDetectionProbe_RequiresAOAuthorization(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "det-noauth-"+uid)
	createHMACRootSecret(t)

	// Create detection probe WITHOUT an AO authorization.
	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "det-noauth-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:            siderealv1alpha1.ProbeProfileDetection,
			TargetNamespace:    ns,
			ExecutionMode:      siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds:    300,
			MitreAttackID:      "T1053.007",
			AOAuthorizationRef: "nonexistent-auth",
		},
	})

	// Wait and verify no Job is created (no active AO authorization).
	time.Sleep(5 * time.Second)

	var jobs batchv1.JobList
	if err := k8sClient.List(ctx, &jobs,
		client.InNamespace(controller.SystemNamespace),
		client.MatchingLabels{controller.ProbeNameLabel: probe.Name},
	); err != nil {
		t.Fatalf("failed to list jobs: %v", err)
	}

	if len(jobs.Items) > 0 {
		t.Error("detection probe should not create Jobs without active AO authorization")
	}
}

func TestDetectionProbe_WithActiveAuthorization(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "det-auth-"+uid)
	rootKey := createHMACRootSecret(t)

	// Create an active AO authorization.
	now := time.Now()
	auth := &siderealv1alpha1.SiderealAOAuthorization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "det-auth-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealAOAuthorizationSpec{
			AOName:               "ISSO Jane Smith",
			AuthorizedTechniques: []string{"T1053.007"},
			AuthorizedNamespaces: []string{ns},
			ValidFrom:            metav1.NewTime(now.Add(-1 * time.Hour)),
			ExpiresAt:            metav1.NewTime(now.Add(24 * time.Hour)),
			Justification:        "Authorized for continuous monitoring test",
			CatalogVersion:       "1.0",
		},
	}
	if err := k8sClient.Create(ctx, auth); err != nil {
		t.Fatalf("failed to create AO authorization: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, auth) })

	// Wait for authorization status to be computed.
	time.Sleep(2 * time.Second)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "det-auth-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:            siderealv1alpha1.ProbeProfileDetection,
			TargetNamespace:    ns,
			ExecutionMode:      siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds:    300,
			MitreAttackID:      "T1053.007",
			AOAuthorizationRef: auth.Name,
		},
	})

	// Simulate detection result.
	probeID := uid + "dede-dede-dede-dededededede"
	simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeProfileDetection),
		probe.Name, ns, string(siderealv1alpha1.OutcomeDetected), "Falco alert correlated for T1053.007", rootKey)

	result := waitForProbeResult(t, probeID, 10*time.Second)

	if result.Spec.Result.Outcome != siderealv1alpha1.OutcomeDetected {
		t.Errorf("expected Detected, got %s", result.Spec.Result.Outcome)
	}
	if result.Spec.Result.ControlEffectiveness != siderealv1alpha1.EffectivenessEffective {
		t.Errorf("expected Effective, got %s", result.Spec.Result.ControlEffectiveness)
	}
}

func TestDetectionProbe_Undetected(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "det-undet-"+uid)
	rootKey := createHMACRootSecret(t)

	now := time.Now()
	auth := &siderealv1alpha1.SiderealAOAuthorization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "det-undet-auth-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealAOAuthorizationSpec{
			AOName:               "ISSO Jane Smith",
			AuthorizedTechniques: []string{"T1059.004"},
			AuthorizedNamespaces: []string{ns},
			ValidFrom:            metav1.NewTime(now.Add(-1 * time.Hour)),
			ExpiresAt:            metav1.NewTime(now.Add(24 * time.Hour)),
			Justification:        "Detection coverage test",
			CatalogVersion:       "1.0",
		},
	}
	if err := k8sClient.Create(ctx, auth); err != nil {
		t.Fatalf("failed to create AO authorization: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, auth) })

	time.Sleep(2 * time.Second)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "det-undet-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:            siderealv1alpha1.ProbeProfileDetection,
			TargetNamespace:    ns,
			ExecutionMode:      siderealv1alpha1.ExecutionModeEnforce,
			IntervalSeconds:    300,
			MitreAttackID:      "T1059.004",
			AOAuthorizationRef: auth.Name,
			ControlMappings: map[string][]string{
				"nist-800-53": {"SI-4"},
			},
		},
	})

	probeID := uid + "fafa-fafa-fafa-fafafafafafa"
	simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeProfileDetection),
		probe.Name, ns, string(siderealv1alpha1.OutcomeUndetected), "No Falco alert within verification window", rootKey)

	result := waitForProbeResult(t, probeID, 10*time.Second)

	if result.Spec.Result.ControlEffectiveness != siderealv1alpha1.EffectivenessIneffective {
		t.Errorf("expected Ineffective, got %s", result.Spec.Result.ControlEffectiveness)
	}

	// Enforce + Ineffective -> incident.
	incident := waitForIncident(t, probeID, 10*time.Second)
	if incident.Spec.Severity != siderealv1alpha1.SeverityHigh {
		t.Errorf("expected High severity, got %s", incident.Spec.Severity)
	}
}
