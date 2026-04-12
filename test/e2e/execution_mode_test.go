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

func TestExecutionMode_DryRunNoJob(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "exec-dry-"+uid)
	createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "exec-dry-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			ProbeType:       siderealv1alpha1.ProbeTypeRBAC,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeDryRun,
			IntervalSeconds: 300,
		},
	})

	time.Sleep(3 * time.Second)

	var jobs batchv1.JobList
	if err := k8sClient.List(ctx, &jobs,
		client.InNamespace(controller.SystemNamespace),
		client.MatchingLabels{controller.ProbeNameLabel: probe.Name},
	); err != nil {
		t.Fatalf("failed to list jobs: %v", err)
	}

	if len(jobs.Items) != 0 {
		t.Errorf("dryRun should not create Jobs, got %d", len(jobs.Items))
	}
}

func TestExecutionMode_ObserveCreatesJobNoIncident(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "exec-obs-"+uid)
	rootKey := createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "exec-obs-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			ProbeType:       siderealv1alpha1.ProbeTypeRBAC,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
			ControlMappings: map[string][]string{
				"nist-800-53": {"AC-6(5)"},
			},
		},
	})

	// Wait for Job creation.
	deadline := time.Now().Add(10 * time.Second)
	var jobs batchv1.JobList
	for time.Now().Before(deadline) {
		if err := k8sClient.List(ctx, &jobs,
			client.InNamespace(controller.SystemNamespace),
			client.MatchingLabels{controller.ProbeNameLabel: probe.Name},
		); err == nil && len(jobs.Items) > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if len(jobs.Items) == 0 {
		t.Fatal("observe mode should create Jobs")
	}

	// Simulate a failing result.
	probeID := uid + "4444-4444-4444-444444444444"
	simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeTypeRBAC),
		probe.Name, ns, string(siderealv1alpha1.OutcomeFail), "RBAC deny not enforced", rootKey)

	result := waitForProbeResult(t, probeID, 10*time.Second)

	if result.Spec.Result.ControlEffectiveness != siderealv1alpha1.EffectivenessIneffective {
		t.Errorf("expected Ineffective, got %s", result.Spec.Result.ControlEffectiveness)
	}

	// In observe mode, no incident should be created even for Ineffective results.
	time.Sleep(3 * time.Second)

	var incidents siderealv1alpha1.SiderealIncidentList
	if err := k8sClient.List(ctx, &incidents,
		client.InNamespace(controller.SystemNamespace),
		client.MatchingLabels{controller.FingerprintLabel: probeID},
	); err != nil {
		t.Fatalf("failed to list incidents: %v", err)
	}

	if len(incidents.Items) > 0 {
		t.Error("observe mode should not create incidents")
	}
}

func TestExecutionMode_EnforceCreatesIncident(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "exec-enf-"+uid)
	rootKey := createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "exec-enf-" + uid,
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

	probeID := uid + "5555-5555-5555-555555555555"
	simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeTypeRBAC),
		probe.Name, ns, string(siderealv1alpha1.OutcomeFail), "RBAC deny not enforced", rootKey)

	// Wait for ProbeResult.
	result := waitForProbeResult(t, probeID, 10*time.Second)

	if result.Spec.Result.ControlEffectiveness != siderealv1alpha1.EffectivenessIneffective {
		t.Errorf("expected Ineffective, got %s", result.Spec.Result.ControlEffectiveness)
	}

	// In enforce mode, an incident should be created for Ineffective results.
	incident := waitForIncident(t, probeID, 10*time.Second)

	if incident.Spec.Severity != siderealv1alpha1.SeverityHigh {
		t.Errorf("expected High severity for Ineffective, got %s", incident.Spec.Severity)
	}
	if incident.Spec.ControlEffectiveness != siderealv1alpha1.EffectivenessIneffective {
		t.Errorf("expected Ineffective effectiveness, got %s", incident.Spec.ControlEffectiveness)
	}
	if incident.Spec.RemediationStatus != siderealv1alpha1.RemediationOpen {
		t.Errorf("expected Open remediation status, got %s", incident.Spec.RemediationStatus)
	}
}
