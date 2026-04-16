package controller

import (
	"context"
	"encoding/json"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/crosswalk"
	siderealhmac "github.com/primaris-tech/sidereal/internal/hmac"
)

const testProbeID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

func createSignedResultCM(t *testing.T, hmacKey []byte, outcome, detail string) (*corev1.ConfigMap, string) {
	t.Helper()

	result := ProbeRunnerResult{
		Outcome:    outcome,
		Detail:     detail,
		DurationMs: 150,
	}
	payload, _ := json.Marshal(result)
	sig, err := siderealhmac.SignResult(hmacKey, payload)
	if err != nil {
		t.Fatalf("failed to sign result: %v", err)
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sidereal-result-" + testProbeID[:8],
			Namespace: SystemNamespace,
		},
		Data: map[string]string{
			"result": string(payload),
			"hmac":   sig,
		},
	}
	return cm, sig
}

func createCompletedJob(probeType, probeName, targetNS string) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sidereal-probe-" + testProbeID[:8],
			Namespace: SystemNamespace,
			Labels: map[string]string{
				FingerprintLabel:     testProbeID,
				ProbeTypeLabel:       probeType,
				ProbeNameLabel:       probeName,
				TargetNamespaceLabel: targetNS,
			},
		},
		Status: batchv1.JobStatus{
			Conditions: []batchv1.JobCondition{
				{
					Type:   batchv1.JobComplete,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}
}

func TestResultReconciler_ValidResult(t *testing.T) {
	scheme := newTestScheme()

	rootKey := []byte("test-root-key-32-bytes-long!!!!")
	execKey, _ := siderealhmac.DeriveExecutionKey(rootKey, testProbeID)

	probe := &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rbac-probe",
			Namespace: SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:         siderealv1alpha1.ProbeProfileRBAC,
			TargetNamespace: "production",
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
			ControlMappings: map[string][]string{
				"nist-800-53": {"AC-3", "AC-6"},
			},
		},
	}

	job := createCompletedJob("rbac", "test-rbac-probe", "production")
	resultCM, _ := createSignedResultCM(t, execKey, "Pass", "RBAC boundaries enforced")

	hmacSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sidereal-hmac-" + testProbeID[:8],
			Namespace: SystemNamespace,
		},
		Data: map[string][]byte{
			"hmac-key": execKey,
		},
	}

	// Set up crosswalk.
	resolver := crosswalk.NewResolver()
	_ = resolver.LoadFramework([]byte(`{
		"framework_id": "cmmc",
		"crosswalk_version": "1.0.0",
		"mappings": [
			{"probe_type": "rbac", "nist_control": "AC-3", "control_ids": ["AC.L2-3.1.1"]},
			{"probe_type": "rbac", "nist_control": "AC-6", "control_ids": ["AC.L2-3.1.5"]}
		]
	}`))

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(job, resultCM, hmacSecret, probe).
		WithStatusSubresource(probe).
		Build()

	reconciler := &ResultReconciler{Client: c, Crosswalk: resolver}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      job.Name,
			Namespace: SystemNamespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// Verify ProbeResult was created.
	var results siderealv1alpha1.SiderealProbeResultList
	if err := c.List(context.Background(), &results); err != nil {
		t.Fatalf("failed to list results: %v", err)
	}
	if len(results.Items) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results.Items))
	}

	result := results.Items[0]

	// Verify fields.
	if result.Spec.Result.Outcome != siderealv1alpha1.OutcomePass {
		t.Errorf("expected outcome Pass, got %s", result.Spec.Result.Outcome)
	}
	if result.Spec.Result.ControlEffectiveness != siderealv1alpha1.EffectivenessEffective {
		t.Errorf("expected Effective, got %s", result.Spec.Result.ControlEffectiveness)
	}
	if result.Spec.Result.IntegrityStatus != siderealv1alpha1.IntegrityVerified {
		t.Errorf("expected Verified, got %s", result.Spec.Result.IntegrityStatus)
	}
	if result.Spec.Result.Detail != "RBAC boundaries enforced" {
		t.Errorf("unexpected detail: %s", result.Spec.Result.Detail)
	}

	// Verify crosswalk mappings.
	nist := result.Spec.Result.ControlMappings["nist-800-53"]
	if len(nist) != 2 {
		t.Errorf("expected 2 NIST controls, got %v", nist)
	}
	cmmc := result.Spec.Result.ControlMappings["cmmc"]
	if len(cmmc) != 2 {
		t.Errorf("expected 2 CMMC controls, got %v", cmmc)
	}
	if result.Spec.Result.CrosswalkVersion == "" {
		t.Error("expected crosswalkVersion to be set")
	}

	// Verify labels.
	if result.Labels["sidereal.cloud/outcome"] != "Pass" {
		t.Errorf("expected outcome label 'Pass', got %q", result.Labels["sidereal.cloud/outcome"])
	}
	if result.Labels["sidereal.cloud/control-effectiveness"] != "Effective" {
		t.Errorf("expected effectiveness label 'Effective', got %q", result.Labels["sidereal.cloud/control-effectiveness"])
	}

	// Verify no SystemAlert was created.
	var alerts siderealv1alpha1.SiderealSystemAlertList
	if err := c.List(context.Background(), &alerts); err != nil {
		t.Fatalf("failed to list alerts: %v", err)
	}
	if len(alerts.Items) != 0 {
		t.Errorf("expected 0 alerts for valid result, got %d", len(alerts.Items))
	}
}

func TestResultReconciler_TamperedResult(t *testing.T) {
	scheme := newTestScheme()

	rootKey := []byte("test-root-key-32-bytes-long!!!!")
	execKey, _ := siderealhmac.DeriveExecutionKey(rootKey, testProbeID)

	probe := &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rbac-probe",
			Namespace: SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:         siderealv1alpha1.ProbeProfileRBAC,
			TargetNamespace: "production",
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
		},
	}

	job := createCompletedJob("rbac", "test-rbac-probe", "production")

	// Create a result with a WRONG signature.
	resultPayload := `{"outcome":"Pass","detail":"looks legit","durationMs":100}`
	tamperedCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sidereal-result-" + testProbeID[:8],
			Namespace: SystemNamespace,
		},
		Data: map[string]string{
			"result": resultPayload,
			"hmac":   "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		},
	}

	hmacSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sidereal-hmac-" + testProbeID[:8],
			Namespace: SystemNamespace,
		},
		Data: map[string][]byte{
			"hmac-key": execKey,
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(job, tamperedCM, hmacSecret, probe).
		WithStatusSubresource(probe).
		Build()

	reconciler := &ResultReconciler{Client: c, Crosswalk: crosswalk.NewResolver()}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      job.Name,
			Namespace: SystemNamespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// Verify ProbeResult with TamperedResult outcome.
	var results siderealv1alpha1.SiderealProbeResultList
	if err := c.List(context.Background(), &results); err != nil {
		t.Fatalf("failed to list results: %v", err)
	}
	if len(results.Items) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results.Items))
	}

	result := results.Items[0]
	if result.Spec.Result.Outcome != siderealv1alpha1.OutcomeTamperedResult {
		t.Errorf("expected TamperedResult, got %s", result.Spec.Result.Outcome)
	}
	if result.Spec.Result.ControlEffectiveness != siderealv1alpha1.EffectivenessCompromised {
		t.Errorf("expected Compromised, got %s", result.Spec.Result.ControlEffectiveness)
	}
	if result.Spec.Result.IntegrityStatus != siderealv1alpha1.IntegrityTamperedResult {
		t.Errorf("expected TamperedResult integrity, got %s", result.Spec.Result.IntegrityStatus)
	}

	// Verify SystemAlert was created.
	var alerts siderealv1alpha1.SiderealSystemAlertList
	if err := c.List(context.Background(), &alerts); err != nil {
		t.Fatalf("failed to list alerts: %v", err)
	}
	if len(alerts.Items) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts.Items))
	}
	if alerts.Items[0].Spec.Reason != siderealv1alpha1.AlertReasonTamperedResult {
		t.Errorf("expected TamperedResult reason, got %s", alerts.Items[0].Spec.Reason)
	}
}

func TestResultReconciler_SkipsNonProbeJobs(t *testing.T) {
	scheme := newTestScheme()

	// A Job without the fingerprint label.
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "some-other-job",
			Namespace: SystemNamespace,
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(job).
		Build()

	reconciler := &ResultReconciler{Client: c, Crosswalk: crosswalk.NewResolver()}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      job.Name,
			Namespace: SystemNamespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile should not error for non-probe jobs: %v", err)
	}
}

func TestResultReconciler_SkipsIncompleteJobs(t *testing.T) {
	scheme := newTestScheme()

	// A probe Job that hasn't completed yet.
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sidereal-probe-running",
			Namespace: SystemNamespace,
			Labels: map[string]string{
				FingerprintLabel: testProbeID,
				ProbeTypeLabel:   "rbac",
			},
		},
		Status: batchv1.JobStatus{}, // no completion condition
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(job).
		Build()

	reconciler := &ResultReconciler{Client: c, Crosswalk: crosswalk.NewResolver()}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      job.Name,
			Namespace: SystemNamespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile should not error for incomplete jobs: %v", err)
	}

	// No results should be created.
	var results siderealv1alpha1.SiderealProbeResultList
	_ = c.List(context.Background(), &results)
	if len(results.Items) != 0 {
		t.Errorf("expected 0 results for incomplete job, got %d", len(results.Items))
	}
}

func TestResultReconciler_IdempotentOnDuplicate(t *testing.T) {
	scheme := newTestScheme()

	rootKey := []byte("test-root-key-32-bytes-long!!!!")
	execKey, _ := siderealhmac.DeriveExecutionKey(rootKey, testProbeID)

	job := createCompletedJob("rbac", "test-rbac-probe", "production")
	resultCM, _ := createSignedResultCM(t, execKey, "Pass", "ok")

	hmacSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sidereal-hmac-" + testProbeID[:8],
			Namespace: SystemNamespace,
		},
		Data: map[string][]byte{"hmac-key": execKey},
	}

	// Pre-existing result (already processed).
	existingResult := &siderealv1alpha1.SiderealProbeResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-result",
			Namespace: SystemNamespace,
			Labels: map[string]string{
				FingerprintLabel: testProbeID,
			},
		},
	}

	probe := &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rbac-probe",
			Namespace: SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:         siderealv1alpha1.ProbeProfileRBAC,
			TargetNamespace: "production",
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(job, resultCM, hmacSecret, existingResult, probe).
		WithStatusSubresource(probe).
		Build()

	reconciler := &ResultReconciler{Client: c, Crosswalk: crosswalk.NewResolver()}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      job.Name,
			Namespace: SystemNamespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// Should still have only the 1 pre-existing result.
	var results siderealv1alpha1.SiderealProbeResultList
	_ = c.List(context.Background(), &results)
	if len(results.Items) != 1 {
		t.Errorf("expected 1 result (idempotent), got %d", len(results.Items))
	}
}
