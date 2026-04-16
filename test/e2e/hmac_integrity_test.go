package e2e

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/controller"
	siderealhmac "github.com/primaris-tech/sidereal/internal/hmac"
)

// SAP: TEST-SYS-02 (HMAC integrity)
func TestHMACIntegrity_ValidSignature(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "hmac-valid-"+uid)
	rootKey := createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "hmac-valid-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:         siderealv1alpha1.ProbeProfileRBAC,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
		},
	})

	probeID := uid + "2222-2222-2222-222222222222"
	simulateProbeResult(t, probeID, string(siderealv1alpha1.ProbeProfileRBAC),
		probe.Name, ns, string(siderealv1alpha1.OutcomePass), "HMAC valid test", rootKey)

	result := waitForProbeResult(t, probeID, 10*time.Second)

	if result.Spec.Result.IntegrityStatus != siderealv1alpha1.IntegrityVerified {
		t.Errorf("expected IntegrityVerified, got %s", result.Spec.Result.IntegrityStatus)
	}
	if result.Spec.Result.Outcome != siderealv1alpha1.OutcomePass {
		t.Errorf("expected Pass outcome, got %s", result.Spec.Result.Outcome)
	}
}

// SAP: TEST-SYS-02 (HMAC tamper detection)
func TestHMACIntegrity_TamperedResult(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "hmac-tamper-"+uid)
	rootKey := createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "hmac-tamper-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:         siderealv1alpha1.ProbeProfileRBAC,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
		},
	})

	probeID := uid + "3333-3333-3333-333333333333"
	shortID := probeID[:8]

	// Derive key and create a valid signature.
	execKey, err := siderealhmac.DeriveExecutionKey(rootKey, probeID)
	if err != nil {
		t.Fatalf("failed to derive key: %v", err)
	}

	resultPayload := controller.ProbeRunnerResult{
		Outcome:    string(siderealv1alpha1.OutcomePass),
		Detail:     "original payload",
		DurationMs: 10,
	}
	resultJSON, _ := json.Marshal(resultPayload)

	sig, err := siderealhmac.SignResult(execKey, resultJSON)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Tamper with the result payload after signing.
	tamperedPayload := controller.ProbeRunnerResult{
		Outcome:    string(siderealv1alpha1.OutcomePass),
		Detail:     "TAMPERED payload",
		DurationMs: 10,
	}
	tamperedJSON, _ := json.Marshal(tamperedPayload)

	// Create result ConfigMap with tampered payload but original signature.
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("sidereal-result-%s", shortID),
			Namespace: controller.SystemNamespace,
		},
		Data: map[string]string{
			"result": string(tamperedJSON),
			"hmac":   sig,
		},
	}
	if err := k8sClient.Create(ctx, cm); err != nil {
		t.Fatalf("failed to create tampered ConfigMap: %v", err)
	}

	// Create HMAC key Secret.
	hmacSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("sidereal-hmac-%s", shortID),
			Namespace: controller.SystemNamespace,
		},
		Data: map[string][]byte{
			"hmac-key": execKey,
		},
	}
	if err := k8sClient.Create(ctx, hmacSecret); err != nil {
		t.Fatalf("failed to create HMAC secret: %v", err)
	}

	// Create a completed Job to trigger reconciliation.
	ttl := int32(controller.JobTTLSeconds)
	completionTime := metav1.Now()
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("sidereal-probe-%s", shortID),
			Namespace: controller.SystemNamespace,
			Labels: map[string]string{
				controller.FingerprintLabel:     probeID,
				controller.ProbeTypeLabel:       string(siderealv1alpha1.ProbeProfileRBAC),
				controller.ProbeNameLabel:       probe.Name,
				controller.TargetNamespaceLabel: ns,
			},
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: &ttl,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					Containers: []corev1.Container{
						{Name: "probe", Image: "ghcr.io/primaris-tech/sidereal-probe-go:latest"},
					},
				},
			},
		},
		Status: batchv1.JobStatus{
			Conditions: []batchv1.JobCondition{
				{Type: batchv1.JobComplete, Status: corev1.ConditionTrue},
			},
			CompletionTime: &completionTime,
		},
	}
	if err := k8sClient.Create(ctx, job); err != nil {
		t.Fatalf("failed to create Job: %v", err)
	}
	t.Cleanup(func() {
		_ = k8sClient.Delete(ctx, job)
	})

	// Wait for the ProbeResult - should be TamperedResult.
	result := waitForProbeResult(t, probeID, 10*time.Second)

	if result.Spec.Result.Outcome != siderealv1alpha1.OutcomeTamperedResult {
		t.Errorf("expected TamperedResult outcome, got %s", result.Spec.Result.Outcome)
	}
	if result.Spec.Result.IntegrityStatus != siderealv1alpha1.IntegrityTamperedResult {
		t.Errorf("expected TamperedResult integrity status, got %s", result.Spec.Result.IntegrityStatus)
	}
	if result.Spec.Result.ControlEffectiveness != siderealv1alpha1.EffectivenessCompromised {
		t.Errorf("expected Compromised effectiveness, got %s", result.Spec.Result.ControlEffectiveness)
	}
}

func TestHMACIntegrity_KeyDerivationDeterministic(t *testing.T) {
	rootKey := make([]byte, 32)
	if _, err := rand.Read(rootKey); err != nil {
		t.Fatalf("failed to generate root key: %v", err)
	}

	probeID := "test-probe-deterministic-key"

	key1, err := siderealhmac.DeriveExecutionKey(rootKey, probeID)
	if err != nil {
		t.Fatalf("first derivation failed: %v", err)
	}

	key2, err := siderealhmac.DeriveExecutionKey(rootKey, probeID)
	if err != nil {
		t.Fatalf("second derivation failed: %v", err)
	}

	if string(key1) != string(key2) {
		t.Error("same root key + probe ID should produce identical execution keys")
	}

	// Different probeID should produce different key.
	key3, err := siderealhmac.DeriveExecutionKey(rootKey, "different-probe-id")
	if err != nil {
		t.Fatalf("third derivation failed: %v", err)
	}

	if string(key1) == string(key3) {
		t.Error("different probe IDs should produce different execution keys")
	}
}
