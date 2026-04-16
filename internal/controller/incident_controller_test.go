package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/webhook"
)

func createProbeResult(probeID, probeType, probeName, targetNS string, outcome siderealv1alpha1.ProbeOutcome, effectiveness siderealv1alpha1.ControlEffectiveness) *siderealv1alpha1.SiderealProbeResult {
	return &siderealv1alpha1.SiderealProbeResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sidereal-result-" + probeID[:8],
			Namespace: SystemNamespace,
			Labels: map[string]string{
				FingerprintLabel:     probeID,
				ProbeProfileLabel:    probeType,
				ProbeNameLabel:       probeName,
				TargetNamespaceLabel: targetNS,
			},
		},
		Spec: siderealv1alpha1.SiderealProbeResultSpec{
			Probe: siderealv1alpha1.ProbeResultProbeRef{
				ID:              probeID,
				Profile:         siderealv1alpha1.ProbeProfile(probeType),
				TargetNamespace: targetNS,
			},
			Result: siderealv1alpha1.ProbeResultResult{
				Outcome:              outcome,
				ControlEffectiveness: effectiveness,
				Detail:               "Cross-namespace secret access allowed",
			},
		},
	}
}

func createEnforceProbe(name, targetNS, probeType string) *siderealv1alpha1.SiderealProbe {
	return &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:         siderealv1alpha1.ProbeProfile(probeType),
			TargetNamespace: targetNS,
			ExecutionMode:   siderealv1alpha1.ExecutionModeEnforce,
			IntervalSeconds: 300,
			ControlMappings: map[string][]string{
				"nist-800-53": {"AC-3", "AC-6"},
			},
			MitreAttackID: "T1078",
		},
	}
}

func TestIncidentReconciler_CreatesIncident(t *testing.T) {
	scheme := newTestScheme()
	probeID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

	result := createProbeResult(probeID, "secret", "test-secret-probe", "production",
		siderealv1alpha1.OutcomeFail, siderealv1alpha1.EffectivenessIneffective)

	probe := createEnforceProbe("test-secret-probe", "production", "secret")

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(result, probe).
		Build()

	reconciler := &IncidentReconciler{Client: c}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      result.Name,
			Namespace: SystemNamespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// Verify the incident was created.
	var incidents siderealv1alpha1.SiderealIncidentList
	if err := c.List(context.Background(), &incidents); err != nil {
		t.Fatalf("failed to list incidents: %v", err)
	}
	if len(incidents.Items) != 1 {
		t.Fatalf("expected 1 incident, got %d", len(incidents.Items))
	}

	incident := incidents.Items[0]
	if incident.Spec.Severity != siderealv1alpha1.SeverityHigh {
		t.Errorf("expected severity High, got %q", incident.Spec.Severity)
	}
	if incident.Spec.Profile != siderealv1alpha1.ProbeProfileSecret {
		t.Errorf("expected probe type secret, got %q", incident.Spec.Profile)
	}
	if incident.Spec.TargetNamespace != "production" {
		t.Errorf("expected target namespace production, got %q", incident.Spec.TargetNamespace)
	}
	if incident.Spec.ControlID != "AC-3" {
		t.Errorf("expected control ID AC-3, got %q", incident.Spec.ControlID)
	}
	if incident.Spec.MitreID != "T1078" {
		t.Errorf("expected MITRE ID T1078, got %q", incident.Spec.MitreID)
	}
	if incident.Spec.RemediationStatus != siderealv1alpha1.RemediationOpen {
		t.Errorf("expected remediation Open, got %q", incident.Spec.RemediationStatus)
	}
}

func TestIncidentReconciler_CompromisedCreatesCriticalIncident(t *testing.T) {
	scheme := newTestScheme()
	probeID := "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"

	result := createProbeResult(probeID, "rbac", "test-rbac-probe", "staging",
		siderealv1alpha1.OutcomeTamperedResult, siderealv1alpha1.EffectivenessCompromised)

	probe := createEnforceProbe("test-rbac-probe", "staging", "rbac")

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(result, probe).
		Build()

	reconciler := &IncidentReconciler{Client: c}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      result.Name,
			Namespace: SystemNamespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	var incidents siderealv1alpha1.SiderealIncidentList
	c.List(context.Background(), &incidents)

	if len(incidents.Items) != 1 {
		t.Fatalf("expected 1 incident, got %d", len(incidents.Items))
	}
	if incidents.Items[0].Spec.Severity != siderealv1alpha1.SeverityCritical {
		t.Errorf("expected Critical severity for Compromised, got %q", incidents.Items[0].Spec.Severity)
	}
}

func TestIncidentReconciler_EffectiveNoIncident(t *testing.T) {
	scheme := newTestScheme()
	probeID := "cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa"

	result := createProbeResult(probeID, "rbac", "test-rbac-probe", "production",
		siderealv1alpha1.OutcomePass, siderealv1alpha1.EffectivenessEffective)

	probe := createEnforceProbe("test-rbac-probe", "production", "rbac")

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(result, probe).
		Build()

	reconciler := &IncidentReconciler{Client: c}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      result.Name,
			Namespace: SystemNamespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	var incidents siderealv1alpha1.SiderealIncidentList
	c.List(context.Background(), &incidents)

	if len(incidents.Items) != 0 {
		t.Errorf("expected no incidents for Effective result, got %d", len(incidents.Items))
	}
}

func TestIncidentReconciler_ObserveModeNoIncident(t *testing.T) {
	scheme := newTestScheme()
	probeID := "dddddddd-eeee-ffff-aaaa-bbbbbbbbbbbb"

	result := createProbeResult(probeID, "secret", "test-secret-probe", "production",
		siderealv1alpha1.OutcomeFail, siderealv1alpha1.EffectivenessIneffective)

	// Probe in observe mode — should NOT create incidents.
	probe := &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret-probe",
			Namespace: SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:         siderealv1alpha1.ProbeProfileSecret,
			TargetNamespace: "production",
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(result, probe).
		Build()

	reconciler := &IncidentReconciler{Client: c}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      result.Name,
			Namespace: SystemNamespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	var incidents siderealv1alpha1.SiderealIncidentList
	c.List(context.Background(), &incidents)

	if len(incidents.Items) != 0 {
		t.Errorf("expected no incidents in observe mode, got %d", len(incidents.Items))
	}
}

func TestIncidentReconciler_IdempotentCreation(t *testing.T) {
	scheme := newTestScheme()
	probeID := "eeeeeeee-ffff-aaaa-bbbb-cccccccccccc"

	result := createProbeResult(probeID, "rbac", "test-rbac-probe", "production",
		siderealv1alpha1.OutcomeFail, siderealv1alpha1.EffectivenessIneffective)

	probe := createEnforceProbe("test-rbac-probe", "production", "rbac")

	// Pre-existing incident.
	existingIncident := &siderealv1alpha1.SiderealIncident{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sidereal-incident-" + probeID[:8],
			Namespace: SystemNamespace,
			Labels: map[string]string{
				FingerprintLabel: probeID,
			},
		},
		Spec: siderealv1alpha1.SiderealIncidentSpec{
			ProbeResultRef: result.Name,
			Severity:       siderealv1alpha1.SeverityHigh,
			Profile:        siderealv1alpha1.ProbeProfileRBAC,
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(result, probe, existingIncident).
		Build()

	reconciler := &IncidentReconciler{Client: c}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      result.Name,
			Namespace: SystemNamespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// Should still be just 1 incident.
	var incidents siderealv1alpha1.SiderealIncidentList
	c.List(context.Background(), &incidents)

	if len(incidents.Items) != 1 {
		t.Errorf("expected 1 incident (idempotent), got %d", len(incidents.Items))
	}
}

func TestIncidentReconciler_WebhookDelivery(t *testing.T) {
	scheme := newTestScheme()
	probeID := "ffffffff-aaaa-bbbb-cccc-dddddddddddd"

	var webhookCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result := createProbeResult(probeID, "admission", "test-admission-probe", "production",
		siderealv1alpha1.OutcomeAccepted, siderealv1alpha1.EffectivenessIneffective)

	probe := createEnforceProbe("test-admission-probe", "production", "admission")

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(result, probe).
		Build()

	webhookClient := webhook.NewClient(webhook.Config{
		URL:        server.URL,
		HTTPClient: server.Client(),
	})

	reconciler := &IncidentReconciler{
		Client:        c,
		WebhookClient: webhookClient,
	}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      result.Name,
			Namespace: SystemNamespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	if !webhookCalled {
		t.Error("expected webhook to be called")
	}

	// Verify webhook delivery status was updated.
	var incidents siderealv1alpha1.SiderealIncidentList
	c.List(context.Background(), &incidents)

	if len(incidents.Items) != 1 {
		t.Fatalf("expected 1 incident, got %d", len(incidents.Items))
	}
	if incidents.Items[0].Spec.WebhookDeliveryStatus != siderealv1alpha1.WebhookDelivered {
		t.Errorf("expected Delivered status, got %q", incidents.Items[0].Spec.WebhookDeliveryStatus)
	}
}

func TestIncidentReconciler_WebhookFailure(t *testing.T) {
	scheme := newTestScheme()
	probeID := "11111111-2222-3333-4444-555555555555"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	result := createProbeResult(probeID, "rbac", "test-rbac-probe", "production",
		siderealv1alpha1.OutcomeFail, siderealv1alpha1.EffectivenessIneffective)

	probe := createEnforceProbe("test-rbac-probe", "production", "rbac")

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(result, probe).
		Build()

	webhookClient := webhook.NewClient(webhook.Config{
		URL:        server.URL,
		HTTPClient: server.Client(),
	})

	reconciler := &IncidentReconciler{
		Client:        c,
		WebhookClient: webhookClient,
	}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      result.Name,
			Namespace: SystemNamespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	var incidents siderealv1alpha1.SiderealIncidentList
	c.List(context.Background(), &incidents)

	if len(incidents.Items) != 1 {
		t.Fatalf("expected 1 incident, got %d", len(incidents.Items))
	}
	if incidents.Items[0].Spec.WebhookDeliveryStatus != siderealv1alpha1.WebhookFailed {
		t.Errorf("expected Failed status, got %q", incidents.Items[0].Spec.WebhookDeliveryStatus)
	}
}

func TestDeriveSeverity(t *testing.T) {
	tests := []struct {
		effectiveness siderealv1alpha1.ControlEffectiveness
		expected      siderealv1alpha1.IncidentSeverity
	}{
		{siderealv1alpha1.EffectivenessCompromised, siderealv1alpha1.SeverityCritical},
		{siderealv1alpha1.EffectivenessIneffective, siderealv1alpha1.SeverityHigh},
		{siderealv1alpha1.EffectivenessDegraded, siderealv1alpha1.SeverityMedium},
		{siderealv1alpha1.EffectivenessEffective, siderealv1alpha1.SeverityLow},
	}

	for _, tt := range tests {
		got := deriveSeverity(tt.effectiveness)
		if got != tt.expected {
			t.Errorf("deriveSeverity(%q) = %q, want %q", tt.effectiveness, got, tt.expected)
		}
	}
}
