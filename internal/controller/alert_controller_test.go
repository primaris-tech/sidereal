package controller

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
)

func TestHasUnacknowledgedAlerts_NoAlerts(t *testing.T) {
	scheme := newTestScheme()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	has, err := HasUnacknowledgedAlerts(context.Background(), c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if has {
		t.Error("expected no unacknowledged alerts")
	}
}

func TestHasUnacknowledgedAlerts_WithOpen(t *testing.T) {
	scheme := newTestScheme()

	alert := &siderealv1alpha1.SiderealSystemAlert{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-alert",
			Namespace: SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealSystemAlertSpec{
			Reason:       siderealv1alpha1.AlertReasonTamperedResult,
			Message:      "HMAC verification failed",
			Acknowledged: false,
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(alert).Build()

	has, err := HasUnacknowledgedAlerts(context.Background(), c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !has {
		t.Error("expected unacknowledged alerts")
	}
}

func TestHasUnacknowledgedAlerts_AllAcknowledged(t *testing.T) {
	scheme := newTestScheme()

	now := metav1.Now()
	alert := &siderealv1alpha1.SiderealSystemAlert{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-alert",
			Namespace: SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealSystemAlertSpec{
			Reason:            siderealv1alpha1.AlertReasonTamperedResult,
			Message:           "HMAC verification failed",
			Acknowledged:      true,
			AcknowledgedBy:    "admin@example.com",
			AcknowledgedAt:    &now,
			RemediationAction: "Rotated HMAC keys",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(alert).Build()

	has, err := HasUnacknowledgedAlerts(context.Background(), c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if has {
		t.Error("expected no unacknowledged alerts when all are acknowledged")
	}
}

func TestValidateAcknowledgment_Valid(t *testing.T) {
	now := metav1.Now()
	alert := &siderealv1alpha1.SiderealSystemAlert{
		Spec: siderealv1alpha1.SiderealSystemAlertSpec{
			Acknowledged:      true,
			AcknowledgedBy:    "admin@example.com",
			AcknowledgedAt:    &now,
			RemediationAction: "Rotated HMAC keys and re-ran probes",
		},
	}

	if err := ValidateAcknowledgment(alert); err != nil {
		t.Errorf("expected valid acknowledgment, got error: %v", err)
	}
}

func TestValidateAcknowledgment_ServiceAccount(t *testing.T) {
	now := metav1.Now()
	alert := &siderealv1alpha1.SiderealSystemAlert{
		Spec: siderealv1alpha1.SiderealSystemAlertSpec{
			Acknowledged:      true,
			AcknowledgedBy:    "system:serviceaccount:sidereal-system:sidereal-controller",
			AcknowledgedAt:    &now,
			RemediationAction: "auto-acknowledged",
		},
	}

	err := ValidateAcknowledgment(alert)
	if err == nil {
		t.Error("expected error for ServiceAccount identity")
	}
}

func TestValidateAcknowledgment_MissingFields(t *testing.T) {
	tests := []struct {
		name  string
		alert *siderealv1alpha1.SiderealSystemAlert
	}{
		{
			"missing acknowledgedBy",
			&siderealv1alpha1.SiderealSystemAlert{
				Spec: siderealv1alpha1.SiderealSystemAlertSpec{
					Acknowledged:      true,
					AcknowledgedAt:    &metav1.Time{},
					RemediationAction: "action",
				},
			},
		},
		{
			"missing remediationAction",
			&siderealv1alpha1.SiderealSystemAlert{
				Spec: siderealv1alpha1.SiderealSystemAlertSpec{
					Acknowledged:   true,
					AcknowledgedBy: "admin@example.com",
					AcknowledgedAt: &metav1.Time{},
				},
			},
		},
		{
			"missing acknowledgedAt",
			&siderealv1alpha1.SiderealSystemAlert{
				Spec: siderealv1alpha1.SiderealSystemAlertSpec{
					Acknowledged:      true,
					AcknowledgedBy:    "admin@example.com",
					RemediationAction: "action",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateAcknowledgment(tt.alert); err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func TestIsServiceAccountIdentity(t *testing.T) {
	tests := []struct {
		identity string
		expected bool
	}{
		{"system:serviceaccount:default:my-sa", true},
		{"system:serviceaccount:sidereal-system:controller", true},
		{"admin@example.com", false},
		{"john.doe", false},
		{"system:admin", false},
	}

	for _, tt := range tests {
		if got := IsServiceAccountIdentity(tt.identity); got != tt.expected {
			t.Errorf("IsServiceAccountIdentity(%q) = %v, want %v", tt.identity, got, tt.expected)
		}
	}
}

func TestAlertReconciler_RevertsInvalidAcknowledgment(t *testing.T) {
	scheme := newTestScheme()

	now := metav1.Now()
	alert := &siderealv1alpha1.SiderealSystemAlert{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-alert-revert",
			Namespace: SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealSystemAlertSpec{
			Reason:            siderealv1alpha1.AlertReasonTamperedResult,
			Message:           "tampered",
			Acknowledged:      true,
			AcknowledgedBy:    "system:serviceaccount:default:bad-sa",
			AcknowledgedAt:    &now,
			RemediationAction: "auto",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(alert).Build()

	reconciler := &AlertReconciler{Client: c}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      alert.Name,
			Namespace: SystemNamespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// Verify acknowledgment was reverted.
	var updated siderealv1alpha1.SiderealSystemAlert
	c.Get(context.Background(), types.NamespacedName{
		Name: alert.Name, Namespace: SystemNamespace,
	}, &updated)

	if updated.Spec.Acknowledged {
		t.Error("expected acknowledgment to be reverted")
	}
	if updated.Spec.AcknowledgedBy != "" {
		t.Errorf("expected empty acknowledgedBy, got %q", updated.Spec.AcknowledgedBy)
	}
}

func TestAlertReconciler_AcceptsValidAcknowledgment(t *testing.T) {
	scheme := newTestScheme()

	now := metav1.Now()
	alert := &siderealv1alpha1.SiderealSystemAlert{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-alert-valid",
			Namespace: SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealSystemAlertSpec{
			Reason:            siderealv1alpha1.AlertReasonBackendUnreachable,
			Message:           "Falco unreachable",
			Acknowledged:      true,
			AcknowledgedBy:    "isso@agency.gov",
			AcknowledgedAt:    &now,
			RemediationAction: "Verified Falco pod restarted and healthy",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(alert).Build()

	reconciler := &AlertReconciler{Client: c}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      alert.Name,
			Namespace: SystemNamespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// Verify acknowledgment was NOT reverted.
	var updated siderealv1alpha1.SiderealSystemAlert
	c.Get(context.Background(), types.NamespacedName{
		Name: alert.Name, Namespace: SystemNamespace,
	}, &updated)

	if !updated.Spec.Acknowledged {
		t.Error("expected acknowledgment to remain")
	}
	if updated.Spec.AcknowledgedBy != "isso@agency.gov" {
		t.Errorf("expected acknowledgedBy preserved, got %q", updated.Spec.AcknowledgedBy)
	}
}

func TestAcknowledgeAlert(t *testing.T) {
	alert := &siderealv1alpha1.SiderealSystemAlert{
		Spec: siderealv1alpha1.SiderealSystemAlertSpec{
			Reason:  siderealv1alpha1.AlertReasonSIEMExportDegraded,
			Message: "Splunk HEC unreachable",
		},
	}

	AcknowledgeAlert(alert, "admin@agency.gov", "Restored Splunk connectivity")

	if !alert.Spec.Acknowledged {
		t.Error("expected acknowledged=true")
	}
	if alert.Spec.AcknowledgedBy != "admin@agency.gov" {
		t.Errorf("unexpected acknowledgedBy: %q", alert.Spec.AcknowledgedBy)
	}
	if alert.Spec.AcknowledgedAt == nil {
		t.Error("expected acknowledgedAt to be set")
	}
	if alert.Spec.RemediationAction != "Restored Splunk connectivity" {
		t.Errorf("unexpected remediationAction: %q", alert.Spec.RemediationAction)
	}
}
