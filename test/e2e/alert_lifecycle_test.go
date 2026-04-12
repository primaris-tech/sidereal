package e2e

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/controller"
)

func TestAlertLifecycle_AcknowledgmentValidation(t *testing.T) {
	uid := uniqueID()

	alert := &siderealv1alpha1.SiderealSystemAlert{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "alert-ack-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealSystemAlertSpec{
			Reason:  siderealv1alpha1.AlertReasonTamperedResult,
			Message: "HMAC verification failed for probe result",
		},
	}
	if err := k8sClient.Create(ctx, alert); err != nil {
		t.Fatalf("failed to create alert: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, alert) })

	// Try acknowledging with a ServiceAccount identity (should be reverted).
	now := metav1.Now()
	alert.Spec.Acknowledged = true
	alert.Spec.AcknowledgedBy = "system:serviceaccount:sidereal-system:sidereal-controller"
	alert.Spec.AcknowledgedAt = &now
	alert.Spec.RemediationAction = "Rotate HMAC keys"
	if err := k8sClient.Update(ctx, alert); err != nil {
		t.Fatalf("failed to update alert: %v", err)
	}

	// Wait for the controller to revert the invalid acknowledgment.
	time.Sleep(3 * time.Second)

	var updated siderealv1alpha1.SiderealSystemAlert
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Name:      alert.Name,
		Namespace: controller.SystemNamespace,
	}, &updated); err != nil {
		t.Fatalf("failed to get updated alert: %v", err)
	}

	if updated.Spec.Acknowledged {
		t.Error("ServiceAccount identity acknowledgment should have been reverted")
	}
}

func TestAlertLifecycle_ValidAcknowledgment(t *testing.T) {
	uid := uniqueID()

	alert := &siderealv1alpha1.SiderealSystemAlert{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "alert-valid-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealSystemAlertSpec{
			Reason:  siderealv1alpha1.AlertReasonSIEMExportDegraded,
			Message: "Splunk HEC endpoint unreachable",
		},
	}
	if err := k8sClient.Create(ctx, alert); err != nil {
		t.Fatalf("failed to create alert: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, alert) })

	// Acknowledge with a valid user identity.
	controller.AcknowledgeAlert(alert, "john.smith@agency.gov", "Splunk endpoint restored and verified")
	if err := k8sClient.Update(ctx, alert); err != nil {
		t.Fatalf("failed to update alert: %v", err)
	}

	// Wait for reconciliation.
	time.Sleep(3 * time.Second)

	var updated siderealv1alpha1.SiderealSystemAlert
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Name:      alert.Name,
		Namespace: controller.SystemNamespace,
	}, &updated); err != nil {
		t.Fatalf("failed to get updated alert: %v", err)
	}

	if !updated.Spec.Acknowledged {
		t.Error("valid acknowledgment should be preserved")
	}
	if updated.Spec.AcknowledgedBy != "john.smith@agency.gov" {
		t.Errorf("unexpected acknowledgedBy: %s", updated.Spec.AcknowledgedBy)
	}
}

func TestAlertLifecycle_MissingFields(t *testing.T) {
	uid := uniqueID()

	alert := &siderealv1alpha1.SiderealSystemAlert{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "alert-miss-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealSystemAlertSpec{
			Reason:  siderealv1alpha1.AlertReasonBaselineConfigurationDrift,
			Message: "Configuration drift detected",
		},
	}
	if err := k8sClient.Create(ctx, alert); err != nil {
		t.Fatalf("failed to create alert: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, alert) })

	// Acknowledge without remediationAction (should be reverted).
	now := metav1.Now()
	alert.Spec.Acknowledged = true
	alert.Spec.AcknowledgedBy = "john.smith@agency.gov"
	alert.Spec.AcknowledgedAt = &now
	// Deliberately missing RemediationAction
	if err := k8sClient.Update(ctx, alert); err != nil {
		t.Fatalf("failed to update alert: %v", err)
	}

	time.Sleep(3 * time.Second)

	var updated siderealv1alpha1.SiderealSystemAlert
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Name:      alert.Name,
		Namespace: controller.SystemNamespace,
	}, &updated); err != nil {
		t.Fatalf("failed to get alert: %v", err)
	}

	if updated.Spec.Acknowledged {
		t.Error("acknowledgment without remediationAction should be reverted")
	}
}

func TestAlertLifecycle_HasUnacknowledgedAlerts(t *testing.T) {
	uid := uniqueID()

	alert := &siderealv1alpha1.SiderealSystemAlert{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "alert-gate-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealSystemAlertSpec{
			Reason:  siderealv1alpha1.AlertReasonAuditWriteFailure,
			Message: "Audit write failed",
		},
	}
	if err := k8sClient.Create(ctx, alert); err != nil {
		t.Fatalf("failed to create alert: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, alert) })

	hasUnacked, err := controller.HasUnacknowledgedAlerts(ctx, k8sClient)
	if err != nil {
		t.Fatalf("failed to check alerts: %v", err)
	}
	if !hasUnacked {
		t.Error("expected unacknowledged alerts to be detected")
	}

	// Acknowledge and verify gate clears.
	controller.AcknowledgeAlert(alert, "admin@agency.gov", "Issue resolved")
	if err := k8sClient.Update(ctx, alert); err != nil {
		t.Fatalf("failed to acknowledge alert: %v", err)
	}

	time.Sleep(2 * time.Second)

	// Re-read to get the acknowledged version.
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Name: alert.Name, Namespace: controller.SystemNamespace,
	}, alert); err != nil {
		t.Fatalf("failed to re-read alert: %v", err)
	}

	if !alert.Spec.Acknowledged {
		t.Error("alert should be acknowledged now")
	}
}
