package controller

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
)

// AlertReconciler watches SiderealSystemAlert resources and enforces the
// acknowledgment gate. Unacknowledged alerts block probe scheduling.
type AlertReconciler struct {
	client.Client
}

// SetupWithManager registers the reconciler with the controller manager.
func (r *AlertReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&siderealv1alpha1.SiderealSystemAlert{}).
		Complete(r)
}

// Reconcile processes a SiderealSystemAlert. It validates acknowledgment
// fields when an alert transitions to acknowledged state.
func (r *AlertReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var alert siderealv1alpha1.SiderealSystemAlert
	if err := r.Get(ctx, req.NamespacedName, &alert); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// If acknowledged, validate the acknowledgment.
	if alert.Spec.Acknowledged {
		if err := ValidateAcknowledgment(&alert); err != nil {
			logger.Error(err, "invalid acknowledgment, reverting",
				"alert", alert.Name,
				"acknowledgedBy", alert.Spec.AcknowledgedBy,
			)
			// Revert the acknowledgment.
			alert.Spec.Acknowledged = false
			alert.Spec.AcknowledgedBy = ""
			alert.Spec.AcknowledgedAt = nil
			alert.Spec.RemediationAction = ""
			if err := r.Update(ctx, &alert); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to revert invalid acknowledgment: %w", err)
			}
			return ctrl.Result{}, nil
		}

		logger.Info("alert acknowledged",
			"alert", alert.Name,
			"reason", alert.Spec.Reason,
			"acknowledgedBy", alert.Spec.AcknowledgedBy,
		)
	}

	return ctrl.Result{}, nil
}

// ValidateAcknowledgment checks that the acknowledgment meets requirements:
//  1. AcknowledgedBy must be set
//  2. AcknowledgedBy must not be a ServiceAccount identity
//  3. RemediationAction must be set
//  4. AcknowledgedAt must be set
func ValidateAcknowledgment(alert *siderealv1alpha1.SiderealSystemAlert) error {
	if alert.Spec.AcknowledgedBy == "" {
		return fmt.Errorf("acknowledgedBy is required")
	}

	if IsServiceAccountIdentity(alert.Spec.AcknowledgedBy) {
		return fmt.Errorf("acknowledgedBy must be an individual user identity, not a ServiceAccount: %s", alert.Spec.AcknowledgedBy)
	}

	if alert.Spec.RemediationAction == "" {
		return fmt.Errorf("remediationAction is required when acknowledging an alert")
	}

	if alert.Spec.AcknowledgedAt == nil {
		return fmt.Errorf("acknowledgedAt timestamp is required")
	}

	return nil
}

// IsServiceAccountIdentity returns true if the identity string represents
// a Kubernetes ServiceAccount rather than an individual user.
// ServiceAccount identities follow the pattern "system:serviceaccount:<ns>:<name>".
func IsServiceAccountIdentity(identity string) bool {
	return strings.HasPrefix(identity, "system:serviceaccount:")
}

// HasUnacknowledgedAlerts checks whether any unacknowledged SiderealSystemAlert
// resources exist in the system namespace. Used by the probe scheduler to gate
// probe execution.
func HasUnacknowledgedAlerts(ctx context.Context, c client.Client) (bool, error) {
	var alerts siderealv1alpha1.SiderealSystemAlertList
	if err := c.List(ctx, &alerts, client.InNamespace(SystemNamespace)); err != nil {
		return false, fmt.Errorf("failed to list system alerts: %w", err)
	}

	for _, alert := range alerts.Items {
		if !alert.Spec.Acknowledged {
			return true, nil
		}
	}

	return false, nil
}

// AcknowledgeAlert sets the acknowledgment fields on a SiderealSystemAlert.
// This is a helper for programmatic acknowledgment (e.g., in tests).
func AcknowledgeAlert(alert *siderealv1alpha1.SiderealSystemAlert, principal, remediationAction string) {
	now := metav1.Now()
	alert.Spec.Acknowledged = true
	alert.Spec.AcknowledgedBy = principal
	alert.Spec.AcknowledgedAt = &now
	alert.Spec.RemediationAction = remediationAction
}
