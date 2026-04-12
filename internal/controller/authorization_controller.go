package controller

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
)

// AuthorizationReconciler watches SiderealAOAuthorization resources and
// manages their active/expired lifecycle. When an authorization expires,
// it creates a SiderealSystemAlert to block detection probe scheduling.
type AuthorizationReconciler struct {
	client.Client
}

// SetupWithManager registers the reconciler with the controller manager.
func (r *AuthorizationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&siderealv1alpha1.SiderealAOAuthorization{}).
		Complete(r)
}

// Reconcile processes a SiderealAOAuthorization by computing its active
// status and creating alerts when authorizations expire.
func (r *AuthorizationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var auth siderealv1alpha1.SiderealAOAuthorization
	if err := r.Get(ctx, req.NamespacedName, &auth); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	now := time.Now().UTC()
	wasActive := auth.Status.Active
	isActive := IsAuthorizationActive(&auth, now)

	// Update status if changed.
	if auth.Status.Active != isActive {
		auth.Status.Active = isActive
		if err := r.Status().Update(ctx, &auth); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update authorization status: %w", err)
		}

		logger.Info("authorization status changed",
			"authorization", auth.Name,
			"active", isActive,
			"aoName", auth.Spec.AOName,
		)
	}

	// If transitioning from active to expired, create a SystemAlert.
	if wasActive && !isActive {
		if err := r.createExpiredAlert(ctx, &auth); err != nil {
			return ctrl.Result{}, err
		}
	}

	// If the authorization is active but will expire, requeue before expiry.
	if isActive {
		remaining := auth.Spec.ExpiresAt.Time.Sub(now)
		if remaining > 0 {
			return ctrl.Result{RequeueAfter: remaining}, nil
		}
	}

	return ctrl.Result{}, nil
}

// createExpiredAlert creates a SiderealSystemAlert for an expired authorization.
func (r *AuthorizationReconciler) createExpiredAlert(ctx context.Context, auth *siderealv1alpha1.SiderealAOAuthorization) error {
	logger := log.FromContext(ctx)

	alertName := fmt.Sprintf("sidereal-alert-ao-expired-%s", auth.Name)

	// Check if alert already exists.
	var existing siderealv1alpha1.SiderealSystemAlert
	if err := r.Get(ctx, client.ObjectKey{
		Name:      alertName,
		Namespace: auth.Namespace,
	}, &existing); err == nil {
		return nil // already exists
	}

	alert := &siderealv1alpha1.SiderealSystemAlert{
		ObjectMeta: metav1.ObjectMeta{
			Name:      alertName,
			Namespace: auth.Namespace,
			Labels: map[string]string{
				"sidereal.cloud/authorization": auth.Name,
			},
		},
		Spec: siderealv1alpha1.SiderealSystemAlertSpec{
			Reason: siderealv1alpha1.AlertReasonAOAuthorizationExpired,
			Message: fmt.Sprintf(
				"AO authorization %q (AO: %s) expired at %s. Detection probes are suspended until a new authorization is created.",
				auth.Name,
				auth.Spec.AOName,
				auth.Spec.ExpiresAt.Time.UTC().Format(time.RFC3339),
			),
		},
	}

	if err := r.Create(ctx, alert); err != nil {
		return fmt.Errorf("failed to create expiry alert for authorization %s: %w", auth.Name, err)
	}

	logger.Info("created AO authorization expiry alert",
		"alert", alertName,
		"authorization", auth.Name,
		"aoName", auth.Spec.AOName,
	)

	return nil
}

// IsAuthorizationActive checks whether the authorization is within its
// valid time window: validFrom <= now < expiresAt.
func IsAuthorizationActive(auth *siderealv1alpha1.SiderealAOAuthorization, now time.Time) bool {
	return !now.Before(auth.Spec.ValidFrom.Time) && now.Before(auth.Spec.ExpiresAt.Time)
}

// FindActiveAuthorization searches for an active SiderealAOAuthorization
// that covers the given technique and namespace. Used by the probe scheduler
// to gate detection probe execution.
func FindActiveAuthorization(
	ctx context.Context,
	c client.Client,
	techniqueID, namespace string,
) (*siderealv1alpha1.SiderealAOAuthorization, error) {
	var auths siderealv1alpha1.SiderealAOAuthorizationList
	if err := c.List(ctx, &auths, client.InNamespace(SystemNamespace)); err != nil {
		return nil, fmt.Errorf("failed to list authorizations: %w", err)
	}

	now := time.Now().UTC()

	for i := range auths.Items {
		auth := &auths.Items[i]
		if !IsAuthorizationActive(auth, now) {
			continue
		}

		// Check technique coverage.
		techniqueMatch := false
		for _, t := range auth.Spec.AuthorizedTechniques {
			if t == techniqueID {
				techniqueMatch = true
				break
			}
		}
		if !techniqueMatch {
			continue
		}

		// Check namespace coverage.
		for _, ns := range auth.Spec.AuthorizedNamespaces {
			if ns == namespace {
				return auth, nil
			}
		}
	}

	return nil, nil
}
