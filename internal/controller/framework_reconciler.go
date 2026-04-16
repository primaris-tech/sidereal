package controller

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/crosswalk"
)

const frameworkFinalizer = "sidereal.cloud/framework-finalizer"

// FrameworkReconciler watches SiderealFramework resources and syncs them
// into the in-memory crosswalk.Resolver. Handles create, update, and delete
// without requiring a controller restart.
type FrameworkReconciler struct {
	client.Client
	Crosswalk *crosswalk.Resolver
}

// SetupWithManager registers the reconciler with the controller manager.
func (r *FrameworkReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&siderealv1alpha1.SiderealFramework{}).
		Complete(r)
}

// Reconcile processes a SiderealFramework event.
func (r *FrameworkReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var fw siderealv1alpha1.SiderealFramework
	if err := r.Get(ctx, req.NamespacedName, &fw); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Deletion path: evict from resolver and remove finalizer.
	if !fw.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&fw, frameworkFinalizer) {
			r.Crosswalk.RemoveFramework(fw.Spec.FrameworkID)
			logger.Info("removed framework from resolver", "frameworkID", fw.Spec.FrameworkID)
			controllerutil.RemoveFinalizer(&fw, frameworkFinalizer)
			if err := r.Update(ctx, &fw); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to remove finalizer: %w", err)
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer on first reconcile so deletes go through the eviction path.
	if !controllerutil.ContainsFinalizer(&fw, frameworkFinalizer) {
		controllerutil.AddFinalizer(&fw, frameworkFinalizer)
		if err := r.Update(ctx, &fw); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to add finalizer: %w", err)
		}
		return ctrl.Result{}, nil // re-enqueued by the update
	}

	// Validate that metadata.name matches spec.frameworkID to prevent silent
	// aliasing where the resource is named differently from the resolver key.
	if fw.Name != fw.Spec.FrameworkID {
		return r.setLoaded(ctx, &fw, metav1.ConditionFalse, "InvalidFrameworkID",
			fmt.Sprintf("metadata.name %q must equal spec.frameworkID %q", fw.Name, fw.Spec.FrameworkID))
	}

	// Convert CRD mappings to resolver type and upsert.
	mappings := make([]crosswalk.Mapping, len(fw.Spec.Mappings))
	for i, m := range fw.Spec.Mappings {
		mappings[i] = crosswalk.Mapping{
			Profile:     string(m.Profile),
			NISTControl: m.NISTControl,
			ControlIDs:  m.ControlIDs,
		}
	}
	r.Crosswalk.UpsertFramework(&crosswalk.Framework{
		FrameworkID: fw.Spec.FrameworkID,
		Version:     fw.Spec.Version,
		Mappings:    mappings,
	})

	logger.Info("loaded framework into resolver",
		"frameworkID", fw.Spec.FrameworkID,
		"version", fw.Spec.Version,
		"mappings", len(mappings),
	)

	return r.setLoaded(ctx, &fw, metav1.ConditionTrue, "FrameworkLoaded",
		fmt.Sprintf("Loaded %d mappings at version %s", len(mappings), fw.Spec.Version))
}

// setLoaded patches the status subresource with an updated Loaded condition.
func (r *FrameworkReconciler) setLoaded(
	ctx context.Context,
	fw *siderealv1alpha1.SiderealFramework,
	status metav1.ConditionStatus,
	reason, message string,
) (ctrl.Result, error) {
	now := metav1.Now()

	condition := metav1.Condition{
		Type:               "Loaded",
		Status:             status,
		ObservedGeneration: fw.Generation,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
	}

	updated := false
	for i, c := range fw.Status.Conditions {
		if c.Type == "Loaded" {
			if c.Status != status {
				fw.Status.Conditions[i] = condition
			} else {
				fw.Status.Conditions[i].Message = message
				fw.Status.Conditions[i].Reason = reason
				fw.Status.Conditions[i].ObservedGeneration = fw.Generation
			}
			updated = true
			break
		}
	}
	if !updated {
		fw.Status.Conditions = append(fw.Status.Conditions, condition)
	}

	if status == metav1.ConditionTrue {
		fw.Status.LoadedAt = &now
		fw.Status.MappingCount = int32(len(fw.Spec.Mappings)) //nolint:gosec // G115: mapping count never approaches int32 max
	}

	if err := r.Status().Update(ctx, fw); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update framework status: %w", err)
	}

	if status != metav1.ConditionTrue {
		return ctrl.Result{}, fmt.Errorf("framework %s: %s", reason, message)
	}
	return ctrl.Result{}, nil
}
