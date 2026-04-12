package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/discovery"
)

const (
	// DefaultDiscoveryInterval is the default interval between discovery runs (6 hours).
	DefaultDiscoveryInterval = 6 * time.Hour

	// HighImpactDiscoveryInterval is the discovery interval for high-impact systems.
	HighImpactDiscoveryInterval = 6 * time.Hour

	// ModerateImpactDiscoveryInterval is the discovery interval for moderate-impact systems.
	ModerateImpactDiscoveryInterval = 12 * time.Hour

	// LowImpactDiscoveryInterval is the discovery interval for low-impact systems.
	LowImpactDiscoveryInterval = 24 * time.Hour
)

// DiscoveryReconciler runs the discovery engine periodically and manages
// SiderealProbeRecommendation lifecycle (creation, supersession, dedup).
type DiscoveryReconciler struct {
	client.Client
	Engine   *discovery.Engine
	Interval time.Duration
}

// SetupWithManager registers the reconciler. It uses a Namespace watch as
// a trigger since discovery scans cluster-wide resources. The actual
// scheduling is timer-based via RequeueAfter.
func (r *DiscoveryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Namespace{}).
		Complete(r)
}

// Reconcile runs the discovery engine and creates/updates recommendations.
// It is triggered by namespace changes but rate-limited to the configured interval.
func (r *DiscoveryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Only run discovery when the sidereal-system namespace is reconciled.
	// This ensures we run on startup (when the namespace is first seen) and
	// periodically via RequeueAfter.
	if req.Name != SystemNamespace {
		return ctrl.Result{}, nil
	}

	logger.Info("starting discovery run")

	recs, err := r.Engine.RunAll(ctx, r.Client)
	if err != nil {
		logger.Error(err, "discovery engine failed")
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	logger.Info("discovery completed", "recommendations", len(recs))

	for _, rec := range recs {
		if err := r.reconcileRecommendation(ctx, rec); err != nil {
			logger.Error(err, "failed to reconcile recommendation",
				"source", fmt.Sprintf("%s/%s", rec.SourceResource.Kind, rec.SourceResource.Name))
		}
	}

	interval := r.Interval
	if interval == 0 {
		interval = DefaultDiscoveryInterval
	}

	return ctrl.Result{RequeueAfter: interval}, nil
}

// reconcileRecommendation creates or updates a SiderealProbeRecommendation
// for a single discovery result. It handles:
//   - Dedup: skip if an existing recommendation with the same source+hash exists
//   - Supersession: if source hash changed, mark old recommendation as superseded
//   - Dismissal: skip if a dismissed recommendation with the same source exists
func (r *DiscoveryReconciler) reconcileRecommendation(ctx context.Context, rec discovery.Recommendation) error {
	logger := log.FromContext(ctx)

	sourceHash := discovery.HashResource(rec.SourceResource)
	recName := discovery.RecommendationName(rec.SourceResource, "")

	// Check for existing recommendation with same name.
	var existing siderealv1alpha1.SiderealProbeRecommendation
	err := r.Get(ctx, types.NamespacedName{
		Name:      recName,
		Namespace: SystemNamespace,
	}, &existing)

	if err == nil {
		// Existing recommendation found.
		switch existing.Status.State {
		case siderealv1alpha1.RecommendationDismissed:
			// Don't re-generate dismissed recommendations with the same hash.
			if existing.Spec.SourceResourceHash == sourceHash {
				return nil
			}
			// Source changed, supersede the dismissed one and create new.
			return r.supersedAndCreate(ctx, &existing, rec, sourceHash)

		case siderealv1alpha1.RecommendationPending:
			// Same hash means no change, skip.
			if existing.Spec.SourceResourceHash == sourceHash {
				return nil
			}
			// Source changed, supersede and create new.
			return r.supersedAndCreate(ctx, &existing, rec, sourceHash)

		case siderealv1alpha1.RecommendationPromoted:
			// Same hash, skip.
			if existing.Spec.SourceResourceHash == sourceHash {
				return nil
			}
			// Source changed. Supersede, but the promoted probe still runs.
			return r.supersedAndCreate(ctx, &existing, rec, sourceHash)

		case siderealv1alpha1.RecommendationSuperseded:
			// Already superseded, check if there's a newer one.
			return nil
		}

		return nil
	}

	// No existing recommendation. Create one.
	newRec := &siderealv1alpha1.SiderealProbeRecommendation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      recName,
			Namespace: SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeRecommendationSpec{
			SourceResource:     rec.SourceResource,
			SourceResourceHash: sourceHash,
			Confidence:         rec.Confidence,
			Rationale:          rec.Rationale,
			ProbeTemplate:      rec.ProbeTemplate,
			ControlMappings:    rec.ControlMappings,
		},
	}

	if err := r.Create(ctx, newRec); err != nil {
		return fmt.Errorf("failed to create recommendation %s: %w", recName, err)
	}

	logger.Info("created recommendation",
		"name", recName,
		"sourceKind", rec.SourceResource.Kind,
		"sourceName", rec.SourceResource.Name,
		"confidence", rec.Confidence,
	)

	return nil
}

// supersedAndCreate marks the existing recommendation as superseded and creates
// a new one with the updated source hash.
func (r *DiscoveryReconciler) supersedAndCreate(
	ctx context.Context,
	existing *siderealv1alpha1.SiderealProbeRecommendation,
	rec discovery.Recommendation,
	sourceHash string,
) error {
	logger := log.FromContext(ctx)

	// Generate a new name with a version suffix.
	newName := fmt.Sprintf("%s-v%d", discovery.RecommendationName(rec.SourceResource, ""),
		time.Now().Unix())
	if len(newName) > 253 {
		newName = newName[:253]
	}

	// Create the new recommendation first.
	newRec := &siderealv1alpha1.SiderealProbeRecommendation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      newName,
			Namespace: SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeRecommendationSpec{
			SourceResource:     rec.SourceResource,
			SourceResourceHash: sourceHash,
			Confidence:         rec.Confidence,
			Rationale:          rec.Rationale,
			ProbeTemplate:      rec.ProbeTemplate,
			ControlMappings:    rec.ControlMappings,
		},
	}

	if err := r.Create(ctx, newRec); err != nil {
		return fmt.Errorf("failed to create superseding recommendation: %w", err)
	}

	// Mark the existing one as superseded.
	existing.Status.State = siderealv1alpha1.RecommendationSuperseded
	existing.Status.SupersededBy = newName
	if err := r.Status().Update(ctx, existing); err != nil {
		return fmt.Errorf("failed to mark recommendation as superseded: %w", err)
	}

	logger.Info("superseded recommendation",
		"old", existing.Name,
		"new", newName,
		"sourceKind", rec.SourceResource.Kind,
	)

	return nil
}

// DiscoveryIntervalForImpactLevel returns the discovery interval for the given
// FIPS 199 impact level.
func DiscoveryIntervalForImpactLevel(impactLevel string) time.Duration {
	switch impactLevel {
	case "high":
		return HighImpactDiscoveryInterval
	case "moderate":
		return ModerateImpactDiscoveryInterval
	case "low":
		return LowImpactDiscoveryInterval
	default:
		return DefaultDiscoveryInterval
	}
}
