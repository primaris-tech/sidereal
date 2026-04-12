package e2e

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/controller"
)

func TestDiscovery_RecommendationLifecycle(t *testing.T) {
	uid := uniqueID()

	rec := &siderealv1alpha1.SiderealProbeRecommendation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "disc-rec-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeRecommendationSpec{
			SourceResource: corev1.ObjectReference{
				Kind:      "RoleBinding",
				Name:      "test-rolebinding",
				Namespace: "default",
			},
			SourceResourceHash: "sha256:abc123",
			Confidence:         siderealv1alpha1.ConfidenceHigh,
			Rationale:          "RoleBinding grants cluster-admin to SA in default namespace",
			ProbeTemplate: siderealv1alpha1.SiderealProbeSpec{
				ProbeType:       siderealv1alpha1.ProbeTypeRBAC,
				TargetNamespace: "default",
				ExecutionMode:   siderealv1alpha1.ExecutionModeDryRun,
				IntervalSeconds: 21600,
			},
		},
	}
	if err := k8sClient.Create(ctx, rec); err != nil {
		t.Fatalf("failed to create recommendation: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, rec) })

	// Verify it starts in pending state.
	var fetched siderealv1alpha1.SiderealProbeRecommendation
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Name: rec.Name, Namespace: controller.SystemNamespace,
	}, &fetched); err != nil {
		t.Fatalf("failed to fetch recommendation: %v", err)
	}

	if fetched.Status.State != siderealv1alpha1.RecommendationPending {
		t.Errorf("expected pending state, got %s", fetched.Status.State)
	}
}

func TestDiscovery_RecommendationDismissal(t *testing.T) {
	uid := uniqueID()

	rec := &siderealv1alpha1.SiderealProbeRecommendation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "disc-dismiss-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeRecommendationSpec{
			SourceResource: corev1.ObjectReference{
				Kind:      "NetworkPolicy",
				Name:      "deny-all",
				Namespace: "staging",
			},
			SourceResourceHash: "sha256:def456",
			Confidence:         siderealv1alpha1.ConfidenceMedium,
			Rationale:          "NetworkPolicy deny-all in staging namespace",
			ProbeTemplate: siderealv1alpha1.SiderealProbeSpec{
				ProbeType:       siderealv1alpha1.ProbeTypeNetPol,
				TargetNamespace: "staging",
				ExecutionMode:   siderealv1alpha1.ExecutionModeDryRun,
				IntervalSeconds: 21600,
			},
		},
	}
	if err := k8sClient.Create(ctx, rec); err != nil {
		t.Fatalf("failed to create recommendation: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, rec) })

	// Dismiss the recommendation.
	rec.Status.State = siderealv1alpha1.RecommendationDismissed
	rec.Status.DismissedBy = "isso@agency.gov"
	rec.Status.DismissedReason = "Policy not applicable in staging"
	if err := k8sClient.Status().Update(ctx, rec); err != nil {
		t.Fatalf("failed to update recommendation status: %v", err)
	}

	var updated siderealv1alpha1.SiderealProbeRecommendation
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Name: rec.Name, Namespace: controller.SystemNamespace,
	}, &updated); err != nil {
		t.Fatalf("failed to fetch updated recommendation: %v", err)
	}

	if updated.Status.State != siderealv1alpha1.RecommendationDismissed {
		t.Errorf("expected dismissed state, got %s", updated.Status.State)
	}
	if updated.Status.DismissedBy != "isso@agency.gov" {
		t.Errorf("expected dismissedBy 'isso@agency.gov', got %s", updated.Status.DismissedBy)
	}
}

func TestDiscovery_RecommendationPromotion(t *testing.T) {
	uid := uniqueID()

	rec := &siderealv1alpha1.SiderealProbeRecommendation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "disc-promote-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeRecommendationSpec{
			SourceResource: corev1.ObjectReference{
				Kind:      "RoleBinding",
				Name:      "admin-binding",
				Namespace: "default",
			},
			SourceResourceHash: "sha256:ghi789",
			Confidence:         siderealv1alpha1.ConfidenceHigh,
			Rationale:          "Admin RoleBinding discovered in default namespace",
			ProbeTemplate: siderealv1alpha1.SiderealProbeSpec{
				ProbeType:       siderealv1alpha1.ProbeTypeRBAC,
				TargetNamespace: "default",
				ExecutionMode:   siderealv1alpha1.ExecutionModeDryRun,
				IntervalSeconds: 21600,
				ControlMappings: map[string][]string{
					"nist-800-53": {"AC-6(5)"},
				},
			},
		},
	}
	if err := k8sClient.Create(ctx, rec); err != nil {
		t.Fatalf("failed to create recommendation: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, rec) })

	// Promote: create a SiderealProbe from the template.
	probeName := "promoted-" + uid
	probeFromTemplate := &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      probeName,
			Namespace: controller.SystemNamespace,
		},
		Spec: rec.Spec.ProbeTemplate,
	}
	if err := k8sClient.Create(ctx, probeFromTemplate); err != nil {
		t.Fatalf("failed to create probe from template: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, probeFromTemplate) })

	// Update recommendation status.
	rec.Status.State = siderealv1alpha1.RecommendationPromoted
	rec.Status.PromotedTo = probeName
	if err := k8sClient.Status().Update(ctx, rec); err != nil {
		t.Fatalf("failed to update recommendation status: %v", err)
	}

	// Verify the promoted probe exists and has dryRun mode.
	var probe siderealv1alpha1.SiderealProbe
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Name: probeName, Namespace: controller.SystemNamespace,
	}, &probe); err != nil {
		t.Fatalf("promoted probe should exist: %v", err)
	}

	if probe.Spec.ExecutionMode != siderealv1alpha1.ExecutionModeDryRun {
		t.Error("promoted probe should default to dryRun execution mode")
	}
}

func TestDiscovery_RecommendationSupersession(t *testing.T) {
	uid := uniqueID()

	original := &siderealv1alpha1.SiderealProbeRecommendation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "disc-orig-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeRecommendationSpec{
			SourceResource: corev1.ObjectReference{
				Kind:      "ValidatingWebhookConfiguration",
				Name:      "policy-webhook",
				Namespace: "",
			},
			SourceResourceHash: "sha256:old111",
			Confidence:         siderealv1alpha1.ConfidenceHigh,
			Rationale:          "ValidatingWebhookConfiguration for policy enforcement",
			ProbeTemplate: siderealv1alpha1.SiderealProbeSpec{
				ProbeType:       siderealv1alpha1.ProbeTypeAdmission,
				TargetNamespace: "default",
				ExecutionMode:   siderealv1alpha1.ExecutionModeDryRun,
				IntervalSeconds: 21600,
			},
		},
	}
	if err := k8sClient.Create(ctx, original); err != nil {
		t.Fatalf("failed to create original recommendation: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, original) })

	replacement := &siderealv1alpha1.SiderealProbeRecommendation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "disc-repl-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeRecommendationSpec{
			SourceResource: corev1.ObjectReference{
				Kind:      "ValidatingWebhookConfiguration",
				Name:      "policy-webhook",
				Namespace: "",
			},
			SourceResourceHash: "sha256:new222",
			Confidence:         siderealv1alpha1.ConfidenceHigh,
			Rationale:          "Updated ValidatingWebhookConfiguration for policy enforcement",
			ProbeTemplate: siderealv1alpha1.SiderealProbeSpec{
				ProbeType:       siderealv1alpha1.ProbeTypeAdmission,
				TargetNamespace: "default",
				ExecutionMode:   siderealv1alpha1.ExecutionModeDryRun,
				IntervalSeconds: 21600,
			},
		},
	}
	if err := k8sClient.Create(ctx, replacement); err != nil {
		t.Fatalf("failed to create replacement: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, replacement) })

	// Mark original as superseded.
	original.Status.State = siderealv1alpha1.RecommendationSuperseded
	original.Status.SupersededBy = replacement.Name
	if err := k8sClient.Status().Update(ctx, original); err != nil {
		t.Fatalf("failed to update original: %v", err)
	}

	var updated siderealv1alpha1.SiderealProbeRecommendation
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Name: original.Name, Namespace: controller.SystemNamespace,
	}, &updated); err != nil {
		t.Fatalf("failed to fetch original: %v", err)
	}

	if updated.Status.State != siderealv1alpha1.RecommendationSuperseded {
		t.Errorf("expected superseded state, got %s", updated.Status.State)
	}
	if updated.Status.SupersededBy != replacement.Name {
		t.Errorf("expected supersededBy %s, got %s", replacement.Name, updated.Status.SupersededBy)
	}
}
