package e2e

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/controller"
	"github.com/primaris-tech/sidereal/internal/discovery"
)

// A fixed discovery result keeps these tests focused on the reconciler's
// persistence and lifecycle behavior against the real API server.
type fixtureDiscoverer struct{ recommendation discovery.Recommendation }

func (d fixtureDiscoverer) Name() string { return "fixture" }
func (d fixtureDiscoverer) Discover(context.Context, client.Client) ([]discovery.Recommendation, error) {
	return []discovery.Recommendation{d.recommendation}, nil
}

func discoveryFixture() discovery.Recommendation {
	return discovery.Recommendation{
		SourceResource: corev1.ObjectReference{Kind: "RoleBinding", Name: "admin-" + uniqueID(), Namespace: "default", ResourceVersion: "1"},
		Confidence:     v1.ConfidenceHigh,
		Rationale:      "RoleBinding grants administrative access",
		ProbeTemplate: v1.SiderealProbeSpec{
			Profile: v1.ProbeProfileRBAC, TargetNamespace: "default",
			ExecutionMode: v1.ExecutionModeDryRun, IntervalSeconds: 21600,
			ControlMappings: map[string][]string{"nist-800-53": {"AC-6(5)"}},
		},
	}
}

func runDiscovery(t *testing.T, rec discovery.Recommendation) *v1.SiderealProbeRecommendation {
	t.Helper()
	r := &controller.DiscoveryReconciler{
		Client: k8sClient,
		Engine: discovery.NewEngineWithDiscoverers(fixtureDiscoverer{rec}),
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: controller.SystemNamespace}}); err != nil {
		t.Fatalf("reconcile discovery: %v", err)
	}
	var stored v1.SiderealProbeRecommendation
	key := client.ObjectKey{Namespace: controller.SystemNamespace, Name: discovery.RecommendationName(rec.SourceResource, "")}
	if err := k8sClient.Get(ctx, key, &stored); err != nil {
		t.Fatalf("fetch discovered recommendation: %v", err)
	}
	return &stored
}

func TestDiscovery_RecommendationLifecycle(t *testing.T) {
	defer startControllers(t)()
	fixture := discoveryFixture()
	rec := runDiscovery(t, fixture)
	if rec.Status.State != v1.RecommendationPending {
		t.Fatalf("expected pending state, got %q", rec.Status.State)
	}
	again := runDiscovery(t, fixture)
	if again.UID != rec.UID || again.Status.State != v1.RecommendationPending {
		t.Fatalf("repeat discovery changed recommendation: %+v", again.Status)
	}
	var recommendations v1.SiderealProbeRecommendationList
	if err := k8sClient.List(ctx, &recommendations, client.InNamespace(controller.SystemNamespace)); err != nil {
		t.Fatal(err)
	}
	if len(recommendations.Items) != 1 {
		t.Fatalf("expected one recommendation, got %d", len(recommendations.Items))
	}
}

func TestDiscovery_InitializesExistingRecommendation(t *testing.T) {
	defer startControllers(t)()
	fixture := discoveryFixture()
	existing := &v1.SiderealProbeRecommendation{
		ObjectMeta: metav1.ObjectMeta{Name: discovery.RecommendationName(fixture.SourceResource, ""), Namespace: controller.SystemNamespace},
		Spec: v1.SiderealProbeRecommendationSpec{
			SourceResource: fixture.SourceResource, SourceResourceHash: discovery.HashResource(fixture.SourceResource),
			Confidence: fixture.Confidence, Rationale: fixture.Rationale, ProbeTemplate: fixture.ProbeTemplate,
		},
	}
	if err := k8sClient.Create(ctx, existing); err != nil {
		t.Fatal(err)
	}
	if existing.Status.State != "" {
		t.Fatalf("fixture must start without status, got %q", existing.Status.State)
	}
	repaired := runDiscovery(t, fixture)
	if repaired.UID != existing.UID || repaired.Status.State != v1.RecommendationPending {
		t.Fatalf("existing recommendation was not initialized: %+v", repaired.Status)
	}
}

func TestDiscovery_RecommendationDismissal(t *testing.T) {
	defer startControllers(t)()
	fixture := discoveryFixture()
	rec := runDiscovery(t, fixture)
	rec.Status.State = v1.RecommendationDismissed
	rec.Status.DismissedBy = "isso@agency.gov"
	rec.Status.DismissedReason = "Policy not applicable in staging"
	if err := k8sClient.Status().Update(ctx, rec); err != nil {
		t.Fatal(err)
	}
	updated := runDiscovery(t, fixture)
	if updated.UID != rec.UID || updated.Status.State != v1.RecommendationDismissed || updated.Status.DismissedBy != "isso@agency.gov" {
		t.Fatalf("discovery changed the dismissal: %+v", updated.Status)
	}
}

func TestDiscovery_RecommendationPromotion(t *testing.T) {
	defer startControllers(t)()
	fixture := discoveryFixture()
	rec := runDiscovery(t, fixture)
	probe := createProbe(t, &v1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{Name: "promoted-" + uniqueID(), Namespace: controller.SystemNamespace},
		Spec:       rec.Spec.ProbeTemplate,
	})
	rec.Status.State = v1.RecommendationPromoted
	rec.Status.PromotedTo = probe.Name
	if err := k8sClient.Status().Update(ctx, rec); err != nil {
		t.Fatal(err)
	}
	updated := runDiscovery(t, fixture)
	if updated.Status.State != v1.RecommendationPromoted || updated.Status.PromotedTo != probe.Name {
		t.Fatalf("discovery changed the promotion: %+v", updated.Status)
	}
	waitForScheduledProbe(t, probe)
	if probe.Spec.ExecutionMode != v1.ExecutionModeDryRun {
		t.Fatal("promoted probe must use dryRun")
	}
}

func TestDiscovery_RecommendationSupersession(t *testing.T) {
	defer startControllers(t)()
	fixture := discoveryFixture()
	original := runDiscovery(t, fixture)
	fixture.SourceResource.ResourceVersion = "2"
	updated := runDiscovery(t, fixture)
	if updated.Status.State != v1.RecommendationSuperseded || updated.Status.SupersededBy == "" {
		t.Fatalf("original recommendation was not superseded: %+v", updated.Status)
	}
	if updated.UID != original.UID {
		t.Fatal("original recommendation was replaced")
	}
	var replacement v1.SiderealProbeRecommendation
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: updated.Status.SupersededBy, Namespace: controller.SystemNamespace}, &replacement); err != nil {
		t.Fatal(err)
	}
	if replacement.Status.State != v1.RecommendationPending || replacement.Spec.SourceResourceHash != discovery.HashResource(fixture.SourceResource) {
		t.Fatalf("replacement has incorrect state or source hash: %+v", replacement)
	}
}
