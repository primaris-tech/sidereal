package controller

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/discovery"
)

type failInitialStatusClient struct {
	client.Client
	fail bool
}

func (c *failInitialStatusClient) Status() client.SubResourceWriter {
	return &failInitialStatusWriter{SubResourceWriter: c.Client.Status(), parent: c}
}

type failInitialStatusWriter struct {
	client.SubResourceWriter
	parent *failInitialStatusClient
}

func (w *failInitialStatusWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if w.parent.fail {
		w.parent.fail = false
		return fmt.Errorf("status API unavailable")
	}
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}

func TestDiscoveryRetriesInitialStatus(t *testing.T) {
	c := &failInitialStatusClient{
		Client: fake.NewClientBuilder().WithScheme(newTestScheme()).WithStatusSubresource(&v1.SiderealProbeRecommendation{}).Build(),
		fail:   true,
	}
	r := &DiscoveryReconciler{Client: c}
	rec := discovery.Recommendation{
		SourceResource: corev1.ObjectReference{Kind: "RoleBinding", Name: "admin", Namespace: "production"},
		Confidence:     v1.ConfidenceHigh, Rationale: "Administrative binding",
		ProbeTemplate: v1.SiderealProbeSpec{Profile: v1.ProbeProfileRBAC, TargetNamespace: "production", ExecutionMode: v1.ExecutionModeDryRun, IntervalSeconds: 300},
	}
	if err := r.reconcileRecommendation(context.Background(), rec); err == nil {
		t.Fatal("expected status write error")
	}
	key := client.ObjectKey{Name: discovery.RecommendationName(rec.SourceResource, ""), Namespace: SystemNamespace}
	var stored v1.SiderealProbeRecommendation
	if err := c.Get(context.Background(), key, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Status.State != "" {
		t.Fatalf("failed status write persisted state %q", stored.Status.State)
	}
	if err := r.reconcileRecommendation(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), key, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Status.State != v1.RecommendationPending {
		t.Fatalf("retry left state %q", stored.Status.State)
	}
	var all v1.SiderealProbeRecommendationList
	if err := c.List(context.Background(), &all); err != nil {
		t.Fatal(err)
	}
	if len(all.Items) != 1 {
		t.Fatalf("retry created %d recommendations", len(all.Items))
	}
}
