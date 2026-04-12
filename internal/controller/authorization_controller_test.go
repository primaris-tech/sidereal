package controller

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
)

func createAuthorization(name string, validFrom, expiresAt time.Time) *siderealv1alpha1.SiderealAOAuthorization {
	return &siderealv1alpha1.SiderealAOAuthorization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealAOAuthorizationSpec{
			AOName:               "Jane Smith, CISO",
			AuthorizedTechniques: []string{"T1611", "T1059.004"},
			AuthorizedNamespaces: []string{"production", "staging"},
			ValidFrom:            metav1.NewTime(validFrom),
			ExpiresAt:            metav1.NewTime(expiresAt),
			Justification:        "Quarterly detection validation per continuous monitoring plan",
		},
		Status: siderealv1alpha1.SiderealAOAuthorizationStatus{
			Active: false,
		},
	}
}

func TestIsAuthorizationActive(t *testing.T) {
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		validFrom time.Time
		expiresAt time.Time
		expected  bool
	}{
		{
			"active - within window",
			now.Add(-1 * time.Hour),
			now.Add(1 * time.Hour),
			true,
		},
		{
			"expired - past window",
			now.Add(-2 * time.Hour),
			now.Add(-1 * time.Hour),
			false,
		},
		{
			"not yet valid",
			now.Add(1 * time.Hour),
			now.Add(2 * time.Hour),
			false,
		},
		{
			"exact validFrom boundary",
			now,
			now.Add(1 * time.Hour),
			true,
		},
		{
			"exact expiresAt boundary",
			now.Add(-1 * time.Hour),
			now,
			false, // expiresAt is exclusive
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := createAuthorization("test", tt.validFrom, tt.expiresAt)
			got := IsAuthorizationActive(auth, now)
			if got != tt.expected {
				t.Errorf("IsAuthorizationActive() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAuthorizationReconciler_ActivatesAuthorization(t *testing.T) {
	scheme := newTestScheme()
	now := time.Now().UTC()

	auth := createAuthorization("test-auth",
		now.Add(-1*time.Hour),
		now.Add(24*time.Hour),
	)

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(auth).
		WithStatusSubresource(auth).
		Build()

	reconciler := &AuthorizationReconciler{Client: c}

	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      auth.Name,
			Namespace: SystemNamespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// Should requeue before expiry.
	if result.RequeueAfter == 0 {
		t.Error("expected requeue for active authorization")
	}

	// Verify status was updated to active.
	var updated siderealv1alpha1.SiderealAOAuthorization
	c.Get(context.Background(), types.NamespacedName{
		Name: auth.Name, Namespace: SystemNamespace,
	}, &updated)

	if !updated.Status.Active {
		t.Error("expected active=true")
	}
}

func TestAuthorizationReconciler_ExpiredCreatesAlert(t *testing.T) {
	scheme := newTestScheme()
	now := time.Now().UTC()

	auth := createAuthorization("expired-auth",
		now.Add(-48*time.Hour),
		now.Add(-1*time.Hour),
	)
	// Simulate it was previously active.
	auth.Status.Active = true

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(auth).
		WithStatusSubresource(auth).
		Build()

	reconciler := &AuthorizationReconciler{Client: c}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      auth.Name,
			Namespace: SystemNamespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// Verify status was updated to inactive.
	var updated siderealv1alpha1.SiderealAOAuthorization
	c.Get(context.Background(), types.NamespacedName{
		Name: auth.Name, Namespace: SystemNamespace,
	}, &updated)

	if updated.Status.Active {
		t.Error("expected active=false for expired authorization")
	}

	// Verify a SystemAlert was created.
	var alerts siderealv1alpha1.SiderealSystemAlertList
	c.List(context.Background(), &alerts)

	if len(alerts.Items) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts.Items))
	}
	if alerts.Items[0].Spec.Reason != siderealv1alpha1.AlertReasonAOAuthorizationExpired {
		t.Errorf("expected AOAuthorizationExpired reason, got %q", alerts.Items[0].Spec.Reason)
	}
}

func TestAuthorizationReconciler_AlreadyExpiredNoAlert(t *testing.T) {
	scheme := newTestScheme()
	now := time.Now().UTC()

	auth := createAuthorization("already-expired",
		now.Add(-48*time.Hour),
		now.Add(-1*time.Hour),
	)
	// Was already inactive — no transition.
	auth.Status.Active = false

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(auth).
		WithStatusSubresource(auth).
		Build()

	reconciler := &AuthorizationReconciler{Client: c}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      auth.Name,
			Namespace: SystemNamespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// No alert should be created since there was no transition.
	var alerts siderealv1alpha1.SiderealSystemAlertList
	c.List(context.Background(), &alerts)

	if len(alerts.Items) != 0 {
		t.Errorf("expected no alerts for already-expired authorization, got %d", len(alerts.Items))
	}
}

func TestFindActiveAuthorization_Found(t *testing.T) {
	scheme := newTestScheme()
	now := time.Now().UTC()

	auth := createAuthorization("active-auth",
		now.Add(-1*time.Hour),
		now.Add(24*time.Hour),
	)
	auth.Status.Active = true

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(auth).
		WithStatusSubresource(auth).
		Build()

	found, err := FindActiveAuthorization(context.Background(), c, "T1611", "production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found == nil {
		t.Fatal("expected to find active authorization")
	}
	if found.Name != "active-auth" {
		t.Errorf("expected active-auth, got %q", found.Name)
	}
}

func TestFindActiveAuthorization_WrongTechnique(t *testing.T) {
	scheme := newTestScheme()
	now := time.Now().UTC()

	auth := createAuthorization("active-auth",
		now.Add(-1*time.Hour),
		now.Add(24*time.Hour),
	)
	auth.Status.Active = true

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(auth).
		WithStatusSubresource(auth).
		Build()

	found, err := FindActiveAuthorization(context.Background(), c, "T9999", "production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found != nil {
		t.Error("expected nil for unauthorized technique")
	}
}

func TestFindActiveAuthorization_WrongNamespace(t *testing.T) {
	scheme := newTestScheme()
	now := time.Now().UTC()

	auth := createAuthorization("active-auth",
		now.Add(-1*time.Hour),
		now.Add(24*time.Hour),
	)
	auth.Status.Active = true

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(auth).
		WithStatusSubresource(auth).
		Build()

	found, err := FindActiveAuthorization(context.Background(), c, "T1611", "unauthorized-ns")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found != nil {
		t.Error("expected nil for unauthorized namespace")
	}
}

func TestFindActiveAuthorization_Expired(t *testing.T) {
	scheme := newTestScheme()
	now := time.Now().UTC()

	auth := createAuthorization("expired-auth",
		now.Add(-48*time.Hour),
		now.Add(-1*time.Hour),
	)

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(auth).
		WithStatusSubresource(auth).
		Build()

	found, err := FindActiveAuthorization(context.Background(), c, "T1611", "production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found != nil {
		t.Error("expected nil for expired authorization")
	}
}
