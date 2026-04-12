package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
)

func createServiceAccounts() []corev1.ServiceAccount {
	var sas []corev1.ServiceAccount
	for _, name := range BuiltInServiceAccounts {
		sas = append(sas, corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: SystemNamespace,
			},
		})
	}
	return sas
}

func createHMACSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      HMACRootSecretName,
			Namespace: SystemNamespace,
		},
		Data: map[string][]byte{
			"hmac-key": []byte("root-key-32-bytes-long-enough!!!"),
		},
	}
}

func createNetworkPolicy() *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sidereal-system-deny-all",
			Namespace: SystemNamespace,
		},
		Spec: networkingv1.NetworkPolicySpec{},
	}
}

func TestBootstrapVerification_AllPass(t *testing.T) {
	scheme := newTestScheme()
	_ = networkingv1.AddToScheme(scheme)

	var objects []client.Object
	for _, sa := range createServiceAccounts() {
		sa := sa
		objects = append(objects, &sa)
	}
	objects = append(objects, createHMACSecret())
	objects = append(objects, createNetworkPolicy())

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()

	result := RunBootstrapVerification(context.Background(), c)

	if !result.Passed {
		t.Errorf("expected all checks to pass: %s", result.Summary())
	}

	// 7 SAs + 1 HMAC + 1 NetworkPolicy = 9 checks
	if len(result.Checks) != 9 {
		t.Errorf("expected 9 checks, got %d", len(result.Checks))
	}

	for _, check := range result.Checks {
		if !check.Passed {
			t.Errorf("check %q failed: %s", check.Name, check.Detail)
		}
	}
}

func TestBootstrapVerification_MissingServiceAccount(t *testing.T) {
	scheme := newTestScheme()
	_ = networkingv1.AddToScheme(scheme)

	// Only create 6 of 7 SAs (omit sidereal-discovery).
	var objects []client.Object
	for _, sa := range createServiceAccounts() {
		if sa.Name == "sidereal-discovery" {
			continue
		}
		sa := sa
		objects = append(objects, &sa)
	}
	objects = append(objects, createHMACSecret())
	objects = append(objects, createNetworkPolicy())

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()

	result := RunBootstrapVerification(context.Background(), c)

	if result.Passed {
		t.Error("expected failure with missing ServiceAccount")
	}

	failed := result.FailedChecks()
	if len(failed) != 1 {
		t.Fatalf("expected 1 failure, got %d", len(failed))
	}
	if failed[0].Name != "ServiceAccount/sidereal-discovery" {
		t.Errorf("expected sidereal-discovery failure, got %q", failed[0].Name)
	}
}

func TestBootstrapVerification_MissingHMACSecret(t *testing.T) {
	scheme := newTestScheme()
	_ = networkingv1.AddToScheme(scheme)

	var objects []client.Object
	for _, sa := range createServiceAccounts() {
		sa := sa
		objects = append(objects, &sa)
	}
	// No HMAC secret.
	objects = append(objects, createNetworkPolicy())

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()

	result := RunBootstrapVerification(context.Background(), c)

	if result.Passed {
		t.Error("expected failure with missing HMAC secret")
	}

	failed := result.FailedChecks()
	foundHMAC := false
	for _, f := range failed {
		if f.Name == "Secret/sidereal-hmac-root" {
			foundHMAC = true
		}
	}
	if !foundHMAC {
		t.Error("expected HMAC secret check to fail")
	}
}

func TestBootstrapVerification_EmptyHMACKey(t *testing.T) {
	scheme := newTestScheme()
	_ = networkingv1.AddToScheme(scheme)

	var objects []client.Object
	for _, sa := range createServiceAccounts() {
		sa := sa
		objects = append(objects, &sa)
	}
	emptySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      HMACRootSecretName,
			Namespace: SystemNamespace,
		},
		Data: map[string][]byte{
			"hmac-key": {},
		},
	}
	objects = append(objects, emptySecret)
	objects = append(objects, createNetworkPolicy())

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()

	result := RunBootstrapVerification(context.Background(), c)

	if result.Passed {
		t.Error("expected failure with empty HMAC key")
	}
}

func TestBootstrapVerification_MissingNetworkPolicy(t *testing.T) {
	scheme := newTestScheme()
	_ = networkingv1.AddToScheme(scheme)

	var objects []client.Object
	for _, sa := range createServiceAccounts() {
		sa := sa
		objects = append(objects, &sa)
	}
	objects = append(objects, createHMACSecret())
	// No NetworkPolicy.

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()

	result := RunBootstrapVerification(context.Background(), c)

	if result.Passed {
		t.Error("expected failure with missing NetworkPolicy")
	}

	failed := result.FailedChecks()
	foundNP := false
	for _, f := range failed {
		if f.Name == "NetworkPolicy/sidereal-system" {
			foundNP = true
		}
	}
	if !foundNP {
		t.Error("expected NetworkPolicy check to fail")
	}
}

func TestBootstrapVerification_MultipleFailures(t *testing.T) {
	scheme := newTestScheme()
	_ = networkingv1.AddToScheme(scheme)

	// Nothing present.
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	result := RunBootstrapVerification(context.Background(), c)

	if result.Passed {
		t.Error("expected failure with nothing present")
	}

	// Should have 7 SA failures + 1 HMAC + 1 NetworkPolicy = 9 failures
	failed := result.FailedChecks()
	if len(failed) != 9 {
		t.Errorf("expected 9 failures, got %d", len(failed))
	}
}

func TestHandleBootstrapFailure_CreatesAlert(t *testing.T) {
	scheme := newTestScheme()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	result := &BootstrapResult{
		Passed: false,
		Checks: []BootstrapCheck{
			{Name: "test", Passed: false, Detail: "missing"},
		},
	}

	err := HandleBootstrapFailure(context.Background(), c, result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var alerts siderealv1alpha1.SiderealSystemAlertList
	c.List(context.Background(), &alerts)

	if len(alerts.Items) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts.Items))
	}
	if alerts.Items[0].Spec.Reason != siderealv1alpha1.AlertReasonBaselineConfigurationDrift {
		t.Errorf("expected BaselineConfigurationDrift, got %q", alerts.Items[0].Spec.Reason)
	}
}

func TestHandleBootstrapFailure_Idempotent(t *testing.T) {
	scheme := newTestScheme()

	existing := &siderealv1alpha1.SiderealSystemAlert{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sidereal-alert-bootstrap-failed",
			Namespace: SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealSystemAlertSpec{
			Reason:  siderealv1alpha1.AlertReasonBaselineConfigurationDrift,
			Message: "previous failure",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()

	result := &BootstrapResult{
		Passed: false,
		Checks: []BootstrapCheck{
			{Name: "test", Passed: false, Detail: "still missing"},
		},
	}

	err := HandleBootstrapFailure(context.Background(), c, result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var alerts siderealv1alpha1.SiderealSystemAlertList
	c.List(context.Background(), &alerts)

	if len(alerts.Items) != 1 {
		t.Errorf("expected 1 alert (idempotent), got %d", len(alerts.Items))
	}
}

func TestHandleBootstrapFailure_PassedNoAlert(t *testing.T) {
	scheme := newTestScheme()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	result := &BootstrapResult{Passed: true}

	err := HandleBootstrapFailure(context.Background(), c, result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var alerts siderealv1alpha1.SiderealSystemAlertList
	c.List(context.Background(), &alerts)

	if len(alerts.Items) != 0 {
		t.Errorf("expected no alerts for passed bootstrap, got %d", len(alerts.Items))
	}
}

func TestBootstrapResult_Summary(t *testing.T) {
	result := &BootstrapResult{
		Passed: true,
		Checks: []BootstrapCheck{
			{Name: "a", Passed: true},
			{Name: "b", Passed: true},
		},
	}
	if result.Summary() != "bootstrap verification passed: 2/2 checks OK" {
		t.Errorf("unexpected summary: %q", result.Summary())
	}

	result.Passed = false
	result.Checks = append(result.Checks, BootstrapCheck{Name: "c", Passed: false, Detail: "missing"})
	summary := result.Summary()
	if !contains(summary, "2/3 checks passed") {
		t.Errorf("unexpected failure summary: %q", summary)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
