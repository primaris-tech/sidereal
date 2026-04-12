package discovery

import (
	"context"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
)

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = siderealv1alpha1.AddToScheme(s)
	_ = admissionregistrationv1.AddToScheme(s)
	return s
}

func TestNetworkPolicyDiscoverer(t *testing.T) {
	scheme := newTestScheme()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production"}}
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deny-all",
			Namespace: "production",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns, np).Build()

	d := &NetworkPolicyDiscoverer{}
	recs, err := d.Discover(context.Background(), c)
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}

	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}

	rec := recs[0]
	if rec.SourceResource.Kind != "NetworkPolicy" {
		t.Errorf("expected source kind NetworkPolicy, got %s", rec.SourceResource.Kind)
	}
	if rec.ProbeTemplate.ProbeType != siderealv1alpha1.ProbeTypeNetPol {
		t.Errorf("expected netpol probe type, got %s", rec.ProbeTemplate.ProbeType)
	}
	if rec.ProbeTemplate.TargetNamespace != "production" {
		t.Errorf("expected target namespace production, got %s", rec.ProbeTemplate.TargetNamespace)
	}
	if rec.ProbeTemplate.ExecutionMode != siderealv1alpha1.ExecutionModeDryRun {
		t.Error("all recommendations should default to dryRun")
	}
	if rec.Confidence != siderealv1alpha1.ConfidenceHigh {
		t.Errorf("expected high confidence, got %s", rec.Confidence)
	}
}

func TestRBACDiscoverer(t *testing.T) {
	scheme := newTestScheme()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production"}}
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "admin-binding",
			Namespace: "production",
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "ClusterRole",
			Name: "admin",
		},
		Subjects: []rbacv1.Subject{
			{Kind: "ServiceAccount", Name: "deployer", Namespace: "production"},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns, rb).Build()

	d := &RBACDiscoverer{}
	recs, err := d.Discover(context.Background(), c)
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}

	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}

	rec := recs[0]
	if rec.SourceResource.Kind != "RoleBinding" {
		t.Errorf("expected source kind RoleBinding, got %s", rec.SourceResource.Kind)
	}
	if rec.ProbeTemplate.ProbeType != siderealv1alpha1.ProbeTypeRBAC {
		t.Errorf("expected rbac probe type, got %s", rec.ProbeTemplate.ProbeType)
	}
}

func TestRBACDiscoverer_SkipsSystemBindings(t *testing.T) {
	scheme := newTestScheme()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}}
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "system:kube-proxy",
			Namespace: "kube-system",
		},
		RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "system:kube-proxy"},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns, rb).Build()

	d := &RBACDiscoverer{}
	recs, err := d.Discover(context.Background(), c)
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}

	// kube-system is excluded, so no recommendations.
	if len(recs) != 0 {
		t.Errorf("expected 0 recommendations for system bindings, got %d", len(recs))
	}
}

func TestAdmissionDiscoverer(t *testing.T) {
	scheme := newTestScheme()

	sideEffects := admissionregistrationv1.SideEffectClassNone
	wh := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "kyverno-resource-validating-webhook-cfg"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name:                    "validate.kyverno.svc",
				SideEffects:             &sideEffects,
				AdmissionReviewVersions: []string{"v1"},
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Name:      "kyverno-svc",
						Namespace: "kyverno",
					},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(wh).Build()

	d := &AdmissionDiscoverer{}
	recs, err := d.Discover(context.Background(), c)
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}

	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}

	rec := recs[0]
	if rec.ProbeTemplate.ProbeType != siderealv1alpha1.ProbeTypeAdmission {
		t.Errorf("expected admission probe type, got %s", rec.ProbeTemplate.ProbeType)
	}
}

func TestSecretDiscoverer(t *testing.T) {
	scheme := newTestScheme()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production"}}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tls-cert", Namespace: "production"},
		Type:       corev1.SecretTypeTLS,
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns, secret).Build()

	d := &SecretDiscoverer{}
	recs, err := d.Discover(context.Background(), c)
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}

	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}

	rec := recs[0]
	if rec.ProbeTemplate.ProbeType != siderealv1alpha1.ProbeTypeSecret {
		t.Errorf("expected secret probe type, got %s", rec.ProbeTemplate.ProbeType)
	}
	if rec.ProbeTemplate.TargetNamespace != "production" {
		t.Errorf("expected target namespace production, got %s", rec.ProbeTemplate.TargetNamespace)
	}
}

func TestSecretDiscoverer_SkipsEmptyNamespaces(t *testing.T) {
	scheme := newTestScheme()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "empty"}}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns).Build()

	d := &SecretDiscoverer{}
	recs, err := d.Discover(context.Background(), c)
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}

	if len(recs) != 0 {
		t.Errorf("expected 0 recommendations for namespace without secrets, got %d", len(recs))
	}
}

func TestEngine_RunAll(t *testing.T) {
	scheme := newTestScheme()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production"}}
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-all", Namespace: "production"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "api-key", Namespace: "production"},
		Type:       corev1.SecretTypeOpaque,
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns, np, secret).Build()

	engine := NewEngine()
	recs, err := engine.RunAll(context.Background(), c)
	if err != nil {
		t.Fatalf("RunAll failed: %v", err)
	}

	// Should have at least netpol + secret recommendations.
	if len(recs) < 2 {
		t.Errorf("expected at least 2 recommendations, got %d", len(recs))
	}

	// All recommendations should be dryRun.
	for _, rec := range recs {
		if rec.ProbeTemplate.ExecutionMode != siderealv1alpha1.ExecutionModeDryRun {
			t.Errorf("recommendation for %s should default to dryRun", rec.SourceResource.Name)
		}
	}
}

func TestHashResource(t *testing.T) {
	obj := map[string]string{"key": "value"}

	hash1 := HashResource(obj)
	hash2 := HashResource(obj)

	if hash1 != hash2 {
		t.Error("same object should produce same hash")
	}
	if hash1 == "" {
		t.Error("hash should not be empty")
	}

	obj2 := map[string]string{"key": "different"}
	hash3 := HashResource(obj2)
	if hash1 == hash3 {
		t.Error("different objects should produce different hashes")
	}
}

func TestRecommendationName(t *testing.T) {
	source := corev1.ObjectReference{
		Kind:      "NetworkPolicy",
		Name:      "deny-all",
		Namespace: "production",
	}

	name := RecommendationName(source, "")
	if name != "sidereal-rec-NetworkPolicy-production-deny-all" {
		t.Errorf("unexpected name: %s", name)
	}

	nameWithSuffix := RecommendationName(source, "deny")
	if nameWithSuffix != "sidereal-rec-NetworkPolicy-production-deny-all-deny" {
		t.Errorf("unexpected name with suffix: %s", nameWithSuffix)
	}
}

func TestExcludedNamespaces(t *testing.T) {
	excluded := ExcludedNamespaces()

	if !excluded["kube-system"] {
		t.Error("kube-system should be excluded")
	}
	if !excluded["sidereal-system"] {
		t.Error("sidereal-system should be excluded")
	}
	if excluded["production"] {
		t.Error("production should not be excluded")
	}
}

func TestDeduplicate(t *testing.T) {
	recs := []Recommendation{
		{SourceResource: corev1.ObjectReference{Kind: "NetworkPolicy", Namespace: "ns1", Name: "a"}},
		{SourceResource: corev1.ObjectReference{Kind: "NetworkPolicy", Namespace: "ns1", Name: "a"}},
		{SourceResource: corev1.ObjectReference{Kind: "NetworkPolicy", Namespace: "ns2", Name: "a"}},
	}

	result := deduplicate(recs)
	if len(result) != 2 {
		t.Errorf("expected 2 unique recommendations, got %d", len(result))
	}
}
