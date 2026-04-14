package rbac

import (
	"context"
	"testing"

	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/primaris-tech/sidereal/internal/probe"
)

// newFakeClientset creates a fake clientset with a reactor that responds to
// SelfSubjectAccessReview requests. The allowedFn determines whether each
// request is allowed based on its resource attributes.
func newFakeClientset(allowedFn func(attrs *authzv1.ResourceAttributes) bool) *fake.Clientset {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authzv1.SelfSubjectAccessReview)
		attrs := review.Spec.ResourceAttributes
		review.Status.Allowed = allowedFn(attrs)
		return true, review, nil
	})
	return cs
}

func TestExecute_AllPass(t *testing.T) {
	// Simulate correct RBAC: deny-path operations are denied, allow-path operations are allowed.
	cs := newFakeClientset(func(attrs *authzv1.ResourceAttributes) bool {
		// Allow rolebinding reads (allow-path), deny everything else (deny-path).
		return attrs.Resource == "rolebindings"
	})

	cfg := probe.Config{
		ProbeID:         "test-probe-1",
		ProbeType:       "rbac",
		TargetNamespace: "production",
		ExecutionMode:   "dryRun",
	}

	result := Execute(context.Background(), cs, cfg)

	if result.Outcome != "Pass" {
		t.Errorf("expected Pass, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_DenyPathViolation(t *testing.T) {
	// Simulate misconfigured RBAC: secrets are accessible (should be denied).
	cs := newFakeClientset(func(attrs *authzv1.ResourceAttributes) bool {
		// Allow everything — this is the misconfiguration.
		return true
	})

	cfg := probe.Config{
		ProbeID:         "test-probe-2",
		ProbeType:       "rbac",
		TargetNamespace: "production",
		ExecutionMode:   "observe",
	}

	result := Execute(context.Background(), cs, cfg)

	if result.Outcome != "Fail" {
		t.Errorf("expected Fail, got %q: %s", result.Outcome, result.Detail)
	}
	if result.Detail == "" {
		t.Error("expected non-empty detail on failure")
	}
}

func TestExecute_AllowPathViolation(t *testing.T) {
	// Simulate over-restricted RBAC: even rolebinding reads are denied.
	cs := newFakeClientset(func(attrs *authzv1.ResourceAttributes) bool {
		// Deny everything — over-restricted.
		return false
	})

	cfg := probe.Config{
		ProbeID:         "test-probe-3",
		ProbeType:       "rbac",
		TargetNamespace: "staging",
		ExecutionMode:   "dryRun",
	}

	result := Execute(context.Background(), cs, cfg)

	if result.Outcome != "Fail" {
		t.Errorf("expected Fail, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_APIError(t *testing.T) {
	// Simulate API server error by using a clientset with an error reactor.
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, context.DeadlineExceeded
	})

	cfg := probe.Config{
		ProbeID:         "test-probe-4",
		ProbeType:       "rbac",
		TargetNamespace: "production",
		ExecutionMode:   "dryRun",
	}

	result := Execute(context.Background(), cs, cfg)

	if result.Outcome != "Indeterminate" {
		t.Errorf("expected Indeterminate, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_MixedViolation(t *testing.T) {
	// Only one deny-path is violated (secrets GET allowed, but others denied correctly).
	cs := newFakeClientset(func(attrs *authzv1.ResourceAttributes) bool {
		if attrs.Resource == "rolebindings" {
			return true
		}
		// Allow only secrets GET — a single misconfiguration.
		if attrs.Resource == "secrets" && attrs.Verb == "get" {
			return true
		}
		return false
	})

	cfg := probe.Config{
		ProbeID:         "test-probe-5",
		ProbeType:       "rbac",
		TargetNamespace: "production",
		ExecutionMode:   "dryRun",
	}

	result := Execute(context.Background(), cs, cfg)

	if result.Outcome != "Fail" {
		t.Errorf("expected Fail for single deny-path violation, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_DurationTracked(t *testing.T) {
	cs := newFakeClientset(func(attrs *authzv1.ResourceAttributes) bool {
		return attrs.Resource == "rolebindings"
	})

	cfg := probe.Config{
		ProbeID:         "test-probe-6",
		ProbeType:       "rbac",
		TargetNamespace: "default",
		ExecutionMode:   "dryRun",
	}

	result := Execute(context.Background(), cs, cfg)

	if result.DurationMs < 0 {
		t.Errorf("expected non-negative duration, got %d", result.DurationMs)
	}
}

func TestDefaultDenyTests(t *testing.T) {
	tests := DefaultDenyTests("production")
	if len(tests) == 0 {
		t.Fatal("expected at least one deny test")
	}
	for _, tc := range tests {
		if tc.ExpectAllowed {
			t.Errorf("deny test %q should have ExpectAllowed=false", tc.Description)
		}
		// Namespace-scoped tests use the target namespace; cluster-scoped tests
		// use an empty namespace string. Both are valid.
		if tc.Namespace != "production" && tc.Namespace != "" && tc.Namespace != "kube-system" {
			t.Errorf("deny test %q has unexpected namespace %q", tc.Description, tc.Namespace)
		}
	}
}

func TestDefaultDenyTests_IncludesClusterScoped(t *testing.T) {
	tests := DefaultDenyTests("production")
	hasNodesProxy := false
	hasClusterRoleBindings := false
	for _, tc := range tests {
		if tc.Resource == "nodes" && tc.SubResource == "proxy" {
			hasNodesProxy = true
		}
		if tc.Resource == "clusterrolebindings" {
			hasClusterRoleBindings = true
		}
	}
	if !hasNodesProxy {
		t.Error("missing nodes/proxy cluster-scoped deny test")
	}
	if !hasClusterRoleBindings {
		t.Error("missing clusterrolebindings cluster-scoped deny test")
	}
}

func TestDefaultAllowTests(t *testing.T) {
	tests := DefaultAllowTests("staging")
	if len(tests) == 0 {
		t.Fatal("expected at least one allow test")
	}
	for _, tc := range tests {
		if !tc.ExpectAllowed {
			t.Errorf("allow test %q should have ExpectAllowed=true", tc.Description)
		}
		if tc.Namespace != "staging" {
			t.Errorf("allow test %q has namespace %q, expected staging", tc.Description, tc.Namespace)
		}
	}
}
