package secret

import (
	"context"
	"net/http"
	"testing"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/primaris-tech/sidereal/internal/probe"
)

func forbiddenError() error {
	return k8serrors.NewForbidden(
		schema.GroupResource{Resource: "secrets"},
		"",
		nil,
	)
}

func serverError() error {
	return &k8serrors.StatusError{
		ErrStatus: metav1.Status{
			Status:  metav1.StatusFailure,
			Code:    http.StatusInternalServerError,
			Reason:  metav1.StatusReasonInternalError,
			Message: "internal server error",
		},
	}
}

// newForbiddenClientset returns a clientset that denies all Secret access with 403.
func newForbiddenClientset() *fake.Clientset {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("*", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenError()
	})
	return cs
}

// newAccessibleClientset returns a clientset that allows Secret access (secrets exist).
func newAccessibleClientset() *fake.Clientset {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-token",
			Namespace: "production",
		},
		Data: map[string][]byte{
			"token": []byte("sensitive-data"),
		},
	}
	kubeSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-token",
			Namespace: "kube-system",
		},
		Data: map[string][]byte{
			"ca.crt": []byte("certificate-data"),
		},
	}
	return fake.NewSimpleClientset(secret, kubeSecret)
}

func TestExecute_AllDenied(t *testing.T) {
	cs := newForbiddenClientset()

	cfg := probe.Config{
		ProbeID:         "test-secret-1",
		ProbeType:       "secret",
		TargetNamespace: "production",
		ExecutionMode:   "dryRun",
	}

	result := Execute(context.Background(), cs, cfg)

	if result.Outcome != "Pass" {
		t.Errorf("expected Pass, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_SecretsAccessible(t *testing.T) {
	// Fake clientset returns secrets successfully (no RBAC enforcement).
	cs := newAccessibleClientset()

	cfg := probe.Config{
		ProbeID:         "test-secret-2",
		ProbeType:       "secret",
		TargetNamespace: "production",
		ExecutionMode:   "observe",
	}

	result := Execute(context.Background(), cs, cfg)

	if result.Outcome != "Fail" {
		t.Errorf("expected Fail, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_PartialAccess(t *testing.T) {
	// LIST is forbidden but GET succeeds (partial misconfiguration).
	cs := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "default-token", Namespace: "production"},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "default-token", Namespace: "kube-system"},
		},
	)
	cs.PrependReactor("list", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenError()
	})
	// GET falls through to default (returns the secret).

	cfg := probe.Config{
		ProbeID:         "test-secret-3",
		ProbeType:       "secret",
		TargetNamespace: "production",
		ExecutionMode:   "dryRun",
	}

	result := Execute(context.Background(), cs, cfg)

	if result.Outcome != "Fail" {
		t.Errorf("expected Fail for partial access, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_NotFoundTreatedAsDenied(t *testing.T) {
	// GET returns 404 (SA lacks visibility), LIST returns 403.
	cs := fake.NewSimpleClientset() // no secrets exist, GET returns 404
	cs.PrependReactor("list", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenError()
	})

	cfg := probe.Config{
		ProbeID:         "test-secret-4",
		ProbeType:       "secret",
		TargetNamespace: "production",
		ExecutionMode:   "dryRun",
	}

	result := Execute(context.Background(), cs, cfg)

	if result.Outcome != "Pass" {
		t.Errorf("expected Pass (404 treated as denied), got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_APIError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("*", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, serverError()
	})

	cfg := probe.Config{
		ProbeID:         "test-secret-5",
		ProbeType:       "secret",
		TargetNamespace: "production",
		ExecutionMode:   "dryRun",
	}

	result := Execute(context.Background(), cs, cfg)

	if result.Outcome != "Indeterminate" {
		t.Errorf("expected Indeterminate, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_DurationTracked(t *testing.T) {
	cs := newForbiddenClientset()

	cfg := probe.Config{
		ProbeID:         "test-secret-6",
		ProbeType:       "secret",
		TargetNamespace: "default",
		ExecutionMode:   "dryRun",
	}

	result := Execute(context.Background(), cs, cfg)

	if result.DurationMs < 0 {
		t.Errorf("expected non-negative duration, got %d", result.DurationMs)
	}
}

func TestDefaultTests(t *testing.T) {
	tests := DefaultTests("staging")
	if len(tests) < 2 {
		t.Fatalf("expected at least 2 tests, got %d", len(tests))
	}

	hasListTarget := false
	hasGetTarget := false
	hasKubeSystem := false
	hasClusterWide := false
	for _, tc := range tests {
		if tc.Verb == "list" && tc.Namespace == "staging" {
			hasListTarget = true
		}
		if tc.Verb == "get" && tc.Namespace == "staging" {
			hasGetTarget = true
		}
		if tc.Namespace == "kube-system" {
			hasKubeSystem = true
		}
		if tc.Verb == "list" && tc.Namespace == "" {
			hasClusterWide = true
		}
	}
	if !hasListTarget {
		t.Error("missing LIST test for target namespace")
	}
	if !hasGetTarget {
		t.Error("missing GET test for target namespace")
	}
	if !hasKubeSystem {
		t.Error("missing kube-system cross-namespace test")
	}
	if !hasClusterWide {
		t.Error("missing cluster-wide LIST test")
	}
}

func TestExecute_CrossNamespaceOnly(t *testing.T) {
	// Target namespace secrets are denied but kube-system is accessible.
	cs := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "default-token", Namespace: "kube-system"},
		},
	)
	cs.PrependReactor("*", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		ns := action.GetNamespace()
		if ns == "production" {
			return true, nil, forbiddenError()
		}
		return false, nil, nil // fall through to default (returns secret)
	})

	cfg := probe.Config{
		ProbeID:         "test-secret-7",
		ProbeType:       "secret",
		TargetNamespace: "production",
		ExecutionMode:   "dryRun",
	}

	result := Execute(context.Background(), cs, cfg)

	if result.Outcome != "Fail" {
		t.Errorf("expected Fail for kube-system access, got %q: %s", result.Outcome, result.Detail)
	}
}
