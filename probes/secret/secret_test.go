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

func forbiddenFor(resource string) error {
	return k8serrors.NewForbidden(
		schema.GroupResource{Resource: resource},
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

// denyAll returns a clientset that denies all Secret and ConfigMap access with 403.
func denyAll() *fake.Clientset {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("*", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenFor("secrets")
	})
	cs.PrependReactor("*", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenFor("configmaps")
	})
	return cs
}

// allowSecrets returns a clientset that returns actual Secret objects (no RBAC enforcement)
// while denying all ConfigMap access.
func allowSecrets() *fake.Clientset {
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
	cs := fake.NewSimpleClientset(secret, kubeSecret)
	cs.PrependReactor("*", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenFor("configmaps")
	})
	return cs
}

func TestExecute_AllDenied(t *testing.T) {
	cs := denyAll()

	cfg := probe.Config{
		ProbeID:         "test-secret-1",
		Profile:         "secret",
		TargetNamespace: "production",
		ExecutionMode:   "dryRun",
	}

	result := Execute(context.Background(), cs, cfg)

	if result.Outcome != "Pass" {
		t.Errorf("expected Pass, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_SecretsAccessible(t *testing.T) {
	cs := allowSecrets()

	cfg := probe.Config{
		ProbeID:         "test-secret-2",
		Profile:         "secret",
		TargetNamespace: "production",
		ExecutionMode:   "observe",
	}

	result := Execute(context.Background(), cs, cfg)

	if result.Outcome != "Fail" {
		t.Errorf("expected Fail, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_ConfigMapsAccessible(t *testing.T) {
	// Secrets denied but configmaps are accessible.
	cs := fake.NewSimpleClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kube-root-ca.crt",
				Namespace: "production",
			},
		},
	)
	cs.PrependReactor("*", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenFor("secrets")
	})
	// configmaps fall through to default (returns the configmap)

	cfg := probe.Config{
		ProbeID:         "test-secret-cm-1",
		Profile:         "secret",
		TargetNamespace: "production",
		ExecutionMode:   "observe",
	}

	result := Execute(context.Background(), cs, cfg)

	if result.Outcome != "Fail" {
		t.Errorf("expected Fail for configmap access, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_WritePathAccessible(t *testing.T) {
	// Secrets and configmaps denied, but secret create (dry-run) succeeds.
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenFor("secrets")
	})
	cs.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenFor("secrets")
	})
	cs.PrependReactor("*", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenFor("configmaps")
	})
	// create on secrets falls through to default (dry-run succeeds)

	cfg := probe.Config{
		ProbeID:         "test-secret-wp-1",
		Profile:         "secret",
		TargetNamespace: "production",
		ExecutionMode:   "observe",
	}

	result := Execute(context.Background(), cs, cfg)

	if result.Outcome != "Fail" {
		t.Errorf("expected Fail for write-path access, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_PartialAccess(t *testing.T) {
	// LIST is forbidden but GET on secrets succeeds (partial misconfiguration).
	cs := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "default-token", Namespace: "production"},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "default-token", Namespace: "kube-system"},
		},
	)
	cs.PrependReactor("list", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenFor("secrets")
	})
	cs.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenFor("secrets")
	})
	cs.PrependReactor("*", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenFor("configmaps")
	})
	// GET secrets falls through to default (returns the secret).

	cfg := probe.Config{
		ProbeID:         "test-secret-3",
		Profile:         "secret",
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
		return true, nil, forbiddenFor("secrets")
	})
	cs.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenFor("secrets")
	})
	cs.PrependReactor("*", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenFor("configmaps")
	})

	cfg := probe.Config{
		ProbeID:         "test-secret-4",
		Profile:         "secret",
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
	cs.PrependReactor("*", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, serverError()
	})

	cfg := probe.Config{
		ProbeID:         "test-secret-5",
		Profile:         "secret",
		TargetNamespace: "production",
		ExecutionMode:   "dryRun",
	}

	result := Execute(context.Background(), cs, cfg)

	if result.Outcome != "Indeterminate" {
		t.Errorf("expected Indeterminate, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_DurationTracked(t *testing.T) {
	cs := denyAll()

	cfg := probe.Config{
		ProbeID:         "test-secret-6",
		Profile:         "secret",
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
	hasListConfigMapTarget := false
	hasListConfigMapKubeSystem := false
	hasWritePath := false

	for _, tc := range tests {
		if tc.Verb == "list" && tc.Resource == "secrets" && tc.Namespace == "staging" {
			hasListTarget = true
		}
		if tc.Verb == "get" && tc.Resource == "secrets" && tc.Namespace == "staging" {
			hasGetTarget = true
		}
		if tc.Resource == "secrets" && tc.Namespace == "kube-system" {
			hasKubeSystem = true
		}
		if tc.Verb == "list" && tc.Resource == "secrets" && tc.Namespace == "" {
			hasClusterWide = true
		}
		if tc.Verb == "list" && tc.Resource == "configmaps" && tc.Namespace == "staging" {
			hasListConfigMapTarget = true
		}
		if tc.Verb == "list" && tc.Resource == "configmaps" && tc.Namespace == "kube-system" {
			hasListConfigMapKubeSystem = true
		}
		if tc.Verb == "create" && tc.Resource == "secrets" {
			hasWritePath = true
		}
	}

	if !hasListTarget {
		t.Error("missing LIST secrets test for target namespace")
	}
	if !hasGetTarget {
		t.Error("missing GET secrets test for target namespace")
	}
	if !hasKubeSystem {
		t.Error("missing kube-system cross-namespace secret test")
	}
	if !hasClusterWide {
		t.Error("missing cluster-wide LIST secrets test")
	}
	if !hasListConfigMapTarget {
		t.Error("missing LIST configmaps test for target namespace")
	}
	if !hasListConfigMapKubeSystem {
		t.Error("missing LIST configmaps test for kube-system")
	}
	if !hasWritePath {
		t.Error("missing write-path CREATE secrets test")
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
			return true, nil, forbiddenFor("secrets")
		}
		return false, nil, nil // fall through to default (returns secret)
	})
	cs.PrependReactor("*", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenFor("configmaps")
	})

	cfg := probe.Config{
		ProbeID:         "test-secret-7",
		Profile:         "secret",
		TargetNamespace: "production",
		ExecutionMode:   "dryRun",
	}

	result := Execute(context.Background(), cs, cfg)

	if result.Outcome != "Fail" {
		t.Errorf("expected Fail for kube-system access, got %q: %s", result.Outcome, result.Detail)
	}
}
