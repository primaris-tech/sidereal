// Package secret implements the Secret Access probe runner, which validates
// that cross-namespace Secret access is denied, that credential material
// in ConfigMaps is inaccessible, and that the probe ServiceAccount cannot
// write Secrets. Unlike the RBAC probe (which checks permissions via
// SelfSubjectAccessReview), this probe attempts actual API calls to verify
// that access controls are operationally effective.
package secret

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/primaris-tech/sidereal/internal/probe"
)

// TestCase defines a single access check.
type TestCase struct {
	// Description is a human-readable label for the test.
	Description string

	// Verb is "get", "list", or "create".
	Verb string

	// Resource is the API resource to check: "secrets" (default if empty) or "configmaps".
	Resource string

	// SecretName is the resource name for GET tests. Empty for LIST and CREATE.
	SecretName string

	// Namespace is the namespace to test access in.
	Namespace string
}

// TestResult captures the outcome of a single test case.
type TestResult struct {
	TestCase
	Denied bool
	Detail string
}

// DefaultTests returns the standard access test cases for the given target namespace.
// All operations should be denied for the Secret probe ServiceAccount.
func DefaultTests(targetNamespace string) []TestCase {
	return []TestCase{
		// Secret read-path checks.
		{
			Description: "LIST secrets in target namespace",
			Verb:        "list",
			Resource:    "secrets",
			Namespace:   targetNamespace,
		},
		{
			Description: "GET well-known secret in target namespace",
			Verb:        "get",
			Resource:    "secrets",
			SecretName:  "default-token",
			Namespace:   targetNamespace,
		},
		{
			Description: "LIST secrets in kube-system",
			Verb:        "list",
			Resource:    "secrets",
			Namespace:   "kube-system",
		},
		{
			Description: "GET well-known secret in kube-system",
			Verb:        "get",
			Resource:    "secrets",
			SecretName:  "default-token",
			Namespace:   "kube-system",
		},
		// Cluster-wide enumeration: LIST /api/v1/secrets with no namespace
		// returns secrets across all namespaces. A principal able to perform
		// this call can exfiltrate the entire cluster's secret material.
		{
			Description: "LIST secrets cluster-wide",
			Verb:        "list",
			Resource:    "secrets",
			Namespace:   "",
		},
		// ConfigMap access checks — credential material (tokens, kubeconfigs,
		// connection strings) frequently leaks into ConfigMaps, and the
		// kube-system namespace holds cluster-critical configuration.
		{
			Description: "LIST configmaps in target namespace",
			Verb:        "list",
			Resource:    "configmaps",
			Namespace:   targetNamespace,
		},
		{
			Description: "LIST configmaps in kube-system",
			Verb:        "list",
			Resource:    "configmaps",
			Namespace:   "kube-system",
		},
		{
			Description: "GET kube-root-ca.crt configmap in target namespace",
			Verb:        "get",
			Resource:    "configmaps",
			SecretName:  "kube-root-ca.crt",
			Namespace:   targetNamespace,
		},
		// Write-path check — verifies that the probe ServiceAccount cannot
		// create Secrets. A misconfigured RBAC grant that allows write access
		// would let a compromised probe plant credentials in the namespace.
		// Dry-run=server is used so no resource is persisted even if RBAC
		// incorrectly allows the request.
		{
			Description: "CREATE secret in target namespace (write-path)",
			Verb:        "create",
			Resource:    "secrets",
			Namespace:   targetNamespace,
		},
	}
}

// Execute runs the Secret Access probe. It attempts actual API calls to verify
// that the probe ServiceAccount cannot read Secrets, read ConfigMaps in sensitive
// namespaces, or write Secrets in the target namespace. All attempts should be denied.
//
// Outcomes:
//   - Pass: all access attempts were denied (403 Forbidden / 404 Not Found)
//   - Fail: one or more operations succeeded
//   - Indeterminate: unexpected API errors prevented evaluation
func Execute(ctx context.Context, clientset kubernetes.Interface, cfg probe.Config) probe.Result {
	start := time.Now()

	tests := DefaultTests(cfg.TargetNamespace)

	var failures []string
	var apiErrors []string

	for _, tc := range tests {
		tr, err := checkAccess(ctx, clientset, tc)
		if err != nil {
			apiErrors = append(apiErrors, fmt.Sprintf("%s: %v", tc.Description, err))
			continue
		}
		if !tr.Denied {
			failures = append(failures, fmt.Sprintf("ACCESSIBLE: %s", tc.Description))
		}
	}

	duration := time.Since(start).Milliseconds()

	if len(apiErrors) > 0 {
		return probe.Result{
			Outcome:    "Indeterminate",
			Detail:     fmt.Sprintf("Unexpected API errors prevented full evaluation: %s", strings.Join(apiErrors, "; ")),
			DurationMs: duration,
		}
	}

	if len(failures) > 0 {
		return probe.Result{
			Outcome:    "Fail",
			Detail:     fmt.Sprintf("%d of %d checks failed: %s", len(failures), len(tests), strings.Join(failures, "; ")),
			DurationMs: duration,
		}
	}

	return probe.Result{
		Outcome:    "Pass",
		Detail:     fmt.Sprintf("All %d access checks denied", len(tests)),
		DurationMs: duration,
	}
}

// checkAccess dispatches to the appropriate check based on verb and resource type.
func checkAccess(ctx context.Context, clientset kubernetes.Interface, tc TestCase) (TestResult, error) {
	resource := tc.Resource
	if resource == "" {
		resource = "secrets"
	}

	switch tc.Verb {
	case "list":
		return checkList(ctx, clientset, tc, resource)
	case "get":
		return checkGet(ctx, clientset, tc, resource)
	case "create":
		return checkCreate(ctx, clientset, tc)
	default:
		return TestResult{}, fmt.Errorf("unsupported verb: %s", tc.Verb)
	}
}

func checkList(ctx context.Context, clientset kubernetes.Interface, tc TestCase, resource string) (TestResult, error) {
	var err error
	switch resource {
	case "secrets":
		_, err = clientset.CoreV1().Secrets(tc.Namespace).List(ctx, metav1.ListOptions{Limit: 1})
	case "configmaps":
		_, err = clientset.CoreV1().ConfigMaps(tc.Namespace).List(ctx, metav1.ListOptions{Limit: 1})
	default:
		return TestResult{}, fmt.Errorf("unsupported resource: %s", resource)
	}

	if err != nil {
		if k8serrors.IsForbidden(err) {
			return TestResult{TestCase: tc, Denied: true, Detail: "403 Forbidden"}, nil
		}
		return TestResult{}, fmt.Errorf("unexpected error: %w", err)
	}
	return TestResult{TestCase: tc, Denied: false, Detail: "list returned successfully"}, nil
}

func checkGet(ctx context.Context, clientset kubernetes.Interface, tc TestCase, resource string) (TestResult, error) {
	var err error
	switch resource {
	case "secrets":
		_, err = clientset.CoreV1().Secrets(tc.Namespace).Get(ctx, tc.SecretName, metav1.GetOptions{})
	case "configmaps":
		_, err = clientset.CoreV1().ConfigMaps(tc.Namespace).Get(ctx, tc.SecretName, metav1.GetOptions{})
	default:
		return TestResult{}, fmt.Errorf("unsupported resource: %s", resource)
	}

	if err != nil {
		if k8serrors.IsForbidden(err) {
			return TestResult{TestCase: tc, Denied: true, Detail: "403 Forbidden"}, nil
		}
		if k8serrors.IsNotFound(err) {
			// 404 means the SA can't see the resource — treated as denied.
			return TestResult{TestCase: tc, Denied: true, Detail: "404 Not Found (access denied)"}, nil
		}
		return TestResult{}, fmt.Errorf("unexpected error: %w", err)
	}
	return TestResult{TestCase: tc, Denied: false, Detail: fmt.Sprintf("%s was readable", resource)}, nil
}

// checkCreate attempts a dry-run=server Secret create in the target namespace.
// RBAC denial fires before dry-run processing, so 403 means least-privilege is
// enforced. Any non-error response means RBAC allows write access (control failure).
func checkCreate(ctx context.Context, clientset kubernetes.Interface, tc TestCase) (TestResult, error) {
	testSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "sidereal-secret-probe-write-",
			Namespace:    tc.Namespace,
			Labels: map[string]string{
				"sidereal.cloud/probe-write-check": "true",
			},
		},
	}

	_, err := clientset.CoreV1().Secrets(tc.Namespace).Create(ctx, testSecret, metav1.CreateOptions{
		DryRun: []string{metav1.DryRunAll},
	})
	if err != nil {
		if k8serrors.IsForbidden(err) {
			return TestResult{TestCase: tc, Denied: true, Detail: "403 Forbidden"}, nil
		}
		return TestResult{}, fmt.Errorf("unexpected error: %w", err)
	}
	// Dry-run create succeeded — RBAC allows write access (control failure).
	return TestResult{TestCase: tc, Denied: false, Detail: "dry-run create succeeded (write access granted)"}, nil
}
