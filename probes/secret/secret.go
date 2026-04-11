// Package secret implements the Secret Access probe runner, which validates
// that cross-namespace Secret access is denied. Unlike the RBAC probe (which
// checks permissions via SelfSubjectAccessReview), this probe attempts actual
// Secret API calls to verify that access controls are operationally effective.
package secret

import (
	"context"
	"fmt"
	"strings"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/primaris-tech/sidereal/internal/probe"
)

// TestCase defines a single Secret access check.
type TestCase struct {
	// Description is a human-readable label for the test.
	Description string

	// Verb is "get" or "list".
	Verb string

	// SecretName is the specific Secret name for GET tests. Empty for LIST.
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

// DefaultTests returns the standard Secret access test cases for the given
// target namespace. All operations should be denied for the Secret probe SA.
func DefaultTests(targetNamespace string) []TestCase {
	return []TestCase{
		{
			Description: "LIST secrets in target namespace",
			Verb:        "list",
			Namespace:   targetNamespace,
		},
		{
			Description: "GET well-known secret in target namespace",
			Verb:        "get",
			SecretName:  "default-token",
			Namespace:   targetNamespace,
		},
		{
			Description: "LIST secrets in kube-system",
			Verb:        "list",
			Namespace:   "kube-system",
		},
		{
			Description: "GET well-known secret in kube-system",
			Verb:        "get",
			SecretName:  "default-token",
			Namespace:   "kube-system",
		},
	}
}

// Execute runs the Secret Access probe. It attempts actual GET and LIST
// operations against Secrets in the target namespace (and kube-system as
// a high-value cross-namespace check). All attempts should be denied.
//
// Outcomes:
//   - Pass: all Secret access attempts were denied (403 Forbidden)
//   - Fail: one or more Secrets were readable
//   - Indeterminate: unexpected API errors prevented evaluation
func Execute(ctx context.Context, clientset kubernetes.Interface, cfg probe.Config) probe.Result {
	start := time.Now()

	tests := DefaultTests(cfg.TargetNamespace)

	var results []TestResult
	var failures []string
	var apiErrors []string

	for _, tc := range tests {
		tr, err := checkSecretAccess(ctx, clientset, tc)
		if err != nil {
			apiErrors = append(apiErrors, fmt.Sprintf("%s: %v", tc.Description, err))
			continue
		}
		results = append(results, tr)
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
		Detail:     fmt.Sprintf("All %d Secret access checks denied", len(tests)),
		DurationMs: duration,
	}
}

// checkSecretAccess attempts the actual API call and checks whether it was denied.
// A 403 Forbidden response means access is correctly denied (good).
// A 404 Not Found on GET is also treated as denied — the SA lacks list/watch
// permissions so the API server returns 404 rather than 403 in some configurations.
// Any successful response means access was granted (bad).
func checkSecretAccess(ctx context.Context, clientset kubernetes.Interface, tc TestCase) (TestResult, error) {
	secrets := clientset.CoreV1().Secrets(tc.Namespace)

	switch tc.Verb {
	case "list":
		_, err := secrets.List(ctx, metav1.ListOptions{Limit: 1})
		if err != nil {
			if k8serrors.IsForbidden(err) {
				return TestResult{TestCase: tc, Denied: true, Detail: "403 Forbidden"}, nil
			}
			// Unexpected error (network, timeout, etc.)
			return TestResult{}, fmt.Errorf("unexpected error: %w", err)
		}
		// List succeeded — access was granted.
		return TestResult{TestCase: tc, Denied: false, Detail: "list returned successfully"}, nil

	case "get":
		_, err := secrets.Get(ctx, tc.SecretName, metav1.GetOptions{})
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
		// Get succeeded — access was granted.
		return TestResult{TestCase: tc, Denied: false, Detail: "secret was readable"}, nil

	default:
		return TestResult{}, fmt.Errorf("unsupported verb: %s", tc.Verb)
	}
}
