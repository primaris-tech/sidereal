// Package rbac implements the RBAC probe runner, which validates that
// Kubernetes RBAC policies are operationally effective by testing both
// deny-path (unauthorized operations must fail) and allow-path
// (authorized operations must succeed) access controls.
package rbac

import (
	"context"
	"fmt"
	"strings"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/primaris-tech/sidereal/internal/probe"
)

// TestCase defines a single RBAC access check.
type TestCase struct {
	// Description is a human-readable label for the test.
	Description string

	// Group is the API group of the resource (e.g., "rbac.authorization.k8s.io").
	// Empty string means the core API group.
	Group string

	// Resource is the Kubernetes resource to check (e.g., "secrets", "pods").
	Resource string

	// Verb is the API verb to check (e.g., "get", "list", "create").
	Verb string

	// SubResource is an optional sub-resource (e.g., "exec").
	SubResource string

	// Namespace is the namespace in which to check access.
	Namespace string

	// ExpectAllowed indicates whether this operation should be permitted.
	// Deny-path tests set this to false; allow-path tests set it to true.
	ExpectAllowed bool
}

// TestResult captures the outcome of a single test case.
type TestResult struct {
	TestCase
	Allowed bool
	Reason  string
	Passed  bool
}

// DefaultDenyTests returns the standard deny-path test cases for the given
// target namespace. These operations should be forbidden for the RBAC probe
// ServiceAccount.
func DefaultDenyTests(targetNamespace string) []TestCase {
	return []TestCase{
		{
			Description:   "GET secrets in target namespace",
			Resource:      "secrets",
			Verb:          "get",
			Namespace:     targetNamespace,
			ExpectAllowed: false,
		},
		{
			Description:   "LIST secrets in target namespace",
			Resource:      "secrets",
			Verb:          "list",
			Namespace:     targetNamespace,
			ExpectAllowed: false,
		},
		{
			Description:   "Pod exec in target namespace",
			Resource:      "pods",
			Verb:          "create",
			SubResource:   "exec",
			Namespace:     targetNamespace,
			ExpectAllowed: false,
		},
		{
			Description:   "CREATE pods in target namespace",
			Resource:      "pods",
			Verb:          "create",
			Namespace:     targetNamespace,
			ExpectAllowed: false,
		},
	}
}

// DefaultAllowTests returns the standard allow-path test cases. These
// operations should be permitted for the RBAC probe ServiceAccount.
func DefaultAllowTests(targetNamespace string) []TestCase {
	return []TestCase{
		{
			Description:   "LIST rolebindings in target namespace",
			Group:         "rbac.authorization.k8s.io",
			Resource:      "rolebindings",
			Verb:          "list",
			Namespace:     targetNamespace,
			ExpectAllowed: true,
		},
		{
			Description:   "GET rolebindings in target namespace",
			Group:         "rbac.authorization.k8s.io",
			Resource:      "rolebindings",
			Verb:          "get",
			Namespace:     targetNamespace,
			ExpectAllowed: true,
		},
	}
}

// Execute runs the RBAC probe against the target namespace using the
// SelfSubjectAccessReview API. It returns a probe.Result with outcome
// Pass (all checks match expectations), Fail (any check violated), or
// Indeterminate (API errors prevented evaluation).
func Execute(ctx context.Context, clientset kubernetes.Interface, cfg probe.Config) probe.Result {
	start := time.Now()

	tests := append(DefaultDenyTests(cfg.TargetNamespace), DefaultAllowTests(cfg.TargetNamespace)...)

	var failures []string
	var apiErrors []string

	for _, tc := range tests {
		tr, err := checkAccess(ctx, clientset, tc)
		if err != nil {
			apiErrors = append(apiErrors, fmt.Sprintf("%s: %v", tc.Description, err))
			continue
		}
		if !tr.Passed {
			if tc.ExpectAllowed {
				failures = append(failures, fmt.Sprintf("OVER-DENIED: %s (expected allowed, got denied)", tc.Description))
			} else {
				failures = append(failures, fmt.Sprintf("UNDER-RESTRICTED: %s (expected denied, got allowed)", tc.Description))
			}
		}
	}

	duration := time.Since(start).Milliseconds()

	if len(apiErrors) > 0 {
		return probe.Result{
			Outcome:    "Indeterminate",
			Detail:     fmt.Sprintf("API errors prevented full evaluation: %s", strings.Join(apiErrors, "; ")),
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
		Detail:     fmt.Sprintf("All %d RBAC checks passed for namespace %s", len(tests), cfg.TargetNamespace),
		DurationMs: duration,
	}
}

// checkAccess performs a SelfSubjectAccessReview for the given test case.
func checkAccess(ctx context.Context, clientset kubernetes.Interface, tc TestCase) (TestResult, error) {
	review := &authzv1.SelfSubjectAccessReview{
		Spec: authzv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace:   tc.Namespace,
				Verb:        tc.Verb,
				Group:       tc.Group,
				Resource:    tc.Resource,
				Subresource: tc.SubResource,
			},
		},
	}

	result, err := clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return TestResult{}, fmt.Errorf("SelfSubjectAccessReview failed: %w", err)
	}

	allowed := result.Status.Allowed
	passed := allowed == tc.ExpectAllowed

	return TestResult{
		TestCase: tc,
		Allowed:  allowed,
		Reason:   result.Status.Reason,
		Passed:   passed,
	}, nil
}
