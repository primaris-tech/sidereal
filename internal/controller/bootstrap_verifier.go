package controller

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/metrics"
)

// BuiltInServiceAccounts lists the 7 ServiceAccounts required for Sidereal operation.
var BuiltInServiceAccounts = []string{
	"sidereal-controller",
	"sidereal-probe-rbac",
	"sidereal-probe-netpol",
	"sidereal-probe-admission",
	"sidereal-probe-secret",
	"sidereal-probe-detection",
	"sidereal-discovery",
}

// HMACRootSecretName is declared in probe_scheduler.go

// BootstrapCheck represents a single verification check.
type BootstrapCheck struct {
	// Name is a human-readable label for the check.
	Name string

	// Passed indicates whether the check succeeded.
	Passed bool

	// Detail provides context on the check result.
	Detail string
}

// BootstrapResult aggregates all bootstrap verification checks.
type BootstrapResult struct {
	Checks []BootstrapCheck
	Passed bool
}

// FailedChecks returns only the checks that did not pass.
func (r *BootstrapResult) FailedChecks() []BootstrapCheck {
	var failed []BootstrapCheck
	for _, c := range r.Checks {
		if !c.Passed {
			failed = append(failed, c)
		}
	}
	return failed
}

// Summary returns a human-readable summary of the bootstrap result.
func (r *BootstrapResult) Summary() string {
	passed := 0
	for _, c := range r.Checks {
		if c.Passed {
			passed++
		}
	}

	if r.Passed {
		return fmt.Sprintf("bootstrap verification passed: %d/%d checks OK", passed, len(r.Checks))
	}

	var failures []string
	for _, c := range r.FailedChecks() {
		failures = append(failures, fmt.Sprintf("%s: %s", c.Name, c.Detail))
	}
	return fmt.Sprintf("bootstrap verification failed: %d/%d checks passed. Failures: %s",
		passed, len(r.Checks), strings.Join(failures, "; "))
}

// RunBootstrapVerification executes all prerequisite checks for the Sidereal
// controller. It is called on startup and periodically for drift detection.
func RunBootstrapVerification(ctx context.Context, c client.Client) *BootstrapResult {
	logger := log.FromContext(ctx)

	result := &BootstrapResult{}

	// Check ServiceAccounts.
	result.Checks = append(result.Checks, checkServiceAccounts(ctx, c)...)

	// Check HMAC root Secret.
	result.Checks = append(result.Checks, checkHMACSecret(ctx, c))

	// Check NetworkPolicy.
	result.Checks = append(result.Checks, checkNetworkPolicy(ctx, c))

	// Determine overall result.
	result.Passed = true
	for _, check := range result.Checks {
		if !check.Passed {
			result.Passed = false
			break
		}
	}

	// Update metrics.
	if result.Passed {
		metrics.BootstrapVerificationStatus.Set(1)
		logger.Info("bootstrap verification passed", "checks", len(result.Checks))
	} else {
		metrics.BootstrapVerificationStatus.Set(0)
		logger.Error(nil, "bootstrap verification failed", "summary", result.Summary())
	}

	return result
}

// HandleBootstrapFailure creates a SiderealSystemAlert for bootstrap failures
// if one doesn't already exist.
func HandleBootstrapFailure(ctx context.Context, c client.Client, result *BootstrapResult) error {
	if result.Passed {
		return nil
	}

	alertName := "sidereal-alert-bootstrap-failed"

	// Check if alert already exists.
	var existing siderealv1alpha1.SiderealSystemAlert
	if err := c.Get(ctx, types.NamespacedName{
		Name:      alertName,
		Namespace: SystemNamespace,
	}, &existing); err == nil {
		return nil // already exists
	}

	alert := &siderealv1alpha1.SiderealSystemAlert{
		ObjectMeta: metav1.ObjectMeta{
			Name:      alertName,
			Namespace: SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealSystemAlertSpec{
			Reason:  siderealv1alpha1.AlertReasonBaselineConfigurationDrift,
			Message: result.Summary(),
		},
	}

	return c.Create(ctx, alert)
}

// checkServiceAccounts verifies all built-in ServiceAccounts exist.
func checkServiceAccounts(ctx context.Context, c client.Client) []BootstrapCheck {
	var checks []BootstrapCheck

	for _, saName := range BuiltInServiceAccounts {
		var sa corev1.ServiceAccount
		err := c.Get(ctx, types.NamespacedName{
			Name:      saName,
			Namespace: SystemNamespace,
		}, &sa)

		if err != nil {
			checks = append(checks, BootstrapCheck{
				Name:   fmt.Sprintf("ServiceAccount/%s", saName),
				Passed: false,
				Detail: fmt.Sprintf("not found: %v", err),
			})
		} else {
			checks = append(checks, BootstrapCheck{
				Name:   fmt.Sprintf("ServiceAccount/%s", saName),
				Passed: true,
				Detail: "exists",
			})
		}
	}

	return checks
}

// checkHMACSecret verifies the HMAC root key Secret exists and has data.
func checkHMACSecret(ctx context.Context, c client.Client) BootstrapCheck {
	var secret corev1.Secret
	err := c.Get(ctx, types.NamespacedName{
		Name:      HMACRootSecretName,
		Namespace: SystemNamespace,
	}, &secret)

	if err != nil {
		return BootstrapCheck{
			Name:   "Secret/sidereal-hmac-root",
			Passed: false,
			Detail: fmt.Sprintf("not found: %v", err),
		}
	}

	if len(secret.Data["hmac-key"]) == 0 {
		return BootstrapCheck{
			Name:   "Secret/sidereal-hmac-root",
			Passed: false,
			Detail: "hmac-key is empty",
		}
	}

	return BootstrapCheck{
		Name:   "Secret/sidereal-hmac-root",
		Passed: true,
		Detail: "exists with hmac-key data",
	}
}

// checkNetworkPolicy verifies at least one NetworkPolicy exists in sidereal-system.
func checkNetworkPolicy(ctx context.Context, c client.Client) BootstrapCheck {
	var policies networkingv1.NetworkPolicyList
	if err := c.List(ctx, &policies, client.InNamespace(SystemNamespace)); err != nil {
		return BootstrapCheck{
			Name:   "NetworkPolicy/sidereal-system",
			Passed: false,
			Detail: fmt.Sprintf("failed to list: %v", err),
		}
	}

	if len(policies.Items) == 0 {
		return BootstrapCheck{
			Name:   "NetworkPolicy/sidereal-system",
			Passed: false,
			Detail: "no NetworkPolicy found in sidereal-system namespace",
		}
	}

	return BootstrapCheck{
		Name:   "NetworkPolicy/sidereal-system",
		Passed: true,
		Detail: fmt.Sprintf("%d NetworkPolicy resources found", len(policies.Items)),
	}
}
