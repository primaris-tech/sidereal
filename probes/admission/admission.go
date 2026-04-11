// Package admission implements the Admission Control probe runner, which
// validates that admission webhooks are rejecting non-compliant pod specs.
// It uses --dry-run=server to submit pods for admission evaluation without
// persisting them.
package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/primaris-tech/sidereal/internal/probe"
)

// Config holds admission-probe-specific configuration loaded from environment.
type Config struct {
	// TargetPolicy is the name of the specific admission policy to test (override mode).
	TargetPolicy string

	// KnownBadSpec is a JSON-encoded PodSpec provided by the operator (override mode).
	KnownBadSpec string
}

// LoadConfig reads admission-specific configuration from environment variables.
func LoadConfig() Config {
	return Config{
		TargetPolicy: os.Getenv("ADMISSION_TARGET_POLICY"),
		KnownBadSpec: os.Getenv("ADMISSION_KNOWN_BAD_SPEC"),
	}
}

// Execute runs the Admission Control probe.
//
// Steps:
//  1. Check for ValidatingWebhookConfiguration or MutatingWebhookConfiguration.
//     If none exist, return NotApplicable.
//  2. Build a known-bad pod spec (default or operator-provided).
//  3. Submit it via dry-run=server. Expect rejection.
//  4. Rejected = Rejected (pass). Accepted = Accepted (fail).
//
// Outcomes:
//   - Rejected: admission webhook correctly rejected the non-compliant spec
//   - Accepted: admission webhook allowed the non-compliant spec (control failure)
//   - NotApplicable: no admission webhooks are configured
//   - Indeterminate: API errors prevented evaluation
func Execute(ctx context.Context, clientset kubernetes.Interface, cfg probe.Config) probe.Result {
	start := time.Now()
	admCfg := LoadConfig()

	result := execute(ctx, clientset, cfg, admCfg)
	result.DurationMs = time.Since(start).Milliseconds()
	return result
}

// ExecuteWithConfig is like Execute but accepts an explicit admission Config
// (used in testing to avoid environment variable dependency).
func ExecuteWithConfig(ctx context.Context, clientset kubernetes.Interface, cfg probe.Config, admCfg Config) probe.Result {
	start := time.Now()

	result := execute(ctx, clientset, cfg, admCfg)
	result.DurationMs = time.Since(start).Milliseconds()
	return result
}

func execute(ctx context.Context, clientset kubernetes.Interface, cfg probe.Config, admCfg Config) probe.Result {
	// Step 1: Check for admission webhooks.
	hasWebhooks, err := hasAdmissionWebhooks(ctx, clientset)
	if err != nil {
		return probe.Result{
			Outcome: "Indeterminate",
			Detail:  fmt.Sprintf("failed to check for admission webhooks: %v", err),
		}
	}
	if !hasWebhooks {
		return probe.Result{
			Outcome: "NotApplicable",
			Detail:  "no ValidatingWebhookConfiguration or MutatingWebhookConfiguration found",
		}
	}

	// Step 2: Build the pod spec to submit.
	pod, err := buildTestPod(cfg.TargetNamespace, admCfg)
	if err != nil {
		return probe.Result{
			Outcome: "Indeterminate",
			Detail:  fmt.Sprintf("failed to build test pod spec: %v", err),
		}
	}

	// Step 3: Submit via dry-run=server.
	_, err = clientset.CoreV1().Pods(cfg.TargetNamespace).Create(ctx, pod, metav1.CreateOptions{
		DryRun: []string{metav1.DryRunAll},
	})

	if err != nil {
		// Rejection by admission webhook is the expected (good) outcome.
		if k8serrors.IsForbidden(err) || k8serrors.IsInvalid(err) {
			detail := fmt.Sprintf("admission webhook rejected the non-compliant spec: %v", err)
			if admCfg.TargetPolicy != "" {
				detail = fmt.Sprintf("policy %q rejected the spec: %v", admCfg.TargetPolicy, err)
			}
			return probe.Result{
				Outcome: "Rejected",
				Detail:  detail,
			}
		}
		// Unexpected error.
		return probe.Result{
			Outcome: "Indeterminate",
			Detail:  fmt.Sprintf("unexpected error during dry-run create: %v", err),
		}
	}

	// Step 4: Pod was accepted (bad — admission should have rejected it).
	detail := "admission webhook accepted the non-compliant spec"
	if admCfg.TargetPolicy != "" {
		detail = fmt.Sprintf("policy %q did not reject the spec", admCfg.TargetPolicy)
	}
	return probe.Result{
		Outcome: "Accepted",
		Detail:  detail,
	}
}

// hasAdmissionWebhooks checks if any ValidatingWebhookConfiguration or
// MutatingWebhookConfiguration resources exist in the cluster.
func hasAdmissionWebhooks(ctx context.Context, clientset kubernetes.Interface) (bool, error) {
	vwc, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		return false, fmt.Errorf("listing ValidatingWebhookConfigurations: %w", err)
	}
	if len(vwc.Items) > 0 {
		return true, nil
	}

	mwc, err := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		return false, fmt.Errorf("listing MutatingWebhookConfigurations: %w", err)
	}
	return len(mwc.Items) > 0, nil
}

// defaultBadPod returns a pod spec that should be rejected by any reasonable
// admission policy: privileged container, host PID, host network, running as
// root, writable root filesystem.
func defaultBadPod(namespace string) *corev1.Pod {
	privileged := true
	runAsRoot := int64(0)

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "sidereal-admission-probe-",
			Namespace:    namespace,
			Labels: map[string]string{
				"sidereal.cloud/admission-probe": "true",
			},
		},
		Spec: corev1.PodSpec{
			HostPID:     true,
			HostNetwork: true,
			Containers: []corev1.Container{
				{
					Name:  "probe",
					Image: "busybox:latest",
					SecurityContext: &corev1.SecurityContext{
						Privileged: &privileged,
						RunAsUser:  &runAsRoot,
					},
				},
			},
		},
	}
}

// buildTestPod returns either the operator-provided knownBadSpec or the default bad pod.
func buildTestPod(namespace string, admCfg Config) (*corev1.Pod, error) {
	if admCfg.KnownBadSpec == "" {
		return defaultBadPod(namespace), nil
	}

	var pod corev1.Pod
	if err := json.Unmarshal([]byte(admCfg.KnownBadSpec), &pod); err != nil {
		return nil, fmt.Errorf("failed to unmarshal knownBadSpec: %w", err)
	}

	// Ensure the probe label is present for fingerprinting.
	if pod.Labels == nil {
		pod.Labels = make(map[string]string)
	}
	pod.Labels["sidereal.cloud/admission-probe"] = "true"

	// Override namespace to match probe config.
	pod.Namespace = namespace

	return &pod, nil
}
