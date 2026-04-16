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
	"strings"
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

	// SeccompEnforcement indicates the cluster enforces seccomp profiles via admission.
	// When true, the probe submits an otherwise-compliant pod with seccompProfile: Unconfined
	// and expects rejection. Also auto-enabled when the target namespace carries the
	// pod-security.kubernetes.io/enforce: restricted label.
	SeccompEnforcement bool

	// UnauthorizedImageRef is an image reference that the cluster's image authorization
	// policy should reject (e.g., an unsigned or out-of-registry image). When non-empty,
	// the probe submits an otherwise-compliant pod referencing this image and expects
	// rejection. When empty, the image authorization test is skipped.
	UnauthorizedImageRef string
}

// LoadConfig reads admission-specific configuration from environment variables.
func LoadConfig() Config {
	return Config{
		TargetPolicy:         os.Getenv("ADMISSION_TARGET_POLICY"),
		KnownBadSpec:         os.Getenv("ADMISSION_KNOWN_BAD_SPEC"),
		SeccompEnforcement:   os.Getenv("ADMISSION_SECCOMP_ENFORCEMENT") == "true",
		UnauthorizedImageRef: os.Getenv("ADMISSION_UNAUTHORIZED_IMAGE_REF"),
	}
}

// testOutcome records the result of a single dry-run pod submission.
type testOutcome struct {
	name    string
	outcome string // "Rejected", "Accepted", "Indeterminate"
	detail  string
}

// Execute runs the Admission Control probe.
//
// Steps:
//  1. Check for ValidatingWebhookConfiguration or MutatingWebhookConfiguration.
//     If none exist, return NotApplicable.
//  2. Run the security-context test: submit a known-bad pod spec (default or
//     operator-provided). Expect rejection.
//  3. If seccomp enforcement is active (explicit config or PSA restricted label),
//     run the seccomp-unconfined test: submit an otherwise-compliant pod with
//     seccompProfile: Unconfined. Expect rejection.
//  4. If UnauthorizedImageRef is configured, run the image-authorization test:
//     submit an otherwise-compliant pod referencing the unauthorized image. Expect
//     rejection.
//
// Outcomes:
//   - Rejected: all applicable tests were rejected (controls enforced)
//   - Accepted: one or more tests were not rejected (control gap)
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

	var outcomes []testOutcome

	// Test 1: security-context (CM-6, CM-7)
	// Submits a pod that is privileged, hostPID, hostNetwork, and root.
	pod, err := buildTestPod(cfg.TargetNamespace, admCfg)
	if err != nil {
		return probe.Result{
			Outcome: "Indeterminate",
			Detail:  fmt.Sprintf("failed to build test pod spec: %v", err),
		}
	}
	o := runDryRunPodTest(ctx, clientset, cfg.TargetNamespace, pod, "security-context", admCfg.TargetPolicy)
	if o.outcome == "Indeterminate" {
		return probe.Result{Outcome: "Indeterminate", Detail: o.detail}
	}
	outcomes = append(outcomes, o)

	// Test 2: seccomp-unconfined (CM-7(2))
	// Submits an otherwise-compliant pod with seccompProfile: Unconfined.
	// Only runs when explicitly configured or auto-detected via PSA restricted label.
	runSeccomp := admCfg.SeccompEnforcement
	if !runSeccomp {
		if level, err := namespacePSALevel(ctx, clientset, cfg.TargetNamespace); err == nil {
			runSeccomp = level == "restricted"
		}
		// Namespace lookup failure → skip rather than surface as Indeterminate;
		// absence of PSA metadata is not itself an error.
	}
	if runSeccomp {
		o := runDryRunPodTest(ctx, clientset, cfg.TargetNamespace, seccompUnconfinedPod(cfg.TargetNamespace), "seccomp-unconfined", "")
		if o.outcome == "Indeterminate" {
			return probe.Result{Outcome: "Indeterminate", Detail: o.detail}
		}
		outcomes = append(outcomes, o)
	}

	// Test 3: image-authorization (CM-7(5))
	// Submits an otherwise-compliant pod referencing an image the operator has
	// declared should be rejected by their image authorization policy.
	// Skipped when UnauthorizedImageRef is not configured.
	if admCfg.UnauthorizedImageRef != "" {
		o := runDryRunPodTest(ctx, clientset, cfg.TargetNamespace, imageAuthPod(cfg.TargetNamespace, admCfg.UnauthorizedImageRef), "image-authorization", "")
		if o.outcome == "Indeterminate" {
			return probe.Result{Outcome: "Indeterminate", Detail: o.detail}
		}
		outcomes = append(outcomes, o)
	}

	// Evaluate overall result.
	var accepted []string
	for _, o := range outcomes {
		if o.outcome == "Accepted" {
			accepted = append(accepted, fmt.Sprintf("%s: %s", o.name, o.detail))
		}
	}

	if len(accepted) > 0 {
		return probe.Result{
			Outcome: "Accepted",
			Detail:  fmt.Sprintf("admission webhook accepted non-compliant spec(s): %s", strings.Join(accepted, "; ")),
		}
	}

	var rejectedDetails []string
	for _, o := range outcomes {
		rejectedDetails = append(rejectedDetails, fmt.Sprintf("%s: %s", o.name, o.detail))
	}
	return probe.Result{
		Outcome: "Rejected",
		Detail:  strings.Join(rejectedDetails, "; "),
	}
}

// runDryRunPodTest submits pod via dry-run=server and returns whether it was rejected.
func runDryRunPodTest(ctx context.Context, clientset kubernetes.Interface, namespace string, pod *corev1.Pod, testName string, policyName string) testOutcome {
	_, err := clientset.CoreV1().Pods(namespace).Create(ctx, pod, metav1.CreateOptions{
		DryRun: []string{metav1.DryRunAll},
	})

	if err != nil {
		if k8serrors.IsForbidden(err) || k8serrors.IsInvalid(err) {
			detail := fmt.Sprintf("admission webhook rejected the non-compliant spec: %v", err)
			if policyName != "" {
				detail = fmt.Sprintf("policy %q rejected the spec: %v", policyName, err)
			}
			return testOutcome{name: testName, outcome: "Rejected", detail: detail}
		}
		return testOutcome{
			name:    testName,
			outcome: "Indeterminate",
			detail:  fmt.Sprintf("unexpected error during dry-run create: %v", err),
		}
	}

	detail := "admission webhook accepted the non-compliant spec"
	if policyName != "" {
		detail = fmt.Sprintf("policy %q did not reject the spec", policyName)
	}
	return testOutcome{name: testName, outcome: "Accepted", detail: detail}
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

// namespacePSALevel returns the pod-security.kubernetes.io/enforce label value
// for the given namespace, or empty string if absent.
func namespacePSALevel(ctx context.Context, clientset kubernetes.Interface, namespace string) (string, error) {
	ns, err := clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("getting namespace %s: %w", namespace, err)
	}
	return ns.Labels["pod-security.kubernetes.io/enforce"], nil
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

// seccompUnconfinedPod returns an otherwise-compliant pod spec that explicitly
// disables seccomp (seccompProfile: Unconfined). Clusters enforcing PSA restricted
// or a seccomp admission policy should reject this. Used to validate CM-7(2).
func seccompUnconfinedPod(namespace string) *corev1.Pod {
	nonRoot := true
	runAsUser := int64(65532)
	allowPrivEsc := false

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "sidereal-admission-probe-seccomp-",
			Namespace:    namespace,
			Labels: map[string]string{
				"sidereal.cloud/admission-probe": "true",
			},
		},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeUnconfined,
				},
			},
			Containers: []corev1.Container{
				{
					Name:  "probe",
					Image: "gcr.io/distroless/static:nonroot",
					SecurityContext: &corev1.SecurityContext{
						RunAsNonRoot:             &nonRoot,
						RunAsUser:                &runAsUser,
						AllowPrivilegeEscalation: &allowPrivEsc,
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"ALL"},
						},
					},
				},
			},
		},
	}
}

// imageAuthPod returns an otherwise-compliant pod spec referencing imageRef.
// Every security context field satisfies PSA restricted so that any rejection
// is attributable to the image source, not the pod configuration. Used to
// validate CM-7(5).
func imageAuthPod(namespace, imageRef string) *corev1.Pod {
	nonRoot := true
	runAsUser := int64(65532)
	allowPrivEsc := false

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "sidereal-admission-probe-imgauth-",
			Namespace:    namespace,
			Labels: map[string]string{
				"sidereal.cloud/admission-probe": "true",
			},
		},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				},
			},
			Containers: []corev1.Container{
				{
					Name:  "probe",
					Image: imageRef,
					SecurityContext: &corev1.SecurityContext{
						RunAsNonRoot:             &nonRoot,
						RunAsUser:               &runAsUser,
						AllowPrivilegeEscalation: &allowPrivEsc,
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"ALL"},
						},
					},
				},
			},
		},
	}
}

// buildTestPod returns either the operator-provided KnownBadSpec or the default bad pod.
func buildTestPod(namespace string, admCfg Config) (*corev1.Pod, error) {
	if admCfg.KnownBadSpec == "" {
		return defaultBadPod(namespace), nil
	}

	var pod corev1.Pod
	if err := json.Unmarshal([]byte(admCfg.KnownBadSpec), &pod); err != nil {
		return nil, fmt.Errorf("failed to unmarshal knownBadSpec: %w", err)
	}

	if pod.Labels == nil {
		pod.Labels = make(map[string]string)
	}
	pod.Labels["sidereal.cloud/admission-probe"] = "true"
	pod.Namespace = namespace

	return &pod, nil
}
