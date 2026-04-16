package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/primaris-tech/sidereal/internal/probe"
)

func baseCfg() probe.Config {
	return probe.Config{
		ProbeID:         "test-admission-1",
		Profile:         "admission",
		TargetNamespace: "production",
		ExecutionMode:   "dryRun",
	}
}

// clientsetWithWebhook returns a clientset that has a ValidatingWebhookConfiguration.
func clientsetWithWebhook(objects ...runtime.Object) *fake.Clientset {
	all := []runtime.Object{
		&admissionregv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "kyverno-policy"},
		},
	}
	all = append(all, objects...)
	return fake.NewSimpleClientset(all...)
}

// clientsetWithWebhookAndPSA returns a clientset with a webhook and the target
// namespace labeled with PSA restricted enforcement.
func clientsetWithWebhookAndPSA(objects ...runtime.Object) *fake.Clientset {
	all := []runtime.Object{
		&admissionregv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "kyverno-policy"},
		},
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "production",
				Labels: map[string]string{
					"pod-security.kubernetes.io/enforce": "restricted",
				},
			},
		},
	}
	all = append(all, objects...)
	return fake.NewSimpleClientset(all...)
}

// clientsetNoWebhooks returns a clientset with no admission webhooks.
func clientsetNoWebhooks() *fake.Clientset {
	return fake.NewSimpleClientset()
}

// rejectAll returns a reactor that rejects all pod creates with Forbidden.
func rejectAll() k8stesting.ReactionFunc {
	return func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serrors.NewForbidden(
			schema.GroupResource{Resource: "pods"},
			"",
			fmt.Errorf("violates policy"),
		)
	}
}

// rejectByGenerateName returns a reactor that rejects pod creates whose
// GenerateName exactly matches generateName, and falls through for others.
// Exact match is required because the seccomp and imgauth GenerateNames share
// the "sidereal-admission-probe-" prefix with the bad pod.
func rejectByGenerateName(generateName string) k8stesting.ReactionFunc {
	return func(action k8stesting.Action) (bool, runtime.Object, error) {
		createAction := action.(k8stesting.CreateAction)
		pod := createAction.GetObject().(*corev1.Pod)
		if pod.GenerateName == generateName {
			return true, nil, k8serrors.NewForbidden(
				schema.GroupResource{Resource: "pods"},
				"",
				fmt.Errorf("violates policy"),
			)
		}
		return false, nil, nil
	}
}

func TestExecute_Rejected(t *testing.T) {
	cs := clientsetWithWebhook()
	cs.PrependReactor("create", "pods", rejectAll())

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), Config{})

	if result.Outcome != "Rejected" {
		t.Errorf("expected Rejected, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_Accepted(t *testing.T) {
	// Webhook exists but pod creation succeeds (no rejection).
	cs := clientsetWithWebhook()

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), Config{})

	if result.Outcome != "Accepted" {
		t.Errorf("expected Accepted, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_NotApplicable(t *testing.T) {
	cs := clientsetNoWebhooks()

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), Config{})

	if result.Outcome != "NotApplicable" {
		t.Errorf("expected NotApplicable, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_WebhookCheckError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "validatingwebhookconfigurations", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, &k8serrors.StatusError{
			ErrStatus: metav1.Status{
				Status:  metav1.StatusFailure,
				Code:    http.StatusInternalServerError,
				Reason:  metav1.StatusReasonInternalError,
				Message: "api server error",
			},
		}
	})

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), Config{})

	if result.Outcome != "Indeterminate" {
		t.Errorf("expected Indeterminate, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_PodCreateAPIError(t *testing.T) {
	cs := clientsetWithWebhook()
	cs.PrependReactor("create", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, &k8serrors.StatusError{
			ErrStatus: metav1.Status{
				Status:  metav1.StatusFailure,
				Code:    http.StatusServiceUnavailable,
				Reason:  metav1.StatusReasonServiceUnavailable,
				Message: "service unavailable",
			},
		}
	})

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), Config{})

	if result.Outcome != "Indeterminate" {
		t.Errorf("expected Indeterminate for API error, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_InvalidRejection(t *testing.T) {
	// Some admission webhooks return IsInvalid rather than IsForbidden.
	cs := clientsetWithWebhook()
	cs.PrependReactor("create", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serrors.NewInvalid(
			schema.GroupKind{Kind: "Pod"},
			"sidereal-admission-probe-xyz",
			nil,
		)
	})

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), Config{})

	if result.Outcome != "Rejected" {
		t.Errorf("expected Rejected for IsInvalid error, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_OverrideMode(t *testing.T) {
	cs := clientsetWithWebhook()
	cs.PrependReactor("create", "pods", rejectAll())

	admCfg := Config{TargetPolicy: "custom-policy"}

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), admCfg)

	if result.Outcome != "Rejected" {
		t.Errorf("expected Rejected, got %q: %s", result.Outcome, result.Detail)
	}
	if !strings.Contains(result.Detail, "custom-policy") {
		t.Errorf("expected policy name in detail, got %q", result.Detail)
	}
}

func TestExecute_KnownBadSpec(t *testing.T) {
	cs := clientsetWithWebhook()
	cs.PrependReactor("create", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		createAction := action.(k8stesting.CreateAction)
		pod := createAction.GetObject().(*corev1.Pod)
		if pod.Spec.Containers[0].Name != "evil" {
			t.Errorf("expected container name 'evil', got %q", pod.Spec.Containers[0].Name)
		}
		if pod.Labels["sidereal.cloud/admission-probe"] != "true" {
			t.Error("expected sidereal admission-probe label")
		}
		return true, nil, k8serrors.NewForbidden(
			schema.GroupResource{Resource: "pods"},
			"",
			fmt.Errorf("rejected"),
		)
	})

	badPod := corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "evil", Image: "evil:latest"},
			},
		},
	}
	badPodJSON, _ := json.Marshal(badPod)

	admCfg := Config{KnownBadSpec: string(badPodJSON)}

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), admCfg)

	if result.Outcome != "Rejected" {
		t.Errorf("expected Rejected, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_InvalidKnownBadSpec(t *testing.T) {
	cs := clientsetWithWebhook()

	admCfg := Config{KnownBadSpec: "not valid json{{{"}

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), admCfg)

	if result.Outcome != "Indeterminate" {
		t.Errorf("expected Indeterminate for bad JSON, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_MutatingWebhookOnly(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&admissionregv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "istio-sidecar-injector"},
		},
	)

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), Config{})

	if result.Outcome != "Accepted" {
		t.Errorf("expected Accepted (mutating webhook exists but didn't reject), got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_DurationTracked(t *testing.T) {
	cs := clientsetNoWebhooks()

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), Config{})

	if result.DurationMs < 0 {
		t.Errorf("expected non-negative duration, got %d", result.DurationMs)
	}
}

// --- CM-7(2): seccomp enforcement tests ---

func TestExecute_SeccompRejectedViaPSA(t *testing.T) {
	// Namespace has PSA restricted — seccomp test auto-runs and is rejected.
	cs := clientsetWithWebhookAndPSA()
	cs.PrependReactor("create", "pods", rejectAll())

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), Config{})

	if result.Outcome != "Rejected" {
		t.Errorf("expected Rejected, got %q: %s", result.Outcome, result.Detail)
	}
	if !strings.Contains(result.Detail, "seccomp-unconfined") {
		t.Errorf("expected seccomp-unconfined in detail, got %q", result.Detail)
	}
}

func TestExecute_SeccompAcceptedViaPSA(t *testing.T) {
	// Namespace has PSA restricted but the seccomp pod is not rejected — policy gap.
	cs := clientsetWithWebhookAndPSA()
	// Only reject the security-context bad pod; let seccomp pod through.
	cs.PrependReactor("create", "pods", rejectByGenerateName("sidereal-admission-probe-"))

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), Config{})

	if result.Outcome != "Accepted" {
		t.Errorf("expected Accepted for seccomp policy gap, got %q: %s", result.Outcome, result.Detail)
	}
	if !strings.Contains(result.Detail, "seccomp-unconfined") {
		t.Errorf("expected seccomp-unconfined in failure detail, got %q", result.Detail)
	}
}

func TestExecute_SeccompRejectedViaConfig(t *testing.T) {
	// No PSA namespace label, but SeccompEnforcement=true via config.
	cs := clientsetWithWebhook()
	cs.PrependReactor("create", "pods", rejectAll())

	admCfg := Config{SeccompEnforcement: true}

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), admCfg)

	if result.Outcome != "Rejected" {
		t.Errorf("expected Rejected, got %q: %s", result.Outcome, result.Detail)
	}
	if !strings.Contains(result.Detail, "seccomp-unconfined") {
		t.Errorf("expected seccomp-unconfined in detail, got %q", result.Detail)
	}
}

func TestExecute_SeccompSkippedNoPSA(t *testing.T) {
	// No PSA label, SeccompEnforcement=false — seccomp test does not run.
	// Bad pod rejected → overall Rejected, detail only mentions security-context.
	cs := clientsetWithWebhook()
	cs.PrependReactor("create", "pods", rejectAll())

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), Config{})

	if result.Outcome != "Rejected" {
		t.Errorf("expected Rejected, got %q: %s", result.Outcome, result.Detail)
	}
	if strings.Contains(result.Detail, "seccomp-unconfined") {
		t.Errorf("seccomp test should not have run, but detail mentions it: %q", result.Detail)
	}
}

// --- CM-7(5): image authorization tests ---

func TestExecute_ImageAuthRejected(t *testing.T) {
	cs := clientsetWithWebhook()
	cs.PrependReactor("create", "pods", rejectAll())

	admCfg := Config{UnauthorizedImageRef: "docker.io/ubuntu:latest"}

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), admCfg)

	if result.Outcome != "Rejected" {
		t.Errorf("expected Rejected, got %q: %s", result.Outcome, result.Detail)
	}
	if !strings.Contains(result.Detail, "image-authorization") {
		t.Errorf("expected image-authorization in detail, got %q", result.Detail)
	}
}

func TestExecute_ImageAuthAccepted(t *testing.T) {
	// Only reject the security-context bad pod; let the image auth pod through.
	cs := clientsetWithWebhook()
	cs.PrependReactor("create", "pods", rejectByGenerateName("sidereal-admission-probe-"))

	admCfg := Config{UnauthorizedImageRef: "docker.io/ubuntu:latest"}

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), admCfg)

	if result.Outcome != "Accepted" {
		t.Errorf("expected Accepted for image auth gap, got %q: %s", result.Outcome, result.Detail)
	}
	if !strings.Contains(result.Detail, "image-authorization") {
		t.Errorf("expected image-authorization in failure detail, got %q", result.Detail)
	}
}

func TestExecute_ImageAuthSkipped(t *testing.T) {
	// UnauthorizedImageRef not set — image auth test does not run.
	cs := clientsetWithWebhook()
	cs.PrependReactor("create", "pods", rejectAll())

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), Config{})

	if result.Outcome != "Rejected" {
		t.Errorf("expected Rejected, got %q: %s", result.Outcome, result.Detail)
	}
	if strings.Contains(result.Detail, "image-authorization") {
		t.Errorf("image auth test should not have run, but detail mentions it: %q", result.Detail)
	}
}

func TestExecute_AllThreeTestsRejected(t *testing.T) {
	// PSA restricted + UnauthorizedImageRef set — all three tests run and are all rejected.
	cs := clientsetWithWebhookAndPSA()
	cs.PrependReactor("create", "pods", rejectAll())

	admCfg := Config{UnauthorizedImageRef: "docker.io/ubuntu:latest"}

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), admCfg)

	if result.Outcome != "Rejected" {
		t.Errorf("expected Rejected, got %q: %s", result.Outcome, result.Detail)
	}
	for _, name := range []string{"security-context", "seccomp-unconfined", "image-authorization"} {
		if !strings.Contains(result.Detail, name) {
			t.Errorf("expected %q in detail, got %q", name, result.Detail)
		}
	}
}

// --- Pod spec tests ---

func TestDefaultBadPod(t *testing.T) {
	pod := defaultBadPod("staging")

	if pod.Namespace != "staging" {
		t.Errorf("expected namespace staging, got %q", pod.Namespace)
	}
	if pod.Labels["sidereal.cloud/admission-probe"] != "true" {
		t.Error("expected admission-probe label")
	}
	if !pod.Spec.HostPID {
		t.Error("expected HostPID=true in bad pod")
	}
	if !pod.Spec.HostNetwork {
		t.Error("expected HostNetwork=true in bad pod")
	}
	if len(pod.Spec.Containers) == 0 {
		t.Fatal("expected at least one container")
	}
	sc := pod.Spec.Containers[0].SecurityContext
	if sc == nil || sc.Privileged == nil || !*sc.Privileged {
		t.Error("expected privileged=true in bad pod")
	}
}

func TestSeccompUnconfinedPod(t *testing.T) {
	pod := seccompUnconfinedPod("staging")

	if pod.Namespace != "staging" {
		t.Errorf("expected namespace staging, got %q", pod.Namespace)
	}
	if !strings.HasPrefix(pod.GenerateName, "sidereal-admission-probe-seccomp-") {
		t.Errorf("unexpected GenerateName %q", pod.GenerateName)
	}
	if pod.Spec.SecurityContext == nil || pod.Spec.SecurityContext.SeccompProfile == nil {
		t.Fatal("expected pod-level seccomp profile")
	}
	if pod.Spec.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeUnconfined {
		t.Errorf("expected Unconfined seccomp, got %q", pod.Spec.SecurityContext.SeccompProfile.Type)
	}
	sc := pod.Spec.Containers[0].SecurityContext
	if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		t.Error("expected allowPrivilegeEscalation=false")
	}
	if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
		t.Error("expected runAsNonRoot=true")
	}
}

func TestImageAuthPod(t *testing.T) {
	pod := imageAuthPod("staging", "docker.io/ubuntu:latest")

	if pod.Namespace != "staging" {
		t.Errorf("expected namespace staging, got %q", pod.Namespace)
	}
	if !strings.HasPrefix(pod.GenerateName, "sidereal-admission-probe-imgauth-") {
		t.Errorf("unexpected GenerateName %q", pod.GenerateName)
	}
	if pod.Spec.Containers[0].Image != "docker.io/ubuntu:latest" {
		t.Errorf("expected image docker.io/ubuntu:latest, got %q", pod.Spec.Containers[0].Image)
	}
	// Seccomp should be RuntimeDefault (compliant) so only the image causes rejection.
	if pod.Spec.SecurityContext == nil || pod.Spec.SecurityContext.SeccompProfile == nil {
		t.Fatal("expected pod-level seccomp profile")
	}
	if pod.Spec.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Errorf("expected RuntimeDefault seccomp, got %q", pod.Spec.SecurityContext.SeccompProfile.Type)
	}
	sc := pod.Spec.Containers[0].SecurityContext
	if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		t.Error("expected allowPrivilegeEscalation=false")
	}
	if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
		t.Error("expected runAsNonRoot=true")
	}
}
