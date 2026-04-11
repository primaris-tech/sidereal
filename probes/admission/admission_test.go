package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
		ProbeType:       "admission",
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

// clientsetNoWebhooks returns a clientset with no admission webhooks.
func clientsetNoWebhooks() *fake.Clientset {
	return fake.NewSimpleClientset()
}

func TestExecute_Rejected(t *testing.T) {
	cs := clientsetWithWebhook()
	// Simulate admission rejection on pod create.
	cs.PrependReactor("create", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serrors.NewForbidden(
			schema.GroupResource{Resource: "pods"},
			"",
			fmt.Errorf("violates policy require-non-privileged"),
		)
	})

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
	cs.PrependReactor("create", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serrors.NewForbidden(
			schema.GroupResource{Resource: "pods"},
			"",
			fmt.Errorf("violates custom-policy"),
		)
	})

	admCfg := Config{
		TargetPolicy: "custom-policy",
	}

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), admCfg)

	if result.Outcome != "Rejected" {
		t.Errorf("expected Rejected, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_KnownBadSpec(t *testing.T) {
	cs := clientsetWithWebhook()
	cs.PrependReactor("create", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		createAction := action.(k8stesting.CreateAction)
		pod := createAction.GetObject().(*corev1.Pod)
		// Verify the custom spec was used.
		if pod.Spec.Containers[0].Name != "evil" {
			t.Errorf("expected container name 'evil', got %q", pod.Spec.Containers[0].Name)
		}
		// Verify probe label was added.
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

	admCfg := Config{
		KnownBadSpec: string(badPodJSON),
	}

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), admCfg)

	if result.Outcome != "Rejected" {
		t.Errorf("expected Rejected, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_InvalidKnownBadSpec(t *testing.T) {
	cs := clientsetWithWebhook()

	admCfg := Config{
		KnownBadSpec: "not valid json{{{",
	}

	result := ExecuteWithConfig(context.Background(), cs, baseCfg(), admCfg)

	if result.Outcome != "Indeterminate" {
		t.Errorf("expected Indeterminate for bad JSON, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_MutatingWebhookOnly(t *testing.T) {
	// Only a MutatingWebhookConfiguration exists (no validating).
	cs := fake.NewSimpleClientset(
		&admissionregv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "istio-sidecar-injector"},
		},
	)
	// Pod create succeeds (no rejection).

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

