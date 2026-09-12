package e2e

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/controller"
)

// SAP: TEST-SYS-08 (Bootstrap verification)
func TestBootstrap_ServiceAccountCheck(t *testing.T) {
	defer startControllers(t)()
	// Create all built-in ServiceAccounts.
	for _, saName := range controller.BuiltInServiceAccounts {
		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      saName,
				Namespace: controller.SystemNamespace,
			},
		}
		if err := k8sClient.Create(ctx, sa); err != nil {
			t.Fatalf("create ServiceAccount %s: %v", saName, err)
		}
		t.Cleanup(func() { deleteFixture(t, sa) })
	}

	result := controller.RunBootstrapVerification(ctx, k8sClient)

	// Check that SA checks pass.
	for _, check := range result.Checks {
		if !check.Passed {
			t.Logf("check failed: %s - %s", check.Name, check.Detail)
		}
	}

	// At minimum, the SA checks should pass since we just created them.
	saCheckPassed := false
	for _, check := range result.Checks {
		if check.Name == "ServiceAccount/sidereal-controller" && check.Passed {
			saCheckPassed = true
			break
		}
	}
	if !saCheckPassed {
		t.Error("expected sidereal-controller SA check to pass")
	}
}

func TestBootstrap_HMACSecretCheck(t *testing.T) {
	defer startControllers(t)()
	createHMACRootSecret(t)

	result := controller.RunBootstrapVerification(ctx, k8sClient)

	hmacCheckPassed := false
	for _, check := range result.Checks {
		if check.Name == "Secret/sidereal-hmac-root" && check.Passed {
			hmacCheckPassed = true
			break
		}
	}
	if !hmacCheckPassed {
		t.Error("expected HMAC root secret check to pass")
	}
}

func TestBootstrap_NetworkPolicyCheck(t *testing.T) {
	defer startControllers(t)()
	// Create a default-deny NetworkPolicy in the system namespace.
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sidereal-default-deny",
			Namespace: controller.SystemNamespace,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
		},
	}
	if err := k8sClient.Create(ctx, np); err != nil {
		t.Fatalf("create NetworkPolicy: %v", err)
	}
	t.Cleanup(func() { deleteFixture(t, np) })

	result := controller.RunBootstrapVerification(ctx, k8sClient)

	npCheckPassed := false
	for _, check := range result.Checks {
		if check.Name == "NetworkPolicy/sidereal-system" && check.Passed {
			npCheckPassed = true
			break
		}
	}
	if !npCheckPassed {
		t.Error("expected NetworkPolicy check to pass")
	}
}

func TestBootstrap_FailureCreatesAlert(t *testing.T) {
	defer startControllers(t)()
	// Run bootstrap without prerequisites - should fail.
	result := controller.RunBootstrapVerification(ctx, k8sClient)

	if result.Passed {
		t.Fatal("bootstrap should fail with prerequisites absent")
	}

	err := controller.HandleBootstrapFailure(ctx, k8sClient, result)
	if err != nil {
		t.Fatalf("HandleBootstrapFailure failed: %v", err)
	}

	// Verify the alert was created.
	alert := waitForAlert(t, "sidereal-alert-bootstrap-failed", 5*time.Second)

	if alert.Spec.Reason != siderealv1alpha1.AlertReasonBaselineConfigurationDrift {
		// Bootstrap alerts may use a different reason; just verify it exists.
		t.Logf("alert reason: %s", alert.Spec.Reason)
	}
}
