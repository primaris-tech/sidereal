package e2e

import (
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/controller"
)

func TestNamespaceSelector_MatchesLabeledNamespaces(t *testing.T) {
	uid := uniqueID()
	createHMACRootSecret(t)

	// Create two namespaces with matching labels.
	for _, nsName := range []string{"nssel-match1-" + uid, "nssel-match2-" + uid} {
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: nsName,
				Labels: map[string]string{
					"sidereal-test": uid,
					"env":           "production",
				},
			},
		}
		if err := k8sClient.Create(ctx, ns); err != nil {
			t.Fatalf("failed to create namespace %s: %v", nsName, err)
		}
		t.Cleanup(func() { _ = k8sClient.Delete(ctx, ns) })
	}

	// Create a non-matching namespace.
	noMatchNS := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "nssel-nomatch-" + uid,
			Labels: map[string]string{
				"env": "staging",
			},
		},
	}
	if err := k8sClient.Create(ctx, noMatchNS); err != nil {
		t.Fatalf("failed to create non-matching namespace: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, noMatchNS) })

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nssel-probe-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile: siderealv1alpha1.ProbeProfileRBAC,
			TargetNamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"sidereal-test": uid,
				},
			},
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
		},
	})

	// Wait for Jobs to be created.
	deadline := time.Now().Add(10 * time.Second)
	var jobs batchv1.JobList
	for time.Now().Before(deadline) {
		if err := k8sClient.List(ctx, &jobs,
			client.InNamespace(controller.SystemNamespace),
			client.MatchingLabels{controller.ProbeNameLabel: probe.Name},
		); err == nil && len(jobs.Items) >= 2 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if len(jobs.Items) < 2 {
		t.Fatalf("expected at least 2 Jobs (one per matching namespace), got %d", len(jobs.Items))
	}

	// Verify Jobs target the correct namespaces.
	targetNamespaces := map[string]bool{}
	for _, job := range jobs.Items {
		targetNamespaces[job.Labels[controller.TargetNamespaceLabel]] = true
	}

	if !targetNamespaces["nssel-match1-"+uid] {
		t.Error("expected Job targeting nssel-match1 namespace")
	}
	if !targetNamespaces["nssel-match2-"+uid] {
		t.Error("expected Job targeting nssel-match2 namespace")
	}
	if targetNamespaces["nssel-nomatch-"+uid] {
		t.Error("should not create Job for non-matching namespace")
	}
}
