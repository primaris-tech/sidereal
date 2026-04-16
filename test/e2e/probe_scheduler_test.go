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

// SAP: TEST-SYS-05 (Job security posture)
func TestProbeScheduler_CreatesJob(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "sched-target-"+uid)
	createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sched-test-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:         siderealv1alpha1.ProbeProfileRBAC,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
		},
	})

	// Wait for a Job to be created.
	deadline := time.Now().Add(10 * time.Second)
	var jobs batchv1.JobList
	for time.Now().Before(deadline) {
		if err := k8sClient.List(ctx, &jobs,
			client.InNamespace(controller.SystemNamespace),
			client.MatchingLabels{
				controller.ProbeNameLabel: probe.Name,
			},
		); err == nil && len(jobs.Items) > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if len(jobs.Items) == 0 {
		t.Fatal("expected Job to be created for observe-mode probe")
	}

	job := jobs.Items[0]

	// Verify fingerprint label.
	if _, ok := job.Labels[controller.FingerprintLabel]; !ok {
		t.Error("Job missing fingerprint label")
	}

	// Verify probe type label.
	if job.Labels[controller.ProbeTypeLabel] != string(siderealv1alpha1.ProbeProfileRBAC) {
		t.Errorf("unexpected probe type label: %s", job.Labels[controller.ProbeTypeLabel])
	}

	// Verify target namespace label.
	if job.Labels[controller.TargetNamespaceLabel] != ns {
		t.Errorf("unexpected target namespace label: %s", job.Labels[controller.TargetNamespaceLabel])
	}

	// Verify Job security posture: non-root, read-only filesystem, drop all caps.
	container := job.Spec.Template.Spec.Containers[0]
	if container.SecurityContext == nil {
		t.Fatal("container SecurityContext is nil")
	}

	sc := container.SecurityContext
	if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
		t.Error("container should set runAsNonRoot: true")
	}
	if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
		t.Error("container should set readOnlyRootFilesystem: true")
	}
	if sc.Capabilities == nil || len(sc.Capabilities.Drop) == 0 {
		t.Error("container should drop ALL capabilities")
	} else {
		foundDropAll := false
		for _, cap := range sc.Capabilities.Drop {
			if cap == corev1.Capability("ALL") {
				foundDropAll = true
				break
			}
		}
		if !foundDropAll {
			t.Error("container should drop ALL capabilities")
		}
	}

	// Verify TTL is set.
	if job.Spec.TTLSecondsAfterFinished == nil {
		t.Error("Job should have TTLSecondsAfterFinished set")
	}
}

func TestProbeScheduler_DryRunDoesNotCreateJob(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "sched-dry-"+uid)
	createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sched-dry-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:         siderealv1alpha1.ProbeProfileRBAC,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeDryRun,
			IntervalSeconds: 300,
		},
	})

	// Wait a bit and verify no Job is created.
	time.Sleep(3 * time.Second)

	var jobs batchv1.JobList
	if err := k8sClient.List(ctx, &jobs,
		client.InNamespace(controller.SystemNamespace),
		client.MatchingLabels{
			controller.ProbeNameLabel: probe.Name,
		},
	); err != nil {
		t.Fatalf("failed to list jobs: %v", err)
	}

	if len(jobs.Items) > 0 {
		t.Error("dryRun probe should not create Jobs")
	}
}

// SAP: TEST-SYS-07 (Identity separation)
func TestProbeScheduler_IdentitySeparation(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "sched-id-"+uid)
	createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sched-id-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:         siderealv1alpha1.ProbeProfileSecret,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
		},
	})

	// Wait for Job.
	deadline := time.Now().Add(10 * time.Second)
	var jobs batchv1.JobList
	for time.Now().Before(deadline) {
		if err := k8sClient.List(ctx, &jobs,
			client.InNamespace(controller.SystemNamespace),
			client.MatchingLabels{controller.ProbeNameLabel: probe.Name},
		); err == nil && len(jobs.Items) > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if len(jobs.Items) == 0 {
		t.Fatal("expected Job to be created")
	}

	job := jobs.Items[0]

	// Verify the Job uses the probe-specific ServiceAccount, not the controller SA.
	expectedSA := "sidereal-probe-secret"
	if job.Spec.Template.Spec.ServiceAccountName != expectedSA {
		t.Errorf("expected ServiceAccount %s, got %s", expectedSA, job.Spec.Template.Spec.ServiceAccountName)
	}
}

func TestProbeScheduler_RateLimiting(t *testing.T) {
	uid := uniqueID()
	ns := createNamespace(t, "sched-rate-"+uid)
	createHMACRootSecret(t)

	probe := createProbe(t, &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sched-rate-" + uid,
			Namespace: controller.SystemNamespace,
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:         siderealv1alpha1.ProbeProfileRBAC,
			TargetNamespace: ns,
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
		},
	})

	// Wait for first Job.
	deadline := time.Now().Add(10 * time.Second)
	var jobs batchv1.JobList
	for time.Now().Before(deadline) {
		if err := k8sClient.List(ctx, &jobs,
			client.InNamespace(controller.SystemNamespace),
			client.MatchingLabels{controller.ProbeNameLabel: probe.Name},
		); err == nil && len(jobs.Items) > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if len(jobs.Items) == 0 {
		t.Fatal("expected first Job to be created")
	}

	firstCount := len(jobs.Items)

	// Wait a short period and verify no duplicate Job is created.
	time.Sleep(3 * time.Second)

	if err := k8sClient.List(ctx, &jobs,
		client.InNamespace(controller.SystemNamespace),
		client.MatchingLabels{controller.ProbeNameLabel: probe.Name},
	); err != nil {
		t.Fatalf("failed to list jobs: %v", err)
	}

	if len(jobs.Items) > firstCount {
		t.Errorf("expected no additional Jobs within interval, got %d (started with %d)", len(jobs.Items), firstCount)
	}
}
