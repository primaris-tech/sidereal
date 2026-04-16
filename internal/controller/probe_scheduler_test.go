package controller

import (
	"context"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = siderealv1alpha1.AddToScheme(s)
	_ = batchv1.AddToScheme(s)
	return s
}

func TestProbeScheduler_DryRunDoesNotCreateJob(t *testing.T) {
	scheme := newTestScheme()

	probe := &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rbac-probe",
			Namespace: SystemNamespace,
			UID:       "test-uid-123",
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:         siderealv1alpha1.ProbeProfileRBAC,
			TargetNamespace: "production",
			ExecutionMode:   siderealv1alpha1.ExecutionModeDryRun,
			IntervalSeconds: 300,
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(probe).
		WithStatusSubresource(probe).
		Build()

	reconciler := &ProbeSchedulerReconciler{Client: c, ProbeGoImage: "test-probe-go:latest", ProbeDetectionImage: "test-probe-detection:latest"}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      probe.Name,
			Namespace: probe.Namespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// Verify no Jobs were created.
	var jobs batchv1.JobList
	if err := c.List(context.Background(), &jobs); err != nil {
		t.Fatalf("failed to list jobs: %v", err)
	}
	if len(jobs.Items) != 0 {
		t.Errorf("expected 0 jobs in dryRun mode, got %d", len(jobs.Items))
	}
}

func TestProbeScheduler_ObserveModeCreatesJob(t *testing.T) {
	scheme := newTestScheme()

	probe := &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rbac-observe",
			Namespace: SystemNamespace,
			UID:       "test-uid-456",
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:         siderealv1alpha1.ProbeProfileRBAC,
			TargetNamespace: "production",
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
		},
	}

	hmacSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      HMACRootSecretName,
			Namespace: SystemNamespace,
		},
		Data: map[string][]byte{
			HMACRootSecretKey: []byte("test-root-key-32-bytes-long!!!!"),
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(probe, hmacSecret).
		WithStatusSubresource(probe).
		Build()

	reconciler := &ProbeSchedulerReconciler{Client: c, ProbeGoImage: "test-probe-go:latest", ProbeDetectionImage: "test-probe-detection:latest"}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      probe.Name,
			Namespace: probe.Namespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// Verify a Job was created.
	var jobs batchv1.JobList
	if err := c.List(context.Background(), &jobs); err != nil {
		t.Fatalf("failed to list jobs: %v", err)
	}
	if len(jobs.Items) != 1 {
		t.Fatalf("expected 1 job in observe mode, got %d", len(jobs.Items))
	}

	job := jobs.Items[0]

	// Verify labels.
	if job.Labels[ProbeProfileLabel] != "rbac" {
		t.Errorf("expected probe-profile label 'rbac', got %q", job.Labels[ProbeProfileLabel])
	}
	if job.Labels[ProbeNameLabel] != "test-rbac-observe" {
		t.Errorf("expected probe-name label 'test-rbac-observe', got %q", job.Labels[ProbeNameLabel])
	}
	if job.Labels[TargetNamespaceLabel] != "production" {
		t.Errorf("expected target-namespace label 'production', got %q", job.Labels[TargetNamespaceLabel])
	}
	if job.Labels[FingerprintLabel] == "" {
		t.Error("expected probe-id label to be set")
	}

	// Verify security context.
	container := job.Spec.Template.Spec.Containers[0]
	sc := container.SecurityContext
	if sc == nil {
		t.Fatal("expected security context to be set")
	}
	if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
		t.Error("expected RunAsNonRoot=true")
	}
	if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
		t.Error("expected ReadOnlyRootFilesystem=true")
	}
	if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		t.Error("expected AllowPrivilegeEscalation=false")
	}
	if len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" {
		t.Error("expected capabilities drop ALL")
	}

	// Verify ServiceAccount.
	if job.Spec.Template.Spec.ServiceAccountName != "sidereal-probe-rbac" {
		t.Errorf("expected SA 'sidereal-probe-rbac', got %q", job.Spec.Template.Spec.ServiceAccountName)
	}

	// Verify HMAC volume mount.
	if len(container.VolumeMounts) != 1 || container.VolumeMounts[0].Name != "hmac-key" {
		t.Error("expected hmac-key volume mount")
	}

	// Verify environment variables.
	envMap := make(map[string]string)
	for _, e := range container.Env {
		envMap[e.Name] = e.Value
	}
	if envMap["TARGET_NAMESPACE"] != "production" {
		t.Errorf("expected TARGET_NAMESPACE=production, got %q", envMap["TARGET_NAMESPACE"])
	}
	if envMap["EXECUTION_MODE"] != "observe" {
		t.Errorf("expected EXECUTION_MODE=observe, got %q", envMap["EXECUTION_MODE"])
	}
	if envMap["PROBE_ID"] == "" {
		t.Error("expected PROBE_ID to be set")
	}
}

func TestProbeScheduler_NotDueYet(t *testing.T) {
	scheme := newTestScheme()

	now := metav1.Now()
	probe := &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-not-due",
			Namespace: SystemNamespace,
			UID:       "test-uid-789",
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:         siderealv1alpha1.ProbeProfileRBAC,
			TargetNamespace: "production",
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 86400, // 24 hours
		},
		Status: siderealv1alpha1.SiderealProbeStatus{
			LastExecutedAt: &now, // just executed
		},
	}

	hmacSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      HMACRootSecretName,
			Namespace: SystemNamespace,
		},
		Data: map[string][]byte{
			HMACRootSecretKey: []byte("test-root-key-32-bytes-long!!!!"),
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(probe, hmacSecret).
		WithStatusSubresource(probe).
		Build()

	reconciler := &ProbeSchedulerReconciler{Client: c, ProbeGoImage: "test-probe-go:latest", ProbeDetectionImage: "test-probe-detection:latest"}

	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      probe.Name,
			Namespace: probe.Namespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// Should requeue, not create a Job.
	if result.RequeueAfter < time.Hour {
		t.Errorf("expected requeue after >1h, got %v", result.RequeueAfter)
	}

	var jobs batchv1.JobList
	if err := c.List(context.Background(), &jobs); err != nil {
		t.Fatalf("failed to list jobs: %v", err)
	}
	if len(jobs.Items) != 0 {
		t.Errorf("expected 0 jobs (not due), got %d", len(jobs.Items))
	}
}

func TestProbeScheduler_DetectionRequiresAuthorization(t *testing.T) {
	scheme := newTestScheme()

	probe := &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-detection",
			Namespace: SystemNamespace,
			UID:       "test-uid-det",
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:            siderealv1alpha1.ProbeProfileDetection,
			TargetNamespace:    "production",
			ExecutionMode:      siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds:    300,
			AOAuthorizationRef: "missing-auth",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(probe).
		WithStatusSubresource(probe).
		Build()

	reconciler := &ProbeSchedulerReconciler{Client: c, ProbeGoImage: "test-probe-go:latest", ProbeDetectionImage: "test-probe-detection:latest"}

	// Should not error, but should not create a Job either (auth missing).
	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      probe.Name,
			Namespace: probe.Namespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile should not error on missing auth, got: %v", err)
	}

	var jobs batchv1.JobList
	if err := c.List(context.Background(), &jobs); err != nil {
		t.Fatalf("failed to list jobs: %v", err)
	}
	if len(jobs.Items) != 0 {
		t.Errorf("expected 0 jobs (no AO auth), got %d", len(jobs.Items))
	}
}

func TestProbeScheduler_NamespaceSelectorExpansion(t *testing.T) {
	scheme := newTestScheme()

	probe := &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-selector",
			Namespace: SystemNamespace,
			UID:       "test-uid-sel",
		},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile: siderealv1alpha1.ProbeProfileRBAC,
			TargetNamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "production"},
			},
			ExecutionMode:   siderealv1alpha1.ExecutionModeObserve,
			IntervalSeconds: 300,
		},
	}

	ns1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "prod-app1",
			Labels: map[string]string{"env": "production"},
		},
	}
	ns2 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "prod-app2",
			Labels: map[string]string{"env": "production"},
		},
	}
	ns3 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "staging-app",
			Labels: map[string]string{"env": "staging"},
		},
	}

	hmacSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      HMACRootSecretName,
			Namespace: SystemNamespace,
		},
		Data: map[string][]byte{
			HMACRootSecretKey: []byte("test-root-key-32-bytes-long!!!!"),
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(probe, ns1, ns2, ns3, hmacSecret).
		WithStatusSubresource(probe).
		Build()

	reconciler := &ProbeSchedulerReconciler{Client: c, ProbeGoImage: "test-probe-go:latest", ProbeDetectionImage: "test-probe-detection:latest"}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      probe.Name,
			Namespace: probe.Namespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// Should create 2 Jobs (prod-app1 and prod-app2), not 3.
	var jobs batchv1.JobList
	if err := c.List(context.Background(), &jobs); err != nil {
		t.Fatalf("failed to list jobs: %v", err)
	}
	if len(jobs.Items) != 2 {
		t.Errorf("expected 2 jobs for matching namespaces, got %d", len(jobs.Items))
	}

	// Verify target namespaces are correct.
	namespaces := map[string]bool{}
	for _, job := range jobs.Items {
		namespaces[job.Labels[TargetNamespaceLabel]] = true
	}
	if !namespaces["prod-app1"] || !namespaces["prod-app2"] {
		t.Errorf("expected jobs for prod-app1 and prod-app2, got %v", namespaces)
	}
	if namespaces["staging-app"] {
		t.Error("should not create job for staging-app (non-matching label)")
	}
}

func TestComputeJitter(t *testing.T) {
	reconciler := &ProbeSchedulerReconciler{}
	interval := 6 * time.Hour
	maxJitter := interval / 10 // ±10%

	for i := 0; i < 100; i++ {
		jitter := reconciler.computeJitter(interval)
		if jitter < -maxJitter || jitter > maxJitter {
			t.Errorf("jitter %v outside ±10%% range (±%v)", jitter, maxJitter)
		}
	}
}

func TestServiceAccountMapping(t *testing.T) {
	reconciler := &ProbeSchedulerReconciler{}

	tests := []struct {
		profile  siderealv1alpha1.ProbeProfile
		expected string
	}{
		{siderealv1alpha1.ProbeProfileRBAC, "sidereal-probe-rbac"},
		{siderealv1alpha1.ProbeProfileNetPol, "sidereal-probe-netpol"},
		{siderealv1alpha1.ProbeProfileAdmission, "sidereal-probe-admission"},
		{siderealv1alpha1.ProbeProfileSecret, "sidereal-probe-secret"},
		{siderealv1alpha1.ProbeProfileDetection, "sidereal-probe-detection"},
	}

	for _, tc := range tests {
		t.Run(string(tc.profile), func(t *testing.T) {
			probe := &siderealv1alpha1.SiderealProbe{
				Spec: siderealv1alpha1.SiderealProbeSpec{Profile: tc.profile},
			}
			got := reconciler.serviceAccountForProbe(probe)
			if got != tc.expected {
				t.Errorf("expected SA %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestCustomProbeUsesCustomSA(t *testing.T) {
	reconciler := &ProbeSchedulerReconciler{}

	probe := &siderealv1alpha1.SiderealProbe{
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile: "acme-corp/custom-check",
			Runner: &siderealv1alpha1.ProbeRunnerSpec{
				Type: siderealv1alpha1.ProbeRunnerCustom,
				Custom: &siderealv1alpha1.CustomProbeConfig{
					Image:              "registry.example.com/my-probe@sha256:abc123",
					ServiceAccountName: "my-custom-probe-sa",
				},
			},
		},
	}

	got := reconciler.serviceAccountForProbe(probe)
	if got != "my-custom-probe-sa" {
		t.Errorf("expected custom SA 'my-custom-probe-sa', got %q", got)
	}

	img := reconciler.imageForProbe(probe)
	if img != "registry.example.com/my-probe@sha256:abc123" {
		t.Errorf("expected custom image, got %q", img)
	}
}

func TestValidateCustomProbe_Valid(t *testing.T) {
	reconciler := &ProbeSchedulerReconciler{
		RegisteredCustomSAs: map[string]bool{
			"my-custom-sa": true,
		},
	}

	probe := &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{Name: "test-custom"},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile: "acme-corp/custom-check",
			Runner: &siderealv1alpha1.ProbeRunnerSpec{
				Type: siderealv1alpha1.ProbeRunnerCustom,
				Custom: &siderealv1alpha1.CustomProbeConfig{
					Image:              "registry.example.com/probe@sha256:abc123",
					ServiceAccountName: "my-custom-sa",
				},
			},
		},
	}

	if err := reconciler.validateCustomProbe(probe); err != nil {
		t.Errorf("expected valid custom probe, got error: %v", err)
	}
}

func TestValidateCustomProbe_UnregisteredSA(t *testing.T) {
	reconciler := &ProbeSchedulerReconciler{
		RegisteredCustomSAs: map[string]bool{
			"approved-sa": true,
		},
	}

	probe := &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{Name: "test-custom"},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile: "acme-corp/custom-check",
			Runner: &siderealv1alpha1.ProbeRunnerSpec{
				Type: siderealv1alpha1.ProbeRunnerCustom,
				Custom: &siderealv1alpha1.CustomProbeConfig{
					Image:              "registry.example.com/probe@sha256:abc123",
					ServiceAccountName: "unapproved-sa",
				},
			},
		},
	}

	err := reconciler.validateCustomProbe(probe)
	if err == nil {
		t.Error("expected error for unregistered SA")
	}
}

func TestValidateCustomProbe_MissingSpec(t *testing.T) {
	reconciler := &ProbeSchedulerReconciler{}

	probe := &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{Name: "test-custom"},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile: "acme-corp/custom-check",
		},
	}

	if err := reconciler.validateCustomProbe(probe); err == nil {
		t.Error("expected error for missing customProbe spec")
	}
}

func TestValidateCustomProbe_MissingImage(t *testing.T) {
	reconciler := &ProbeSchedulerReconciler{}

	probe := &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{Name: "test-custom"},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile: "acme-corp/custom-check",
			Runner: &siderealv1alpha1.ProbeRunnerSpec{
				Type: siderealv1alpha1.ProbeRunnerCustom,
				Custom: &siderealv1alpha1.CustomProbeConfig{
					ServiceAccountName: "my-sa",
				},
			},
		},
	}

	if err := reconciler.validateCustomProbe(probe); err == nil {
		t.Error("expected error for missing image")
	}
}

func TestValidateCustomProbe_MissingSA(t *testing.T) {
	reconciler := &ProbeSchedulerReconciler{}

	probe := &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{Name: "test-custom"},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile: "acme-corp/custom-check",
			Runner: &siderealv1alpha1.ProbeRunnerSpec{
				Type: siderealv1alpha1.ProbeRunnerCustom,
				Custom: &siderealv1alpha1.CustomProbeConfig{
					Image: "registry.example.com/probe@sha256:abc123",
				},
			},
		},
	}

	if err := reconciler.validateCustomProbe(probe); err == nil {
		t.Error("expected error for missing SA")
	}
}

func TestValidateCustomProbe_NilRegistryAllowsAll(t *testing.T) {
	// When RegisteredCustomSAs is nil, skip SA validation (test mode).
	reconciler := &ProbeSchedulerReconciler{}

	probe := &siderealv1alpha1.SiderealProbe{
		ObjectMeta: metav1.ObjectMeta{Name: "test-custom"},
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile: "acme-corp/custom-check",
			Runner: &siderealv1alpha1.ProbeRunnerSpec{
				Type: siderealv1alpha1.ProbeRunnerCustom,
				Custom: &siderealv1alpha1.CustomProbeConfig{
					Image:              "registry.example.com/probe@sha256:abc123",
					ServiceAccountName: "any-sa",
				},
			},
		},
	}

	if err := reconciler.validateCustomProbe(probe); err != nil {
		t.Errorf("expected nil registry to allow all SAs, got error: %v", err)
	}
}

func TestCustomProbeJobHasConfigEnv(t *testing.T) {
	reconciler := &ProbeSchedulerReconciler{}

	probe := &siderealv1alpha1.SiderealProbe{
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:       "acme-corp/custom-check",
			ExecutionMode: siderealv1alpha1.ExecutionModeObserve,
			Runner: &siderealv1alpha1.ProbeRunnerSpec{
				Type: siderealv1alpha1.ProbeRunnerCustom,
				Custom: &siderealv1alpha1.CustomProbeConfig{
					Image:              "registry.example.com/probe@sha256:abc123",
					ServiceAccountName: "my-sa",
					Config: &runtime.RawExtension{
						Raw: []byte(`{"threshold":42,"checkType":"deep"}`),
					},
				},
			},
		},
	}

	job := reconciler.buildProbeJob(probe, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "production", "hmac-secret")

	// Find PROBE_CONFIG env var.
	var probeConfig string
	for _, env := range job.Spec.Template.Spec.Containers[0].Env {
		if env.Name == "PROBE_CONFIG" {
			probeConfig = env.Value
		}
	}

	if probeConfig == "" {
		t.Error("expected PROBE_CONFIG env var for custom probe")
	}
	if probeConfig != `{"threshold":42,"checkType":"deep"}` {
		t.Errorf("unexpected PROBE_CONFIG value: %q", probeConfig)
	}
}

func TestBuiltInProbeJobNoConfigEnv(t *testing.T) {
	reconciler := &ProbeSchedulerReconciler{}

	probe := &siderealv1alpha1.SiderealProbe{
		Spec: siderealv1alpha1.SiderealProbeSpec{
			Profile:       siderealv1alpha1.ProbeProfileRBAC,
			ExecutionMode: siderealv1alpha1.ExecutionModeObserve,
		},
	}

	job := reconciler.buildProbeJob(probe, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "production", "hmac-secret")

	for _, env := range job.Spec.Template.Spec.Containers[0].Env {
		if env.Name == "PROBE_CONFIG" {
			t.Error("built-in probes should not have PROBE_CONFIG env var")
		}
	}
}
