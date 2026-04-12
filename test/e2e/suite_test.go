package e2e

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	ctrl "sigs.k8s.io/controller-runtime"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/controller"
	"github.com/primaris-tech/sidereal/internal/crosswalk"
	siderealhmac "github.com/primaris-tech/sidereal/internal/hmac"
)

var (
	testEnv   *envtest.Environment
	k8sClient client.Client
	scheme    *runtime.Scheme
	ctx       context.Context
	cancel    context.CancelFunc
)

func TestMain(m *testing.M) {
	log.SetLogger(zap.New(zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	scheme = runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = siderealv1alpha1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)

	// Find CRD manifests.
	crdPaths := []string{}
	projectRoot := findProjectRoot()
	crdDir := filepath.Join(projectRoot, "config", "crd", "bases")
	if _, err := os.Stat(crdDir); err == nil {
		crdPaths = append(crdPaths, crdDir)
	}

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     crdPaths,
		ErrorIfCRDPathMissing: false,
		Scheme:                scheme,
	}

	cfg, err := testEnv.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start envtest: %v\n", err)
		os.Exit(1)
	}

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create client: %v\n", err)
		os.Exit(1)
	}

	// Create the system namespace.
	systemNS := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: controller.SystemNamespace},
	}
	if err := k8sClient.Create(ctx, systemNS); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create system namespace: %v\n", err)
		os.Exit(1)
	}

	// Start controllers in the background.
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create manager: %v\n", err)
		os.Exit(1)
	}

	cw := crosswalk.NewResolver()
	crosswalkDir := filepath.Join(projectRoot, "internal", "crosswalk", "data")
	if _, err := os.Stat(crosswalkDir); err == nil {
		_ = cw.LoadFromDir(crosswalkDir)
	}

	if err := (&controller.ProbeSchedulerReconciler{
		Client: mgr.GetClient(),
	}).SetupWithManager(mgr); err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup probe scheduler: %v\n", err)
		os.Exit(1)
	}

	if err := (&controller.ResultReconciler{
		Client:    mgr.GetClient(),
		Crosswalk: cw,
	}).SetupWithManager(mgr); err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup result reconciler: %v\n", err)
		os.Exit(1)
	}

	if err := (&controller.IncidentReconciler{
		Client: mgr.GetClient(),
	}).SetupWithManager(mgr); err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup incident reconciler: %v\n", err)
		os.Exit(1)
	}

	if err := (&controller.AlertReconciler{
		Client: mgr.GetClient(),
	}).SetupWithManager(mgr); err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup alert reconciler: %v\n", err)
		os.Exit(1)
	}

	if err := (&controller.AuthorizationReconciler{
		Client: mgr.GetClient(),
	}).SetupWithManager(mgr); err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup authorization reconciler: %v\n", err)
		os.Exit(1)
	}

	go func() {
		if err := mgr.Start(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "manager exited: %v\n", err)
		}
	}()

	// Wait for cache sync.
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		fmt.Fprintf(os.Stderr, "cache sync failed\n")
		os.Exit(1)
	}

	// Use the manager's cached client for tests.
	k8sClient = mgr.GetClient()

	code := m.Run()

	cancel()
	_ = testEnv.Stop()
	os.Exit(code)
}

// findProjectRoot walks up from the current directory to find go.mod.
func findProjectRoot() string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

// --- Test helper functions ---

// createNamespace creates a namespace and returns its name.
func createNamespace(t *testing.T, name string) string {
	t.Helper()
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	if err := k8sClient.Create(ctx, ns); err != nil {
		t.Fatalf("failed to create namespace %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = k8sClient.Delete(ctx, ns)
	})
	return name
}

// createHMACRootSecret creates the HMAC root secret in the system namespace.
func createHMACRootSecret(t *testing.T) []byte {
	t.Helper()
	rootKey := make([]byte, 32)
	if _, err := rand.Read(rootKey); err != nil {
		t.Fatalf("failed to generate HMAC root key: %v", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      controller.HMACRootSecretName,
			Namespace: controller.SystemNamespace,
		},
		Data: map[string][]byte{
			controller.HMACRootSecretKey: rootKey,
		},
	}
	if err := k8sClient.Create(ctx, secret); err != nil {
		t.Fatalf("failed to create HMAC root secret: %v", err)
	}
	t.Cleanup(func() {
		_ = k8sClient.Delete(ctx, secret)
	})
	return rootKey
}

// createProbe creates a SiderealProbe and registers cleanup.
func createProbe(t *testing.T, probe *siderealv1alpha1.SiderealProbe) *siderealv1alpha1.SiderealProbe {
	t.Helper()
	if probe.Namespace == "" {
		probe.Namespace = controller.SystemNamespace
	}
	if err := k8sClient.Create(ctx, probe); err != nil {
		t.Fatalf("failed to create probe: %v", err)
	}
	t.Cleanup(func() {
		_ = k8sClient.Delete(ctx, probe)
	})
	return probe
}

// simulateProbeResult creates the ConfigMap and HMAC Secret that a probe runner
// would produce, then creates a completed Job so the ResultReconciler picks it up.
func simulateProbeResult(t *testing.T, probeID, probeType, probeName, targetNamespace, outcome, detail string, rootKey []byte) {
	t.Helper()

	// Derive per-execution HMAC key.
	execKey, err := siderealhmac.DeriveExecutionKey(rootKey, probeID)
	if err != nil {
		t.Fatalf("failed to derive HMAC key: %v", err)
	}

	// Build result JSON.
	resultPayload := controller.ProbeRunnerResult{
		Outcome:    outcome,
		Detail:     detail,
		DurationMs: 42,
	}
	resultJSON, err := json.Marshal(resultPayload)
	if err != nil {
		t.Fatalf("failed to marshal result: %v", err)
	}

	// Sign result.
	sig, err := siderealhmac.SignResult(execKey, resultJSON)
	if err != nil {
		t.Fatalf("failed to sign result: %v", err)
	}

	shortID := probeID[:8]

	// Create result ConfigMap.
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("sidereal-result-%s", shortID),
			Namespace: controller.SystemNamespace,
		},
		Data: map[string]string{
			"result": string(resultJSON),
			"hmac":   sig,
		},
	}
	if err := k8sClient.Create(ctx, cm); err != nil {
		t.Fatalf("failed to create result ConfigMap: %v", err)
	}

	// Create HMAC key Secret.
	hmacSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("sidereal-hmac-%s", shortID),
			Namespace: controller.SystemNamespace,
		},
		Data: map[string][]byte{
			"hmac-key": execKey,
		},
	}
	if err := k8sClient.Create(ctx, hmacSecret); err != nil {
		t.Fatalf("failed to create HMAC secret: %v", err)
	}

	// Create a completed Job.
	ttl := int32(controller.JobTTLSeconds)
	completionTime := metav1.Now()
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("sidereal-probe-%s", shortID),
			Namespace: controller.SystemNamespace,
			Labels: map[string]string{
				controller.FingerprintLabel:   probeID,
				controller.ProbeTypeLabel:     probeType,
				controller.ProbeNameLabel:     probeName,
				controller.TargetNamespaceLabel: targetNamespace,
			},
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: &ttl,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					Containers: []corev1.Container{
						{
							Name:  "probe",
							Image: "ghcr.io/primaris-tech/sidereal-probe-go:latest",
						},
					},
				},
			},
		},
		Status: batchv1.JobStatus{
			Conditions: []batchv1.JobCondition{
				{
					Type:   batchv1.JobComplete,
					Status: corev1.ConditionTrue,
				},
			},
			CompletionTime: &completionTime,
		},
	}
	if err := k8sClient.Create(ctx, job); err != nil {
		t.Fatalf("failed to create completed Job: %v", err)
	}
	t.Cleanup(func() {
		_ = k8sClient.Delete(ctx, job)
	})
}

// waitForProbeResult polls until a SiderealProbeResult with the given probeID label appears.
func waitForProbeResult(t *testing.T, probeID string, timeout time.Duration) *siderealv1alpha1.SiderealProbeResult {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var results siderealv1alpha1.SiderealProbeResultList
		if err := k8sClient.List(ctx, &results,
			client.InNamespace(controller.SystemNamespace),
			client.MatchingLabels{controller.FingerprintLabel: probeID},
		); err == nil && len(results.Items) > 0 {
			return &results.Items[0]
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for ProbeResult with probeID %s", probeID)
	return nil
}

// waitForIncident polls until a SiderealIncident with the given probeID label appears.
func waitForIncident(t *testing.T, probeID string, timeout time.Duration) *siderealv1alpha1.SiderealIncident {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var incidents siderealv1alpha1.SiderealIncidentList
		if err := k8sClient.List(ctx, &incidents,
			client.InNamespace(controller.SystemNamespace),
			client.MatchingLabels{controller.FingerprintLabel: probeID},
		); err == nil && len(incidents.Items) > 0 {
			return &incidents.Items[0]
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for Incident with probeID %s", probeID)
	return nil
}

// waitForAlert polls until a SiderealSystemAlert with the given name appears.
func waitForAlert(t *testing.T, name string, timeout time.Duration) *siderealv1alpha1.SiderealSystemAlert {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var alert siderealv1alpha1.SiderealSystemAlert
		if err := k8sClient.Get(ctx, types.NamespacedName{
			Name:      name,
			Namespace: controller.SystemNamespace,
		}, &alert); err == nil {
			return &alert
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for SystemAlert %s", name)
	return nil
}

// uniqueID generates a short unique suffix for test resource names.
func uniqueID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
