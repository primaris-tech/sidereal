package e2e

import (
	"bytes"
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
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/controller"
	"github.com/primaris-tech/sidereal/internal/crosswalk"
	siderealhmac "github.com/primaris-tech/sidereal/internal/hmac"
)

// Envtest validates Job specs but has no kubelet to pull or run this image.
const testProbeImage = "example.invalid/sidereal-probe@sha256:0000000000000000000000000000000000000000000000000000000000000000"

var (
	testEnv   *envtest.Environment
	k8sClient client.Client
	scheme    *runtime.Scheme
	ctx       context.Context
	cfg       *rest.Config
)

func TestMain(m *testing.M) {
	os.Exit(runSuite(m))
}

func runSuite(m *testing.M) (code int) {
	log.SetLogger(zap.New(zap.UseDevMode(true)))
	ctx = context.Background()
	scheme = runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, siderealv1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			fmt.Fprintf(os.Stderr, "register scheme: %v\n", err)
			return 1
		}
	}
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join(findProjectRoot(), "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
		UseExistingCluster:    ptr.To(false),
		Scheme:                scheme,
	}
	var err error
	cfg, err = testEnv.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "start envtest: %v\n", err)
		return 1
	}
	defer func() {
		if stopErr := testEnv.Stop(); stopErr != nil {
			fmt.Fprintf(os.Stderr, "stop envtest: %v\n", stopErr)
			code = 1
		}
	}()

	// Fixture writes and reads go directly to the API server. Controllers
	// retain their normal cached clients and reconcile asynchronously.
	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		fmt.Fprintf(os.Stderr, "create fixture client: %v\n", err)
		return 1
	}
	systemNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: controller.SystemNamespace}}
	if err := k8sClient.Create(ctx, systemNS); err != nil {
		fmt.Fprintf(os.Stderr, "create system namespace: %v\n", err)
		return 1
	}
	return m.Run()
}

// Tests use `defer startControllers(t)()` so their controllers stop before
// t.Cleanup removes fixtures. Tests share only the API server and run serially.
func startControllers(t *testing.T) func() {
	t.Helper()
	// Envtest has no garbage collector. Clear generated resources as well as
	// fixtures, especially alerts that would block the next test's probes.
	// Background deletion avoids the orphan finalizer that would retain Jobs.
	t.Cleanup(func() {
		for _, obj := range []client.Object{
			&siderealv1alpha1.SiderealProbe{}, &batchv1.Job{},
			&siderealv1alpha1.SiderealProbeResult{}, &siderealv1alpha1.SiderealIncident{},
			&siderealv1alpha1.SiderealSystemAlert{}, &siderealv1alpha1.SiderealAOAuthorization{},
			&siderealv1alpha1.SiderealProbeRecommendation{}, &siderealv1alpha1.SiderealReport{},
			&corev1.ConfigMap{}, &corev1.Secret{}, &corev1.ServiceAccount{}, &networkingv1.NetworkPolicy{},
		} {
			if err := k8sClient.DeleteAllOf(ctx, obj, client.InNamespace(controller.SystemNamespace), client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil {
				t.Errorf("clean up %T: %v", obj, err)
			}
		}
	})
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		// Controller names are reused by serial, independent test managers.
		Controller: config.Controller{SkipNameValidation: ptr.To(true)},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	cw := crosswalk.NewResolver()
	if err := cw.LoadFromDir(filepath.Join(findProjectRoot(), "internal", "crosswalk", "data")); err != nil {
		t.Fatalf("load crosswalk: %v", err)
	}
	reconcilers := []interface{ SetupWithManager(ctrl.Manager) error }{
		&controller.ProbeSchedulerReconciler{
			Client: mgr.GetClient(), ProbeGoImage: testProbeImage, ProbeDetectionImage: testProbeImage,
			RegisteredCustomSAs: map[string]bool{"sidereal-probe-custom-test": true},
		},
		&controller.ResultReconciler{Client: mgr.GetClient(), Crosswalk: cw},
		&controller.IncidentReconciler{Client: mgr.GetClient()},
		&controller.AlertReconciler{Client: mgr.GetClient()},
		&controller.AuthorizationReconciler{Client: mgr.GetClient()},
	}
	for _, reconciler := range reconcilers {
		if err := reconciler.SetupWithManager(mgr); err != nil {
			t.Fatalf("set up %T: %v", reconciler, err)
		}
	}
	// Register watched types before starting so cache sync cannot succeed
	// with an empty informer set while controller startup is still pending.
	for _, obj := range []client.Object{
		&siderealv1alpha1.SiderealProbe{}, &batchv1.Job{},
		&siderealv1alpha1.SiderealProbeResult{}, &siderealv1alpha1.SiderealSystemAlert{},
		&siderealv1alpha1.SiderealAOAuthorization{},
	} {
		if _, err := mgr.GetCache().GetInformer(ctx, obj); err != nil {
			t.Fatalf("register informer for %T: %v", obj, err)
		}
	}
	managerCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- mgr.Start(managerCtx) }()
	stop := func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("manager exited: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("controller shutdown timed out")
		}
	}
	syncCtx, cancelSync := context.WithTimeout(managerCtx, 10*time.Second)
	defer cancelSync()
	if !mgr.GetCache().WaitForCacheSync(syncCtx) {
		stop()
		t.Fatal("cache sync failed")
	}
	return stop
}

func eventually(t *testing.T, description string, timeout time.Duration, condition func() (bool, error)) {
	t.Helper()
	err := wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, timeout, true, func(context.Context) (bool, error) {
		return condition()
	})
	if err != nil {
		t.Fatalf("waiting for %s: %v", description, err)
	}
}

func consistently(t *testing.T, description string, duration time.Duration, condition func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(duration)
	for {
		ok, err := condition()
		if err != nil || !ok {
			t.Fatalf("%s: condition=%t error=%v", description, ok, err)
		}
		if !time.Now().Before(deadline) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func waitForScheduledProbe(t *testing.T, probe *siderealv1alpha1.SiderealProbe) {
	t.Helper()
	eventually(t, "probe scheduling status", 10*time.Second, func() (bool, error) {
		var current siderealv1alpha1.SiderealProbe
		err := k8sClient.Get(ctx, client.ObjectKeyFromObject(probe), &current)
		return current.Status.LastExecutedAt != nil, err
	})
}

func completeJob(t *testing.T, job *batchv1.Job) {
	t.Helper()
	now := metav1.Now()
	job.Status = batchv1.JobStatus{
		StartTime: &now, CompletionTime: &now, Succeeded: 1,
		Conditions: []batchv1.JobCondition{
			{Type: batchv1.JobSuccessCriteriaMet, Status: corev1.ConditionTrue, LastTransitionTime: now},
			{Type: batchv1.JobComplete, Status: corev1.ConditionTrue, LastTransitionTime: now},
		},
	}
	if err := k8sClient.Status().Update(ctx, job); err != nil {
		t.Fatalf("complete Job through status subresource: %v", err)
	}
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
		deleteFixture(t, ns)
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
		deleteFixture(t, secret)
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
		deleteFixture(t, probe)
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
	if err = k8sClient.Create(ctx, cm); err != nil {
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
	var existingSecret corev1.Secret
	err = k8sClient.Get(ctx, client.ObjectKeyFromObject(hmacSecret), &existingSecret)
	if apierrors.IsNotFound(err) {
		if err = k8sClient.Create(ctx, hmacSecret); err != nil {
			t.Fatalf("create HMAC secret: %v", err)
		}
	} else if err != nil {
		t.Fatalf("get execution HMAC secret: %v", err)
	} else if !bytes.Equal(existingSecret.Data["hmac-key"], execKey) {
		t.Fatal("scheduler execution key differs from the derived fixture key")
	}

	// The API clears status on Create, so mark completion after creation.
	ttl := int32(controller.JobTTLSeconds)
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf("sidereal-probe-%s", shortID),
			Namespace:   controller.SystemNamespace,
			Annotations: map[string]string{controller.ProbeProfileAnnotation: probeType},
			Labels: map[string]string{
				controller.FingerprintLabel:     probeID,
				controller.ProbeProfileLabel:    controller.ProbeProfileLabelValue(probeType),
				controller.ProbeNameLabel:       probeName,
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
							Image: testProbeImage,
						},
					},
				},
			},
		},
	}
	var scheduled batchv1.Job
	err = k8sClient.Get(ctx, client.ObjectKeyFromObject(job), &scheduled)
	if apierrors.IsNotFound(err) {
		if err = k8sClient.Create(ctx, job); err != nil {
			t.Fatalf("create simulated Job: %v", err)
		}
	} else if err != nil {
		t.Fatalf("get scheduled Job: %v", err)
	} else {
		if scheduled.Labels[controller.FingerprintLabel] != probeID {
			t.Fatal("execution IDs collide on the Job name")
		}
		job = &scheduled
	}
	t.Cleanup(func() { deleteFixture(t, job) })
	completeJob(t, job)
}

// waitForProbeResult polls until the result for this execution appears.
func waitForProbeResult(t *testing.T, probeID string, timeout time.Duration) *siderealv1alpha1.SiderealProbeResult {
	t.Helper()
	var results siderealv1alpha1.SiderealProbeResultList
	eventually(t, "ProbeResult for "+probeID, timeout, func() (bool, error) {
		err := k8sClient.List(ctx, &results, client.InNamespace(controller.SystemNamespace), client.MatchingLabels{controller.FingerprintLabel: probeID})
		return len(results.Items) > 0, err
	})
	return &results.Items[0]
}

func waitForIncident(t *testing.T, probeID string, timeout time.Duration) *siderealv1alpha1.SiderealIncident {
	t.Helper()
	var incidents siderealv1alpha1.SiderealIncidentList
	eventually(t, "Incident for "+probeID, timeout, func() (bool, error) {
		err := k8sClient.List(ctx, &incidents, client.InNamespace(controller.SystemNamespace), client.MatchingLabels{controller.FingerprintLabel: probeID})
		return len(incidents.Items) > 0, err
	})
	return &incidents.Items[0]
}

func waitForAlert(t *testing.T, name string, timeout time.Duration) *siderealv1alpha1.SiderealSystemAlert {
	t.Helper()
	var alert siderealv1alpha1.SiderealSystemAlert
	eventually(t, "SystemAlert "+name, timeout, func() (bool, error) {
		err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: controller.SystemNamespace}, &alert)
		return err == nil, client.IgnoreNotFound(err)
	})
	return &alert
}

// uniqueID generates a short unique suffix for test resource names.
func uniqueID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", b)
}

func deleteFixture(t *testing.T, obj client.Object) {
	t.Helper()
	if err := k8sClient.Delete(ctx, obj, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil && !apierrors.IsNotFound(err) {
		t.Errorf("delete fixture %T %s: %v", obj, obj.GetName(), err)
	}
}

func scheduledJob(t *testing.T, probe *siderealv1alpha1.SiderealProbe) *batchv1.Job {
	t.Helper()
	waitForScheduledProbe(t, probe)
	var jobs batchv1.JobList
	if err := k8sClient.List(ctx, &jobs, client.InNamespace(controller.SystemNamespace), client.MatchingLabels{controller.ProbeNameLabel: probe.Name}); err != nil {
		t.Fatal(err)
	}
	if len(jobs.Items) != 1 {
		t.Fatalf("expected one scheduled Job for %s, got %d", probe.Name, len(jobs.Items))
	}
	return &jobs.Items[0]
}
