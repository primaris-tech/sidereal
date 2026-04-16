package probe

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	siderealhmac "github.com/primaris-tech/sidereal/internal/hmac"
)

// testPhasedProbe is a PhasedProbe implementation for testing.
type testPhasedProbe struct {
	setupErr       error
	executeResult  Result
	teardownErr    error
	setupCalled    bool
	executeCalled  bool
	teardownCalled bool
}

func (p *testPhasedProbe) Setup(_ context.Context, _ kubernetes.Interface, _ Config) error {
	p.setupCalled = true
	return p.setupErr
}

func (p *testPhasedProbe) Execute(_ context.Context, _ kubernetes.Interface, _ Config) Result {
	p.executeCalled = true
	return p.executeResult
}

func (p *testPhasedProbe) Teardown(_ context.Context, _ kubernetes.Interface, _ Config) error {
	p.teardownCalled = true
	return p.teardownErr
}

func TestExecutePhasedProbe_HappyPath(t *testing.T) {
	probeID := "dddddddd-eeee-ffff-aaaa-bbbbbbbbbbbb"
	rootKey := []byte("test-root-key-32-bytes-long!!!!")
	execKey, _ := siderealhmac.DeriveExecutionKey(rootKey, probeID)

	p := &testPhasedProbe{
		executeResult: Result{Outcome: "Pass", Detail: "all checks passed", DurationMs: 10},
	}
	cfg := Config{ProbeID: probeID, TargetNamespace: "default"}
	cs := fake.NewSimpleClientset()

	executePhasedProbe(p, cs, cfg, execKey)

	if !p.setupCalled {
		t.Error("expected Setup to be called")
	}
	if !p.executeCalled {
		t.Error("expected Execute to be called")
	}
	if !p.teardownCalled {
		t.Error("expected Teardown to be called")
	}

	cmName := ResultConfigMapPrefix + probeID[:8]
	cm, err := cs.CoreV1().ConfigMaps("sidereal-system").Get(context.Background(), cmName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("result ConfigMap not written: %v", err)
	}
	if cm.Data["result"] == "" {
		t.Error("result ConfigMap has empty result")
	}
}

func TestExecutePhasedProbe_TeardownCalledOnSetupFailure(t *testing.T) {
	probeID := "eeeeeeee-ffff-aaaa-bbbb-cccccccccccc"
	rootKey := []byte("test-root-key-32-bytes-long!!!!")
	execKey, _ := siderealhmac.DeriveExecutionKey(rootKey, probeID)

	p := &testPhasedProbe{
		setupErr: errors.New("prerequisite resource creation failed"),
	}
	cfg := Config{ProbeID: probeID, TargetNamespace: "default"}
	cs := fake.NewSimpleClientset()

	executePhasedProbe(p, cs, cfg, execKey)

	if !p.setupCalled {
		t.Error("expected Setup to be called")
	}
	if p.executeCalled {
		t.Error("Execute should not be called after Setup failure")
	}
	if !p.teardownCalled {
		t.Error("Teardown must be called even when Setup fails")
	}

	// An Indeterminate result should be written.
	cmName := ResultConfigMapPrefix + probeID[:8]
	cm, err := cs.CoreV1().ConfigMaps("sidereal-system").Get(context.Background(), cmName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("result ConfigMap not written after Setup failure: %v", err)
	}
	var result Result
	if err := json.Unmarshal([]byte(cm.Data["result"]), &result); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}
	if result.Outcome != "Indeterminate" {
		t.Errorf("expected Indeterminate outcome after Setup failure, got %q", result.Outcome)
	}
}

func TestExecutePhasedProbe_TeardownCalledOnExecuteFailure(t *testing.T) {
	probeID := "ffffffff-aaaa-bbbb-cccc-dddddddddddd"
	rootKey := []byte("test-root-key-32-bytes-long!!!!")
	execKey, _ := siderealhmac.DeriveExecutionKey(rootKey, probeID)

	p := &testPhasedProbe{
		executeResult: Result{Outcome: "Fail", Detail: "control not enforcing", DurationMs: 5},
	}
	cfg := Config{ProbeID: probeID, TargetNamespace: "default"}
	cs := fake.NewSimpleClientset()

	executePhasedProbe(p, cs, cfg, execKey)

	if !p.teardownCalled {
		t.Error("Teardown must be called even when Execute returns Fail")
	}
}

func TestLoadHMACKey(t *testing.T) {
	t.Run("reads key from file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "hmac-key")
		os.WriteFile(path, []byte("test-key-data"), 0600)

		key, err := LoadHMACKey(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(key) != "test-key-data" {
			t.Errorf("expected 'test-key-data', got %q", string(key))
		}
	})

	t.Run("returns error for missing file", func(t *testing.T) {
		_, err := LoadHMACKey("/nonexistent/path")
		if err == nil {
			t.Error("expected error for missing file")
		}
	})

	t.Run("returns error for empty file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "empty-key")
		os.WriteFile(path, []byte{}, 0600)

		_, err := LoadHMACKey(path)
		if err == nil {
			t.Error("expected error for empty key")
		}
	})
}

func TestSignAndWriteResult(t *testing.T) {
	probeID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	rootKey := []byte("test-root-key-32-bytes-long!!!!")
	execKey, _ := siderealhmac.DeriveExecutionKey(rootKey, probeID)

	result := Result{
		Outcome:    "Pass",
		Detail:     "RBAC boundaries enforced",
		DurationMs: 150,
	}

	clientset := fake.NewSimpleClientset()
	ctx := context.Background()

	err := SignAndWriteResult(ctx, clientset, "sidereal-system", probeID, execKey, result)
	if err != nil {
		t.Fatalf("SignAndWriteResult failed: %v", err)
	}

	// Verify ConfigMap was created.
	cmName := ResultConfigMapPrefix + probeID[:8]
	cm, err := clientset.CoreV1().ConfigMaps("sidereal-system").Get(ctx, cmName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get result ConfigMap: %v", err)
	}

	// Verify it has result and hmac keys.
	resultPayload, ok := cm.Data["result"]
	if !ok {
		t.Fatal("ConfigMap missing 'result' key")
	}
	signature, ok := cm.Data["hmac"]
	if !ok {
		t.Fatal("ConfigMap missing 'hmac' key")
	}

	// Verify the payload deserializes correctly.
	var parsed Result
	if err := json.Unmarshal([]byte(resultPayload), &parsed); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}
	if parsed.Outcome != "Pass" {
		t.Errorf("expected outcome 'Pass', got %q", parsed.Outcome)
	}
	if parsed.Detail != "RBAC boundaries enforced" {
		t.Errorf("unexpected detail: %q", parsed.Detail)
	}
	if parsed.DurationMs != 150 {
		t.Errorf("expected 150ms, got %d", parsed.DurationMs)
	}

	// Verify the HMAC signature is valid.
	if err := siderealhmac.VerifyResult(execKey, []byte(resultPayload), signature); err != nil {
		t.Errorf("HMAC verification failed: %v", err)
	}

	// Verify the label.
	if cm.Labels["sidereal.cloud/probe-id"] != probeID {
		t.Errorf("expected probe-id label %q, got %q", probeID, cm.Labels["sidereal.cloud/probe-id"])
	}
}

func TestSignAndWriteResult_ControllerCanVerify(t *testing.T) {
	// End-to-end: probe runner signs → controller verifies.
	probeID := "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
	rootKey := []byte("production-root-key-32-bytes!!")
	execKey, _ := siderealhmac.DeriveExecutionKey(rootKey, probeID)

	result := Result{
		Outcome:    "Fail",
		Detail:     "Cross-namespace secret access allowed",
		DurationMs: 230,
	}

	clientset := fake.NewSimpleClientset()
	ctx := context.Background()

	// Probe runner writes.
	err := SignAndWriteResult(ctx, clientset, "sidereal-system", probeID, execKey, result)
	if err != nil {
		t.Fatalf("SignAndWriteResult failed: %v", err)
	}

	// Controller reads (simulated).
	cmName := ResultConfigMapPrefix + probeID[:8]
	cm, _ := clientset.CoreV1().ConfigMaps("sidereal-system").Get(ctx, cmName, metav1.GetOptions{})

	// Controller re-derives the same key from the same root.
	controllerKey, _ := siderealhmac.DeriveExecutionKey(rootKey, probeID)

	// Controller verifies.
	if err := siderealhmac.VerifyResult(controllerKey, []byte(cm.Data["result"]), cm.Data["hmac"]); err != nil {
		t.Fatalf("controller-side HMAC verification failed: %v", err)
	}

	// Verify tampered payload is detected.
	tampered := []byte(`{"outcome":"Pass","detail":"nothing to see here","durationMs":1}`)
	if err := siderealhmac.VerifyResult(controllerKey, tampered, cm.Data["hmac"]); err == nil {
		t.Error("expected verification failure for tampered payload")
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	t.Setenv("PROBE_ID", "test-id")
	t.Setenv("PROBE_PROFILE", "rbac")
	t.Setenv("TARGET_NAMESPACE", "production")
	t.Setenv("EXECUTION_MODE", "observe")
	t.Setenv("HMAC_KEY_PATH", "/var/run/secrets/sidereal/hmac-key")

	cfg := LoadConfigFromEnv()

	if cfg.ProbeID != "test-id" {
		t.Errorf("expected ProbeID 'test-id', got %q", cfg.ProbeID)
	}
	if cfg.Profile != "rbac" {
		t.Errorf("expected Profile 'rbac', got %q", cfg.Profile)
	}
	if cfg.TargetNamespace != "production" {
		t.Errorf("expected TargetNamespace 'production', got %q", cfg.TargetNamespace)
	}
	if cfg.ExecutionMode != "observe" {
		t.Errorf("expected ExecutionMode 'observe', got %q", cfg.ExecutionMode)
	}
	if cfg.HMACKeyPath != "/var/run/secrets/sidereal/hmac-key" {
		t.Errorf("expected HMACKeyPath, got %q", cfg.HMACKeyPath)
	}
}

// Verify the ConfigMap naming convention matches what the result reconciler expects.
func TestConfigMapNamingConvention(t *testing.T) {
	probeID := "12345678-abcd-efgh-ijkl-mnopqrstuvwx"
	expected := "sidereal-result-12345678"
	got := ResultConfigMapPrefix + probeID[:8]
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

// Verify the fake clientset rejects duplicate ConfigMap creation.
func TestSignAndWriteResult_DuplicateRejected(t *testing.T) {
	probeID := "cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa"
	key := []byte("test-key-32-bytes-long-enough!!")

	result := Result{Outcome: "Pass", Detail: "ok", DurationMs: 50}

	// Pre-create the ConfigMap.
	cmName := ResultConfigMapPrefix + probeID[:8]
	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: "sidereal-system",
		},
	}
	clientset := fake.NewSimpleClientset(existing)

	err := SignAndWriteResult(context.Background(), clientset, "sidereal-system", probeID, key, result)
	if err == nil {
		t.Error("expected error for duplicate ConfigMap creation")
	}
}
