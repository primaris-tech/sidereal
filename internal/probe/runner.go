package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	siderealhmac "github.com/primaris-tech/sidereal/internal/hmac"
)

const (
	// ResultConfigMapPrefix is the naming convention for result ConfigMaps.
	ResultConfigMapPrefix = "sidereal-result-"
)

// Config holds the environment-provided configuration for a probe runner.
type Config struct {
	ProbeID         string
	ProbeType       string
	TargetNamespace string
	ExecutionMode   string
	HMACKeyPath     string
}

// LoadConfigFromEnv reads probe runner configuration from environment variables.
func LoadConfigFromEnv() Config {
	return Config{
		ProbeID:         os.Getenv("PROBE_ID"),
		ProbeType:       os.Getenv("PROBE_TYPE"),
		TargetNamespace: os.Getenv("TARGET_NAMESPACE"),
		ExecutionMode:   os.Getenv("EXECUTION_MODE"),
		HMACKeyPath:     os.Getenv("HMAC_KEY_PATH"),
	}
}

// LoadHMACKey reads the HMAC key from the mounted Secret volume.
func LoadHMACKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("probe: failed to read HMAC key from %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("probe: HMAC key at %s is empty", path)
	}
	return data, nil
}

// MustLoadHMACKey reads the HMAC key or exits the process.
func MustLoadHMACKey(path string) []byte {
	key, err := LoadHMACKey(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
	return key
}

// SignAndWriteResult serializes the result, signs it with HMAC, and writes
// the result + signature to a ConfigMap for the controller to consume.
func SignAndWriteResult(ctx context.Context, clientset kubernetes.Interface, namespace, probeID string, key []byte, result Result) error {
	payload, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("probe: failed to marshal result: %w", err)
	}

	signature, err := siderealhmac.SignResult(key, payload)
	if err != nil {
		return fmt.Errorf("probe: failed to sign result: %w", err)
	}

	cmName := ResultConfigMapPrefix + probeID[:8]
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: namespace,
			Labels: map[string]string{
				"sidereal.cloud/probe-id": probeID,
			},
		},
		Data: map[string]string{
			"result": string(payload),
			"hmac":   signature,
		},
	}

	_, err = clientset.CoreV1().ConfigMaps(namespace).Create(ctx, cm, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("probe: failed to create result ConfigMap %s: %w", cmName, err)
	}

	return nil
}

// MustSignAndWriteResult signs and writes the result or exits the process.
func MustSignAndWriteResult(ctx context.Context, clientset kubernetes.Interface, namespace, probeID string, key []byte, result Result) {
	if err := SignAndWriteResult(ctx, clientset, namespace, probeID, key, result); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

// NewInClusterClientset creates a Kubernetes clientset from the in-cluster config.
func NewInClusterClientset() (kubernetes.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("probe: failed to get in-cluster config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("probe: failed to create clientset: %w", err)
	}
	return clientset, nil
}

// Run is the standard probe runner entrypoint. It handles config loading,
// HMAC key loading, probe execution, result signing, and ConfigMap writing.
// The executeFn performs the actual probe logic.
func Run(executeFn func(ctx context.Context, cfg Config) Result) {
	RunWithClient(func(ctx context.Context, clientset kubernetes.Interface, cfg Config) Result {
		return executeFn(ctx, cfg)
	})
}

// RunWithClient is like Run but also passes the in-cluster Kubernetes clientset
// to the execute function. Use this when the probe needs to make API calls
// (e.g., SelfSubjectAccessReview for RBAC probes).
func RunWithClient(executeFn func(ctx context.Context, clientset kubernetes.Interface, cfg Config) Result) {
	cfg := LoadConfigFromEnv()
	key := MustLoadHMACKey(cfg.HMACKeyPath)

	clientset, err := NewInClusterClientset()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result := executeFn(ctx, clientset, cfg)

	MustSignAndWriteResult(ctx, clientset, "sidereal-system", cfg.ProbeID, key, result)
}
