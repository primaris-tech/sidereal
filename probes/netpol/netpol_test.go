package netpol

import (
	"context"
	"testing"
	"time"

	"github.com/primaris-tech/sidereal/internal/backend/networkpolicy"
	"github.com/primaris-tech/sidereal/internal/probe"
)

func baseCfg() probe.Config {
	return probe.Config{
		ProbeID:         "test-netpol-1",
		Profile:         "netpol",
		TargetNamespace: "production",
		ExecutionMode:   "dryRun",
	}
}

func TestExecute_NoTargetHost(t *testing.T) {
	netCfg := Config{
		VerificationMode: networkpolicy.ModeTCPInference,
		TargetHost:       "",
		TargetPort:       80,
	}

	result := ExecuteWithConfig(context.Background(), baseCfg(), netCfg)

	if result.Outcome != "Indeterminate" {
		t.Errorf("expected Indeterminate for missing target host, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_UnknownMode(t *testing.T) {
	netCfg := Config{
		VerificationMode: "invalid-mode",
		TargetHost:       "10.0.0.1",
		TargetPort:       80,
	}

	result := ExecuteWithConfig(context.Background(), baseCfg(), netCfg)

	if result.Outcome != "Indeterminate" {
		t.Errorf("expected Indeterminate for unknown mode, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_CNIVerdictDelegated(t *testing.T) {
	// cni-verdict mode should send traffic and return Indeterminate (awaiting controller).
	netCfg := Config{
		VerificationMode: networkpolicy.ModeCNIVerdict,
		TargetHost:       "10.96.0.1",
		TargetPort:       443,
		ConnectTimeout:   100 * time.Millisecond,
	}

	result := ExecuteWithConfig(context.Background(), baseCfg(), netCfg)

	if result.Outcome != "Indeterminate" {
		t.Errorf("expected Indeterminate for delegated mode, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestExecute_ResponderDelegated(t *testing.T) {
	netCfg := Config{
		VerificationMode: networkpolicy.ModeResponder,
		TargetHost:       "10.96.0.1",
		TargetPort:       80,
		ConnectTimeout:   100 * time.Millisecond,
	}

	result := ExecuteWithConfig(context.Background(), baseCfg(), netCfg)

	if result.Outcome != "Indeterminate" {
		t.Errorf("expected Indeterminate for responder mode, got %q: %s", result.Outcome, result.Detail)
	}
}

func TestVerdictToResult_AllVerdicts(t *testing.T) {
	netCfg := Config{
		TargetHost: "10.0.0.1",
		TargetPort: 80,
	}

	tests := []struct {
		verdict         networkpolicy.Verdict
		expectedOutcome string
	}{
		{networkpolicy.VerdictDropped, "Blocked"},
		{networkpolicy.VerdictInferredDropped, "Blocked"},
		{networkpolicy.VerdictForwarded, "NotEnforced"},
		{networkpolicy.VerdictInferredForwarded, "NotEnforced"},
		{networkpolicy.VerdictIndeterminate, "Indeterminate"},
		{networkpolicy.Verdict("Unknown"), "Indeterminate"},
	}

	for _, tt := range tests {
		t.Run(string(tt.verdict), func(t *testing.T) {
			result := verdictToResult(tt.verdict, netCfg, 100)
			if result.Outcome != tt.expectedOutcome {
				t.Errorf("verdict %q: expected outcome %q, got %q", tt.verdict, tt.expectedOutcome, result.Outcome)
			}
			if result.DurationMs != 100 {
				t.Errorf("expected duration 100, got %d", result.DurationMs)
			}
		})
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	// With no env vars set, should get sensible defaults.
	cfg := LoadConfig()

	if cfg.VerificationMode != networkpolicy.ModeTCPInference {
		t.Errorf("expected default mode tcp-inference, got %q", cfg.VerificationMode)
	}
	if cfg.TargetPort != 80 {
		t.Errorf("expected default port 80, got %d", cfg.TargetPort)
	}
	if cfg.ConnectTimeout != 5*time.Second {
		t.Errorf("expected default timeout 5s, got %v", cfg.ConnectTimeout)
	}
}

func TestLoadConfig_FromEnv(t *testing.T) {
	t.Setenv("NETPOL_VERIFICATION_MODE", "cni-verdict")
	t.Setenv("NETPOL_TARGET_HOST", "10.96.0.1")
	t.Setenv("NETPOL_TARGET_PORT", "443")
	t.Setenv("NETPOL_CONNECT_TIMEOUT", "3s")

	cfg := LoadConfig()

	if cfg.VerificationMode != networkpolicy.ModeCNIVerdict {
		t.Errorf("expected cni-verdict, got %q", cfg.VerificationMode)
	}
	if cfg.TargetHost != "10.96.0.1" {
		t.Errorf("expected 10.96.0.1, got %q", cfg.TargetHost)
	}
	if cfg.TargetPort != 443 {
		t.Errorf("expected 443, got %d", cfg.TargetPort)
	}
	if cfg.ConnectTimeout != 3*time.Second {
		t.Errorf("expected 3s, got %v", cfg.ConnectTimeout)
	}
}
