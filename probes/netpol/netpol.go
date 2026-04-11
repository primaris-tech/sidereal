// Package netpol implements the NetworkPolicy probe runner, which validates
// that Kubernetes NetworkPolicies are operationally enforcing traffic controls.
//
// Three verification modes are supported:
//   - tcp-inference: the probe attempts a TCP connection and infers the verdict
//     from the result (timeout=dropped, established=forwarded). Works with any CNI.
//   - cni-verdict: the probe sends traffic and exits; the controller queries the
//     CNI observability layer (Hubble/Calico) for the authoritative verdict.
//   - responder: the probe deploys an ephemeral responder pod, sends traffic,
//     and verifies the result end-to-end.
//
// In cni-verdict and responder modes, the probe only sends the traffic and
// reports a preliminary result. The controller performs the backend query and
// writes the final SiderealProbeResult.
package netpol

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/primaris-tech/sidereal/internal/backend/networkpolicy"
	"github.com/primaris-tech/sidereal/internal/probe"
)

// Config holds netpol-probe-specific configuration loaded from environment.
type Config struct {
	// VerificationMode is one of: tcp-inference, cni-verdict, responder.
	VerificationMode networkpolicy.VerificationMode

	// TargetHost is the ClusterIP or DNS name to probe.
	TargetHost string

	// TargetPort is the TCP port to probe.
	TargetPort int

	// ConnectTimeout is the TCP connection timeout for tcp-inference mode.
	ConnectTimeout time.Duration
}

// LoadConfig reads netpol-specific configuration from environment variables.
func LoadConfig() Config {
	port, _ := strconv.Atoi(os.Getenv("NETPOL_TARGET_PORT"))
	if port == 0 {
		port = 80
	}

	timeout, _ := time.ParseDuration(os.Getenv("NETPOL_CONNECT_TIMEOUT"))
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	mode := networkpolicy.VerificationMode(os.Getenv("NETPOL_VERIFICATION_MODE"))
	if mode == "" {
		mode = networkpolicy.ModeTCPInference
	}

	return Config{
		VerificationMode: mode,
		TargetHost:       os.Getenv("NETPOL_TARGET_HOST"),
		TargetPort:       port,
		ConnectTimeout:   timeout,
	}
}

// Execute runs the NetworkPolicy probe.
//
// In tcp-inference mode, the probe performs the full verification inline
// and returns a final result.
//
// In cni-verdict and responder modes, the probe sends the traffic and
// returns a preliminary result indicating that the controller should
// query the backend for the final verdict.
func Execute(ctx context.Context, cfg probe.Config) probe.Result {
	netCfg := LoadConfig()
	return ExecuteWithConfig(ctx, cfg, netCfg)
}

// ExecuteWithConfig is like Execute but accepts an explicit netpol Config
// (used in testing to avoid environment variable dependency).
func ExecuteWithConfig(ctx context.Context, cfg probe.Config, netCfg Config) probe.Result {
	start := time.Now()

	if netCfg.TargetHost == "" {
		return probe.Result{
			Outcome:    "Indeterminate",
			Detail:     "NETPOL_TARGET_HOST not configured",
			DurationMs: time.Since(start).Milliseconds(),
		}
	}

	switch netCfg.VerificationMode {
	case networkpolicy.ModeTCPInference:
		return executeTCPInference(ctx, cfg, netCfg, start)

	case networkpolicy.ModeCNIVerdict, networkpolicy.ModeResponder:
		return executeDelegated(ctx, cfg, netCfg, start)

	default:
		return probe.Result{
			Outcome:    "Indeterminate",
			Detail:     fmt.Sprintf("unknown verification mode: %s", netCfg.VerificationMode),
			DurationMs: time.Since(start).Milliseconds(),
		}
	}
}

// executeTCPInference performs inline TCP connection inference.
func executeTCPInference(ctx context.Context, cfg probe.Config, netCfg Config, start time.Time) probe.Result {
	backend := networkpolicy.NewTCPInferenceBackend(networkpolicy.TCPInferenceConfig{
		TargetHost:     netCfg.TargetHost,
		TargetPort:     netCfg.TargetPort,
		ConnectTimeout: netCfg.ConnectTimeout,
	})

	verdict, err := backend.QueryFlowVerdict(ctx, cfg.ProbeID, 0)
	duration := time.Since(start).Milliseconds()

	if err != nil {
		return probe.Result{
			Outcome:    "Indeterminate",
			Detail:     fmt.Sprintf("tcp-inference error: %v", err),
			DurationMs: duration,
		}
	}

	return verdictToResult(verdict, netCfg, duration)
}

// executeDelegated sends the TCP probe and returns a preliminary result.
// The controller will query the appropriate backend for the final verdict.
func executeDelegated(ctx context.Context, cfg probe.Config, netCfg Config, start time.Time) probe.Result {
	// Use TCP inference backend just for the SYN attempt — we don't interpret
	// the result. The probe exits and the controller queries the CNI backend.
	backend := networkpolicy.NewTCPInferenceBackend(networkpolicy.TCPInferenceConfig{
		TargetHost:     netCfg.TargetHost,
		TargetPort:     netCfg.TargetPort,
		ConnectTimeout: netCfg.ConnectTimeout,
	})

	// Send traffic (we don't care about the TCP-level result here).
	_, _ = backend.QueryFlowVerdict(ctx, cfg.ProbeID, 0)
	duration := time.Since(start).Milliseconds()

	// Return a preliminary result — the controller will replace this with
	// the backend's authoritative verdict.
	return probe.Result{
		Outcome:    "Indeterminate",
		Detail:     fmt.Sprintf("traffic sent via %s mode; awaiting controller backend query against %s:%d", netCfg.VerificationMode, netCfg.TargetHost, netCfg.TargetPort),
		DurationMs: duration,
	}
}

// verdictToResult maps a NetworkPolicy verdict to a probe Result.
func verdictToResult(verdict networkpolicy.Verdict, netCfg Config, durationMs int64) probe.Result {
	target := fmt.Sprintf("%s:%d", netCfg.TargetHost, netCfg.TargetPort)

	switch verdict {
	case networkpolicy.VerdictDropped:
		return probe.Result{
			Outcome:    "Blocked",
			Detail:     fmt.Sprintf("NetworkPolicy dropped traffic to %s (cni-verdict)", target),
			DurationMs: durationMs,
		}
	case networkpolicy.VerdictInferredDropped:
		return probe.Result{
			Outcome:    "Blocked",
			Detail:     fmt.Sprintf("NetworkPolicy inferred to have dropped traffic to %s (tcp-inference: timeout)", target),
			DurationMs: durationMs,
		}
	case networkpolicy.VerdictForwarded:
		return probe.Result{
			Outcome:    "NotEnforced",
			Detail:     fmt.Sprintf("NetworkPolicy did not block traffic to %s (cni-verdict: forwarded)", target),
			DurationMs: durationMs,
		}
	case networkpolicy.VerdictInferredForwarded:
		return probe.Result{
			Outcome:    "NotEnforced",
			Detail:     fmt.Sprintf("NetworkPolicy did not block traffic to %s (tcp-inference: connection established)", target),
			DurationMs: durationMs,
		}
	case networkpolicy.VerdictIndeterminate:
		return probe.Result{
			Outcome:    "Indeterminate",
			Detail:     fmt.Sprintf("could not determine NetworkPolicy enforcement for %s (connection reset)", target),
			DurationMs: durationMs,
		}
	default:
		return probe.Result{
			Outcome:    "Indeterminate",
			Detail:     fmt.Sprintf("unknown verdict %q for %s", verdict, target),
			DurationMs: durationMs,
		}
	}
}
