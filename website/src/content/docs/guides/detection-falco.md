---
title: Detection Probes with Falco
description: Setting up Falco integration and creating detection probes with AO authorization
---

Detection probes validate that your runtime threat detection layer is working. They fire synthetic syscall patterns that match known MITRE ATT&CK techniques, then verify that Falco raises the expected alert. If the alert never arrives, the control is ineffective and the probe reports it.

## Prerequisites

Your cluster needs a running Falco deployment with gRPC output enabled. Sidereal connects to Falco's gRPC endpoint, which defaults to `falco-grpc.falco:50051`. Configure this in your Helm values:

```yaml
profile:
  detectionBackend: falco

detection:
  falco:
    endpoint: falco-grpc.falco:50051
```

If you are using Tetragon instead, set `profile.detectionBackend: tetragon` and configure the `detection.tetragon.endpoint` (default `tetragon.kube-system:54321`).

## AO Authorization

Detection probes require an active `SiderealAOAuthorization` before they will execute. This is a time-bounded, technique-scoped, namespace-scoped authorization from an Authorizing Official. Without it, the controller will refuse to schedule detection probe jobs.

```yaml
apiVersion: sidereal.cloud/v1alpha1
kind: SiderealAOAuthorization
metadata:
  name: q1-detection-auth
  namespace: sidereal-system
spec:
  aoName: "Jane Smith"
  authorizedTechniques:
    - T1053.007
    - T1059.004
    - T1105
  authorizedNamespaces:
    - production
    - staging
  validFrom: "2026-01-01T00:00:00Z"
  expiresAt: "2026-04-01T00:00:00Z"
  justification: "Q1 continuous monitoring authorization for detection coverage validation"
```

Key fields:

- **aoName** -- the individual Authorizing Official, not a team or role.
- **authorizedTechniques** -- MITRE ATT&CK technique IDs. Only these techniques may be probed.
- **authorizedNamespaces** -- explicit namespace list. No wildcards.
- **validFrom / expiresAt** -- the controller computes `status.active` from these bounds. Expired authorizations trigger a `SiderealSystemAlert`.

## Creating a Detection Probe

With the authorization in place, create a `SiderealProbe` that references it:

```yaml
apiVersion: sidereal.cloud/v1alpha1
kind: SiderealProbe
metadata:
  name: detect-container-drift-staging
  namespace: sidereal-system
spec:
  probeType: detection
  targetNamespace: staging
  executionMode: observe
  intervalSeconds: 21600
  mitreAttackId: T1053.007
  aoAuthorizationRef: q1-detection-auth
  verificationWindowSeconds: 60
```

## How verification works

The detection probe runs in two phases with strict privilege separation:

1. **Probe runner job** -- a short-lived Kubernetes Job running the Rust detection probe binary. It fires a synthetic syscall pattern matching the specified ATT&CK technique, then exits. The probe container has no network access, no volume mounts, no credentials, and drops all capabilities.

2. **Controller verification** -- the controller polls the Falco gRPC backend every 5 seconds for up to `verificationWindowSeconds` (default 60s), checking whether Falco raised an alert matching the probe's fingerprint label.

If Falco detects the synthetic activity, the result is `Detected` with effectiveness `Effective`. If the verification window expires without a matching alert, the result is `Undetected` with effectiveness `Ineffective`.

## Supported MITRE ATT&CK techniques

The Rust detection probe supports 9 techniques. Each produces a distinct syscall pattern that a properly configured Falco rule set should catch. The techniques cover execution, persistence, privilege escalation, and other MITRE ATT&CK tactics relevant to container workloads.
