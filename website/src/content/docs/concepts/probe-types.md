---
title: Probe Types
description: The six probe surfaces Sidereal validates
---

Sidereal ships with five built-in probe types and supports operator-extensible custom probes.

## RBAC

**What it tests**: ServiceAccount permission boundaries are enforced.

The probe uses `SelfSubjectAccessReview` to attempt operations the probe SA should not be allowed to perform in the target namespace. It tests both deny paths (operations that should be blocked) and allow paths (operations that should be permitted).

**Outcomes**: `Pass` (deny path enforced), `Fail` (unauthorized access allowed), `Indeterminate` (API errors)

**Needs**: Nothing beyond Kubernetes RBAC.

## NetworkPolicy

**What it tests**: East-west traffic restrictions are enforced at the CNI layer.

The probe tests whether NetworkPolicy deny paths are actually blocking traffic, not just defined. Three verification modes are available depending on your CNI:

- **cni-verdict**: Queries Hubble (Cilium) or Calico for the CNI's own drop/allow verdict
- **tcp-inference**: Attempts a TCP connection and infers enforcement from timeout/reset (works with any CNI)
- **responder**: Uses a Sidereal-deployed responder pod for controlled traffic tests

When `NETPOL_ALLOW_TARGET_HOST` is configured alongside the deny-path target, the probe runs a dual-path SC-7(5) check: the deny target must be blocked by default-deny, and the allow target must be reachable via an explicit allow rule. Both must pass for the result to be `Blocked`. This is the strongest form of NetworkPolicy validation — it confirms deny-by-default and allow-by-exception are both operating correctly, not just one or the other.

**Outcomes**: `Blocked` (traffic denied on deny path; allow path reachable when dual-path is configured), `NotEnforced` (deny path not blocking, or allow path unexpectedly blocked), `BackendUnreachable` (CNI observability unavailable)

**Needs**: A CNI that enforces NetworkPolicy (most do). Hubble or Calico for cni-verdict mode.

## Admission Control

**What it tests**: Admission controller policies reject non-compliant resource specs.

The probe submits a known-bad resource spec (e.g., privileged container, hostPath mount) via `--dry-run=server` and verifies the admission controller rejects it.

**Outcomes**: `Rejected` (policy enforced), `Accepted` (spec was allowed through), `Indeterminate` (no webhook evaluation in response)

**Needs**: Kyverno or OPA/Gatekeeper.

## Secret Access

**What it tests**: Cross-namespace Secret isolation.

The probe attempts to read Secrets in the target namespace from a ServiceAccount in a different namespace. All reads should be denied.

**Outcomes**: `Pass` (all reads denied), `Fail` (Secrets were readable)

**Needs**: Nothing beyond Kubernetes RBAC.

## Detection Coverage

**What it tests**: The detection pipeline catches known-bad behavior.

A Rust-based probe container fires a synthetic syscall pattern matching a MITRE ATT&CK technique. The controller independently queries the detection backend to verify an alert was raised. Nine techniques are supported:

| Technique | Description |
|---|---|
| T1053.007 | Container Orchestration Job |
| T1059.004 | Unix Shell |
| T1068 | Privilege Escalation |
| T1069.003 | Cloud Groups Discovery |
| T1078.001 | Default Accounts |
| T1552.001 | Credentials In Files |
| T1552.007 | Container API |
| T1611 | Escape to Host |
| T1613 | Container and Resource Discovery |

**Outcomes**: `Detected` (alert raised), `Undetected` (no alert within verification window)

**Needs**: Falco or Tetragon. An active SiderealAOAuthorization.

## Custom

**What it tests**: Agency-specific controls.

A standardized input/output contract lets agencies build probes for controls Sidereal does not cover natively (encryption at rest, certificate expiration, service mesh mTLS, logging pipeline integrity). Custom probes are subject to the same security controls as built-in probes: image signing, HMAC integrity, pod security, admission verification.

**Needs**: A pre-registered ServiceAccount. A cosign-signed, digest-pinned container image.
