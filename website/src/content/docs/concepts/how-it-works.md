---
title: How Sidereal Works
description: Architecture and component overview
---

Sidereal is deployed as a Kubernetes operator via Helm into the `sidereal-system` namespace.

## Component separation

Sidereal enforces strict privilege isolation between three component types:

**Controller Manager** orchestrates scheduling, verifies results, manages recommendations, and exports audit records. It holds only Job-creation and CRD read/write permissions. It cannot perform probe operations.

**Probe Runner Jobs** are short-lived, immutable Kubernetes Jobs. One Job per probe execution. Each runs as non-root with a read-only filesystem, all capabilities dropped, and TTL-based cleanup. Probe runners cannot write their own results directly to CRDs.

**Per-Probe ServiceAccounts** provide minimum required RBAC for each probe type. The RBAC probe SA can only perform SelfSubjectAccessReview. The Secret probe SA can only attempt Secret reads. No SA has permissions beyond what its probe needs.

## Execution flow

1. The **Probe Scheduler** reconciler watches SiderealProbe resources. When execution is due, it derives a per-execution HMAC key from the root secret and creates a Kubernetes Job.

2. The **Probe Runner** Job executes the probe logic (e.g., attempts an unauthorized API call), signs the result with the HMAC key, and writes the signed result to a ConfigMap.

3. The **Result Reconciler** watches for completed Jobs, reads the result ConfigMap, verifies the HMAC signature, and creates an immutable SiderealProbeResult CRD.

4. If HMAC verification fails, a `TamperedResult` outcome is recorded and a SystemAlert is created, suspending the affected probe surface.

5. The **Incident Reconciler** watches ProbeResults. In `enforce` mode, if controlEffectiveness is `Ineffective` or `Compromised`, it creates a SiderealIncident and delivers it to the IR webhook.

## Detection probe flow

Detection probes follow a different pattern because they validate the detection pipeline, not just Kubernetes controls:

1. The controller verifies an active AO authorization exists for the technique and namespace.
2. A Rust-based probe container fires a synthetic syscall pattern (e.g., execve of a known-bad path) and exits.
3. The controller independently queries the detection backend (Falco or Tetragon) every 5 seconds for 60 seconds to verify an alert was raised.
4. Two separate identities, two separate actions. If the detection pipeline missed the pattern, Sidereal surfaces the gap.

## HMAC integrity

Every probe result is signed with a per-execution key derived via HKDF-SHA256 from a KMS-encrypted root secret. The probe signs the result, the controller verifies it. This ensures a compromised probe runner cannot produce falsified evidence. An invalid signature produces a `TamperedResult` outcome with `Compromised` effectiveness, creates a SystemAlert, and suspends the affected probe surface.
