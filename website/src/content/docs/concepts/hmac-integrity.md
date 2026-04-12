---
title: HMAC Integrity
description: How Sidereal prevents falsified probe results
---

Sidereal uses HMAC-SHA256 signatures to ensure probe results cannot be tampered with. A compromised probe runner cannot produce falsified evidence.

## How it works

1. A root HMAC key is stored as a Kubernetes Secret in the `sidereal-system` namespace. In production, this should be backed by a KMS.

2. When the scheduler creates a probe Job, it derives a per-execution key using HKDF-SHA256 with the probe's execution ID as the info parameter. The derived key is mounted into the Job as a Secret volume.

3. The probe runner executes the probe logic, serializes the result as JSON, and computes an HMAC-SHA256 signature over the result payload using the derived key. Both the result and signature are written to a ConfigMap.

4. The result reconciler reads the ConfigMap, retrieves the same derived key, and verifies the signature using constant-time comparison.

5. If verification passes, the result is recorded with `integrityStatus: Verified`.

6. If verification fails, the result is recorded as `TamperedResult` with `controlEffectiveness: Compromised`, a SystemAlert is created, and the affected probe surface is suspended until the alert is acknowledged.

## Key properties

- **Per-execution keys**: Each probe execution uses a unique derived key. Compromising one key does not compromise other executions.
- **FIPS 140-2 cryptography**: HMAC-SHA256 routes to BoringCrypto (Go) or aws-lc-rs (Rust), both FIPS validated.
- **Constant-time comparison**: Signature verification uses constant-time comparison to prevent timing attacks.
- **Separation of concerns**: The probe signs, the controller verifies. Neither can perform the other's role.

## Tamper response

When HMAC verification fails:

1. A `TamperedResult` probe result is created with `Compromised` effectiveness
2. A SiderealSystemAlert is created with reason `TamperedResult`
3. The affected probe surface is suspended (no new Jobs scheduled)
4. An individual user (not a ServiceAccount) must acknowledge the alert with a remediation action before probes resume
