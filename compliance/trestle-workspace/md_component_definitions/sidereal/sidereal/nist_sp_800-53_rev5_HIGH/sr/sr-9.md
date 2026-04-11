---
x-trestle-comp-def-rules:
  sidereal:
    - name: hmac-result-signing-cosign-image-tamper-detection
      description: Sidereal detects tampering through HMAC signing of all probe result ConfigMaps (verified by the controller before acceptance) and cosign image verification at admission, ensuring both runtime data integrity and binary integrity
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: sr-09
status: implemented
---

# SR-9 — Tamper Resistance and Detection

## Control Statement

Implement a tamper protection program for systems, system components, and
services, including mechanisms to detect and respond to physical and logical
tampering. Cover all lifecycle phases from development through disposal.

## Sidereal Implementation

Sidereal implements tamper detection at three independent layers. Each layer
targets a different tamper attack surface — binary integrity, runtime data
integrity, and audit record integrity — and each generates an automated
response without requiring human triage to detect the tamper event.

### Layer 1: Binary Tamper Detection — cosign Image Verification

The first tamper surface is the probe runner and controller binaries
themselves. An attacker who can substitute a tampered binary can produce
falsified probe results while appearing compliant.

Sidereal's defense: every image is cosign-signed at build time (CM-14).
The admission enforcement policy (`sidereal-image-signature-required` —
rendered for the configured admission controller per the deployment profile)
verifies the cosign signature at every Pod admission. A tampered binary has
a different SHA-256 digest than the signed image — its signature is invalid.
The admission controller (e.g., Kyverno or OPA/Gatekeeper) blocks it at
admission before it ever executes.

This defense is independent of the Sidereal controller. Even a fully
compromised controller cannot bypass admission enforcement. The tamper
protection at the binary layer does not trust Sidereal to protect itself.

### Layer 2: Runtime Data Tamper Detection — HMAC-Signed Result ConfigMaps

The second tamper surface is the probe result data in transit within the
cluster. A probe runner writes its result to a ConfigMap. The controller
reads from that ConfigMap. An attacker with write access to the ConfigMap
(e.g., via a compromised Kubernetes API server component or an RBAC
misconfiguration) could modify the result between write and read, converting
a `Fail` outcome to a `Pass` and hiding a real control failure.

Sidereal's defense: the probe runner signs the result payload with
HMAC-SHA256 before writing it. The HMAC key is derived from a per-execution
secret injected into the Job — it is unique to that execution and not
accessible to any other principal.

The controller verifies the HMAC before ingesting any result. Verification
failure produces a `TamperedResult` outcome:
- The tampered result is **not** recorded as a legitimate `Pass` or `Fail`
- A `SiderealSystemAlert` is created with `reason: TamperedResult`
- The alert is exported to the SIEM with the probe identity and execution ID
- Probe execution on the affected surface is **suspended** until an
  authorized operator acknowledges the alert

This means a tamper event on result data produces an automatic security
escalation rather than a falsified compliance record.

### Layer 3: Audit Record Tamper Detection — Append-Only SiderealProbeResult

The third tamper surface is the audit record itself. An attacker who achieves
cluster-admin could attempt to delete or modify `SiderealProbeResult` records
to erase evidence of a control failure.

Sidereal's defense: an admission enforcement policy (e.g., Kyverno
ClusterPolicy or OPA Constraint) denies UPDATE and DELETE operations on
`SiderealProbeResult` resources for all principals, including cluster-admin. Once created, an audit record cannot be modified or deleted
through the Kubernetes API.

SIEM-exported records are protected by S3 object lock in COMPLIANCE mode
(when S3 export is configured). Object lock prevents deletion or modification
even by the bucket owner during the retention period. This extends
append-only protection to the off-cluster copy, ensuring both in-cluster
and exported records are tamper-resistant.

### Tamper Response Path

When any tamper event is detected, the automated response is:

| Detection Event | Automated Response |
|---|---|
| HMAC signature invalid on result ConfigMap | `TamperedResult` outcome; `SiderealSystemAlert` created; probe surface suspended |
| cosign signature invalid at Pod admission | Admission controller denies admission; Pod never runs; policy event generated |
| Attempted UPDATE/DELETE on SiderealProbeResult | Admission controller denies mutation; audit log entry for the denied request |
| Unexpected network flow (CNI observability correlation) | `SiderealSystemAlert` with `reason: UnexpectedNetworkFlow` |

Every detection event generates a SIEM export record. No tamper event
requires human detection to trigger escalation — the response is automatic.

### Lifecycle Coverage

Tamper protection covers all lifecycle phases:
- **Development**: FIPS-validated build tools; no developer signing access
- **Build**: cosign signing in isolated CI step; Rekor transparency log
- **Distribution**: Immutable OCI registry paths; digest pinning in Helm
- **Deployment**: Admission controller verification; SBOM attestation check
- **Operation**: HMAC result signing; append-only audit records; CNI observability monitoring
- **Disposal**: Audit records retained per AU-11 (365 days minimum); SIEM
  records retained per agency policy

### Enhancement: SR-9(1) — Inspection of Systems or Components

The SBOM (CM-8) and SLSA provenance attestation (SR-4) enable systematic
inspection of any deployed Sidereal component at any point during its
operational life. The cosign-attested SBOM contains the complete dependency
tree; the SLSA attestation provides the build provenance. Either can be
queried without taking the running system offline.

## Evidence Produced

- `SiderealSystemAlert` CRs with `reason: TamperedResult` for any HMAC
  verification failure, exported to SIEM
- `SiderealProbeResult` CRs with `integrityStatus: TamperedResult` for
  rejected tampered results
- Admission controller denial events for any unsigned or tampered Sidereal
  image admission attempt
- Admission controller mutation denial events for attempted modifications to
  `SiderealProbeResult` records
- S3 object lock configuration records (per-agency, per SIEM export setup)

## Customer Responsibility

The deploying agency must:
1. Protect the HMAC signing key Secret in `sidereal-system` from
   unauthorized access using RBAC and KMS envelope encryption (SC-12)
2. Not create exceptions to the append-only admission enforcement policy for
   `SiderealProbeResult` CRs under any circumstances
3. Configure Alertmanager to alert on `SiderealSystemAlert` resources with
   `reason: TamperedResult` and treat these as potential active attack
   indicators requiring immediate IR response
4. Configure S3 object lock in COMPLIANCE mode for the Sidereal SIEM export
   bucket to extend tamper-resistant audit record protection off-cluster
