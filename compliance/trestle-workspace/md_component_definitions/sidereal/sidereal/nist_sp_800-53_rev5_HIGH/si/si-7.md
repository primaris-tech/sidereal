---
x-trestle-comp-def-rules:
  sidereal:
    - name: sidereal-integrity-verification
      description: Sidereal verifies software, firmware, and information integrity through HMAC result signing, cosign image verification, and append-only audit enforcement
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: si-07
status: implemented
---

# SI-7 — Software, Firmware, and Information Integrity

## Control Statement

Employ integrity verification tools to detect unauthorized changes to software,
firmware, and information; and take defined actions when unauthorized changes
are discovered.

## Sidereal Implementation

Sidereal applies integrity verification at three distinct layers: software
(probe images), information in transit (result ConfigMaps), and information
at rest (audit records).

### Layer 1: Software Integrity — Probe Image Signing

All probe runner container images are signed using Sigstore/cosign at build
time in the CI/CD pipeline. An admission enforcement policy shipped with the Helm
chart verifies the cosign signature of every probe image before the Job pod
is admitted to the cluster. Any Job referencing an unsigned or invalidly-signed
image is rejected at admission — it never runs.

This verification is performed by the admission controller independently of the Sidereal
controller. A compromised controller cannot circumvent image integrity
verification.

Image digests are pinned in the Helm chart. Tag-based references are not used,
preventing tag mutation from substituting a different image without detection.

### Layer 2: Information Integrity in Transit — HMAC Result Signing

The controller generates a unique HMAC key per probe execution, injected into
the Job via a Kubernetes Secret. The probe runner signs the result payload
before writing to the result ConfigMap. The controller verifies the signature
before accepting any result.

An invalid or missing signature produces a `TamperedResult` outcome:
- The tampered result is **not** recorded as a legitimate probe outcome
- A `SiderealSystemAlert` is created with `reason: TamperedResult`
- The alert is exported to the SIEM
- Probe execution on the affected surface is suspended until the alert
  is acknowledged by an authorized operator

This ensures that even if the result ConfigMap is modified between the probe
runner writing it and the controller reading it, the tampering is detected and
does not produce a falsified ATO evidence record.

### Layer 3: Information Integrity at Rest — Append-Only Audit Records

`SiderealProbeResult` resources are protected by an admission enforcement policy
that denies UPDATE and DELETE operations for all principals. Once created,
audit records cannot be modified or deleted by any Kubernetes principal,
including cluster-admin. This is enforced at the admission layer, independent
of the controller.

SIEM export targets (S3) are configured with object lock in COMPLIANCE mode,
providing equivalent write-once protection for exported records.

### Enhancement: SI-7(1) — Integrity Checks

Integrity checks are performed:
- On every probe execution (HMAC verification of result ConfigMap)
- On every probe Job admission (cosign verification of image signature)
- Continuously by the append-only admission enforcement policy (at every write attempt)

### Enhancement: SI-7(6) — Cryptographic Protection of Software

Probe images are cryptographically signed using cosign with keys managed
per SC-12 (HSM/KMS-backed, rotation schedule, documented destruction). The
signature verification key is shipped with the Helm chart and verified at
every Job admission.

### Enhancement: SI-7(7) — Integration of Detection and Response

`TamperedResult` outcomes automatically create `SiderealSystemAlert` resources
and export to the SIEM. This directly integrates integrity detection with
the IR response path — no manual triage is required to identify and escalate
an integrity violation.

## Evidence Produced

- Admission enforcement policy for cosign image verification (shipped in Helm chart)
- Admission enforcement policy for append-only SiderealProbeResult (shipped in Helm chart)
- HMAC verification status field in every SiderealProbeResult
- TamperedResult outcome records in SIEM when signature verification fails
- SiderealSystemAlert records for integrity violations
- cosign signatures in image registry (one per probe image per release)

## Customer Responsibility

The deploying agency must:
1. Configure Alertmanager to alert on `TamperedResult` outcomes in SIEM
2. Acknowledge SiderealSystemAlert records created by integrity violations
   and document remediation actions
3. Verify cosign key validity during annual control assessments
4. For air-gapped environments: re-sign mirrored images with a
   registry-specific key and update the admission enforcement policy accordingly
