---
x-trestle-comp-def-rules:
  gauntlet:
    - name: gauntlet-audit-protection
      description: Gauntlet protects audit information from unauthorized access, modification, and deletion through cryptographic and admission enforcement controls
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: au-09
status: implemented
---

# AU-9 — Protection of Audit Information

## Control Statement

Protect audit information and audit tools from unauthorized access, modification, and
deletion; and alert defined personnel in the event of unauthorized access, modification,
or deletion of audit information.

## Gauntlet Implementation

Audit information is protected through a layered set of cryptographic and
admission-layer controls. No single point of failure exists — protections are
applied at creation, storage, and transmission.

### Protection at Creation: HMAC Result Signing

The controller generates a unique per-execution HMAC key before creating each probe
Job. The key is injected into the Job via a Kubernetes Secret volume mount. The probe
runner signs the result payload with this key before writing it to the result ConfigMap.
The controller verifies the HMAC signature before accepting the result. Any result with
an invalid or missing signature produces a `TamperedResult` outcome — it is never
recorded as a legitimate pass or fail. This ensures the integrity of every audit record
from the moment of creation.

### Protection at Storage: Append-Only Enforcement

An admission enforcement policy (e.g., Kyverno ClusterPolicy or OPA Constraint)
shipped with the Helm chart explicitly denies UPDATE and DELETE operations on
`GauntletProbeResult` resources for all principals, including cluster-admin. Only CREATE is permitted. This is enforced at the Kubernetes admission
layer — independent of the Gauntlet controller. A compromised controller cannot
modify or delete audit records.

### Protection at Transmission: Cryptographic Transport

All SIEM export connections use TLS 1.2+ with FIPS-approved cipher suites and
certificate validation. Audit payloads are signed with the Gauntlet signing key before
transmission so the receiving SIEM can independently verify records were not altered
in transit. S3 export targets require SSE-KMS encryption and object lock in COMPLIANCE
mode — records cannot be deleted or overwritten by any principal, including the bucket
owner, for the duration of the object lock period.

### Protection of In-Transit Results: NetworkPolicy Isolation

The `gauntlet-system` NetworkPolicy restricts all egress from probe Jobs. The result
ConfigMap can only be written by the probe runner and read by the controller — no
other principal in the cluster can access the intermediate result store.

### Enhancement: AU-9(2) — Store Audit Records in Separate Physical Systems

In-cluster `GauntletProbeResult` records and SIEM-exported records are maintained
independently. SIEM failure does not affect in-cluster record integrity; cluster
compromise does not affect SIEM records.

### Enhancement: AU-9(3) — Cryptographic Protection

All audit record transmission uses TLS 1.2+ with FIPS-approved cipher suites.
Payload signing with the Gauntlet signing key (HSM/KMS-backed, SC-12) provides
cryptographic protection of records in transit.

### Enhancement: AU-9(4) — Access by Subset of Privileged Users

The `gauntlet-audit-admin` role provides read-only access to `GauntletProbeResult`
resources. This role is separate from cluster-admin. The admission enforcement append-only policy
applies to all principals regardless of role — cluster-admin cannot delete or modify
audit records. Per AU-9(4), the audit administrator and system administrator roles
must be held by separate individuals, enforced administratively by the ISSO.

## Evidence Produced

- Admission enforcement policy denying UPDATE/DELETE on GauntletProbeResult (shipped in Helm chart)
- HMAC verification status field in every GauntletProbeResult record
- TamperedResult outcome records when signature verification fails
- TLS configuration for all SIEM export connections (Helm values schema)
- S3 object lock configuration documentation

## Customer Responsibility

The deploying agency must:
1. Assign the `gauntlet-audit-admin` and cluster-admin roles to separate individuals per AU-9(4)
2. Configure their SIEM to verify Gauntlet payload signatures on ingest
3. Configure S3 bucket object lock if using S3 as the SIEM export target
4. Alert on `TamperedResult` outcomes, which indicate attempted audit record manipulation
