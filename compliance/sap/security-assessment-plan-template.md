# Security Assessment Plan (SAP) Template
## Sidereal Continuous Security Control Validation Operator

**Classification**: [Agency: Insert applicable classification marking]
**Version**: 1.0
**Date**: [Agency: Insert date]
**Status**: [Draft / Final]
**Assessment Type**: [Annual Assessment / Significant Change Assessment / Initial Authorization]

> **How to use this template**: This SAP contains two types of content:
>
> 1. **Pre-written test procedures** — documented by the Sidereal team; describe how to
>    execute and interpret each test. Do not alter these procedures without consulting your
>    Sidereal representative, as changes may invalidate the OSCAL Component Definition mapping.
>
> 2. **Agency fill-in sections** — marked `[Agency: ...]`; require assessor-specific input
>    (schedule, team, environment details, actual results, findings).
>
> **Key concept**: Sidereal generates continuous assessment evidence automatically.
> For controls covered by Sidereal probes, the assessor's primary task is to
> **verify that Sidereal is operating correctly** and **review the probe result record**
> for the assessment period — not to re-execute the same tests manually.
> Section 4 defines this evidence review methodology.

---

## Table of Contents

1. [Assessment Overview](#1-assessment-overview)
2. [Assessment Team](#2-assessment-team)
3. [Assessment Scope and Boundaries](#3-assessment-scope-and-boundaries)
4. [Evidence Review Methodology](#4-evidence-review-methodology)
5. [Test Procedures — Sidereal System Integrity](#5-test-procedures--sidereal-system-integrity)
6. [Test Procedures — Access Control (AC)](#6-test-procedures--access-control-ac)
7. [Test Procedures — Audit and Accountability (AU)](#7-test-procedures--audit-and-accountability-au)
8. [Test Procedures — Configuration Management (CM)](#8-test-procedures--configuration-management-cm)
9. [Test Procedures — Identification and Authentication (IA)](#9-test-procedures--identification-and-authentication-ia)
10. [Test Procedures — Security Assessment and Authorization (CA)](#10-test-procedures--security-assessment-and-authorization-ca)
11. [Test Procedures — System and Communications Protection (SC)](#11-test-procedures--system-and-communications-protection-sc)
12. [Test Procedures — System and Information Integrity (SI)](#12-test-procedures--system-and-information-integrity-si)
13. [Test Procedures — Supply Chain Risk Management (SR)](#13-test-procedures--supply-chain-risk-management-sr)
14. [Assessment Schedule](#14-assessment-schedule)
15. [Findings Summary](#15-findings-summary)
16. [Approvals and Signatures](#16-approvals-and-signatures)
17. [Appendix A — Evidence Collection Commands](#appendix-a--evidence-collection-commands)
18. [Appendix B — Finding Template](#appendix-b--finding-template)

---

## 1. Assessment Overview

### 1.1 Purpose

This Security Assessment Plan defines the test procedures, schedule, and methodology for
assessing the security controls implemented by the Sidereal Continuous Security Control
Validation Operator. The assessment supports the [Agency: insert assessment type and
associated authorization package].

### 1.2 System Under Assessment

| Field | Value |
|---|---|
| System Name | Sidereal Continuous Security Control Validation Operator |
| Helm Chart Version | [Agency: Insert deployed version, e.g., `sidereal-1.2.0`] |
| Assessment Period | [Agency: Insert start date] through [Agency: Insert end date] |
| Target Environment | [Agency: Insert cluster name / environment] |
| Associated SSP | `compliance/ssp/system-security-plan-template.md` |
| OSCAL Component Definition | `compliance/trestle-workspace/component-definitions/sidereal/component-definition.json` |

### 1.3 Assessment Basis

This assessment uses:
- **NIST SP 800-53A Rev 5** — assessment procedures for the High baseline
- **NIST SP 800-53 Rev 5** — control requirement definitions
- **Sidereal OSCAL Component Definition** — authoritative source of control implementations

### 1.4 Prior Assessment Findings

[Agency: List any open findings from prior assessments that this assessment should revisit,
with references to their POA&M entries and the `SiderealIncident` CRs that documented them.]

| POA&M Item | Control | Description | Status |
|---|---|---|---|
| [Agency: ID] | [Agency: Control] | [Agency: Description] | [Agency: Open/Closed] |

---

## 2. Assessment Team

### 2.1 Lead Assessor

| Field | Value |
|---|---|
| Name | [Agency: Insert name] |
| Organization | [Agency: Insert organization] |
| Certification(s) | [Agency: CISSP / CAP / etc.] |
| Independence | [Agency: Document independence from Sidereal deployment team] |
| Phone | [Agency: Insert phone] |
| Email | [Agency: Insert email] |

### 2.2 Assessment Team Members

| Name | Role | Organization | Responsibilities |
|---|---|---|---|
| [Agency: Name] | Technical Assessor | [Agency: Org] | Probe surface testing |
| [Agency: Name] | Crypto Assessor | [Agency: Org] | FIPS validation, key management |
| [Agency: Name] | Supply Chain Assessor | [Agency: Org] | Image signature verification |
| [Agency: Name] | ISSO Support | [Agency: Org] | Evidence coordination |

### 2.3 Assessor Independence Statement

[Agency: Document how the assessment team is independent of the personnel who operate
Sidereal. Per CA-2(1), assessors must be independent of the system they are assessing.
For Sidereal, this means the assessment team must be independent of the team that deployed
and configured the Sidereal Helm chart and the team that created the SiderealProbe resources.]

---

## 3. Assessment Scope and Boundaries

### 3.1 Controls In Scope

The following controls are within scope for this assessment. All are implemented by Sidereal
as documented in the OSCAL Component Definition.

| Control | Title | Test Sections |
|---|---|---|
| AC-3 | Access Enforcement | §6.1 |
| AC-3(2) | Access Enforcement — Dual Authorization | §6.2 |
| AC-3(7) | Access Enforcement — Role-Based Access Control | §6.3 |
| AC-4 | Information Flow Enforcement | §6.4 |
| AC-4(12) | Information Flow Enforcement — Data Flow Usage Evidence | §6.5 |
| AC-6 | Least Privilege | §6.6 |
| AC-6(9) | Least Privilege — Log Use of Privileged Functions | §6.7 |
| AC-12 | Session Termination | §6.8 |
| AU-2 | Event Logging | §7.1 |
| AU-3 | Content of Audit Records | §7.2 |
| AU-4 | Audit Log Storage Capacity | §7.3 |
| AU-5 | Response to Audit Processing Failures | §7.4 |
| AU-8 | Time Stamps | §7.5 |
| AU-9 | Protection of Audit Information | §7.6 |
| AU-10 | Non-Repudiation | §7.7 |
| AU-11 | Audit Record Retention | §7.8 |
| AU-12 | Audit Record Generation | §7.9 |
| CA-2 | Control Assessments | §10.1 |
| CA-7 | Continuous Monitoring | §10.2 |
| CA-8 | Penetration Testing | §10.3 |
| CM-2 | Baseline Configuration | §8.1 |
| CM-3 | Configuration Change Control | §8.2 |
| CM-6 | Configuration Settings | §8.3 |
| CM-7 | Least Functionality | §8.4 |
| CM-8 | System Component Inventory | §8.5 |
| CM-14 | Signed Components | §8.6 |
| IA-3 | Device Identification and Authentication | §9.1 |
| IA-7 | Cryptographic Module Authentication | §9.2 |
| IA-8 | Identification and Authentication (Non-Org Users) | §9.3 |
| SC-7 | Boundary Protection | §11.1 |
| SC-8 | Transmission Confidentiality and Integrity | §11.2 |
| SC-12 | Cryptographic Key Establishment and Management | §11.3 |
| SC-13 | Cryptographic Protection | §11.4 |
| SI-2 | Flaw Remediation | §12.1 |
| SI-6 | Security and Privacy Function Verification | §12.2 |
| SI-14 | Non-Persistence | §12.3 |
| SR-3 | Supply Chain Controls and Plans | §13.1 |
| SR-4 | Provenance | §13.2 |
| SR-9 | Tamper Resistance and Detection | §13.3 |
| SR-11 | Component Authenticity | §13.4 |

### 3.2 Controls Out of Scope

The following control families are inherited from the underlying Kubernetes infrastructure
and are assessed as part of the cluster ATO, not this assessment:

- Physical and Environmental Protection (PE)
- Personnel Security (PS)
- Media Protection (MP)
- Contingency Planning (CP) — assessed at the cluster level; see `compliance/plans/contingency-plan.md` for Sidereal-specific procedures

### 3.3 Assessment Environment

[Agency: Document the specific cluster and namespace where testing will be performed.
Confirm that testing will be performed in an environment representative of production,
or document the differences and their impact on assessment validity.]

| Item | Value |
|---|---|
| Cluster | [Agency: Cluster name] |
| Kubernetes version | [Agency: Version] |
| Sidereal namespace | `sidereal-system` |
| CNI in use | [Agency: Cilium / Calico / other] |
| Detection backends | [Agency: detection backend in use, e.g., Falco / Tetragon / none] |
| SIEM target(s) | [Agency: Splunk / Elasticsearch / S3] |
| SIEM export format | [Agency: JSON / CEF / LEEF / Syslog / OCSF] |
| Impact level (`global.impactLevel`) | [Agency: low / moderate / high] |

---

## 4. Evidence Review Methodology

### 4.1 Two-Track Assessment Approach

This assessment uses a two-track approach:

**Track 1 — Sidereal System Integrity** (Section 5): The assessor verifies that Sidereal
itself is operating correctly, its controls are implemented as described, and its output
is trustworthy. This track uses traditional examiner/interview/test methods against Sidereal's
own components.

**Track 2 — Continuous Evidence Review** (Sections 6–13): For controls covered by Sidereal
probes, the assessor reviews the accumulated probe result record rather than re-executing
the same tests manually. The assessor verifies the evidence is complete, unbroken, and
shows no failures during the assessment period.

Track 2 is valid only if Track 1 confirms Sidereal's integrity. If Track 1 produces any
findings, Track 2 evidence for controls tested by the affected probe surface must be
treated as unconfirmed until Sidereal's integrity is restored and re-verified.

### 4.2 Track 2 Evidence Review Procedure

For each control tested by Sidereal probes, the assessor executes this standard procedure:

**Step 1 — Retrieve probe results for the assessment period:**

```bash
kubectl get siderealproberesults -n sidereal-system \
  --field-selector='spec.probe.type=<PROBE_TYPE>' \
  -o json \
  | jq '[.items[] | select(.spec.execution.timestamp >= "<START_DATE>")]
         | sort_by(.spec.execution.timestamp)'
```

**Step 2 — Check for any Failure or Undetected outcomes:**

```bash
kubectl get siderealproberesults -n sidereal-system -o json \
  | jq '[.items[] | select(.spec.result.outcome != "Pass" and
                            .spec.result.outcome != "Blocked")] | length'
```

A count of `0` indicates no failures during the period. Any non-zero count requires
investigation of the corresponding `SiderealIncident` CRs.

**Step 2a — Check for any non-Effective control effectiveness assessments:**

```bash
kubectl get siderealproberesults -n sidereal-system -o json \
  | jq '[.items[] | select(.spec.result.controlEffectiveness != "Effective")] | length'
```

A count of `0` indicates all controls were assessed as Effective during the period.
Any `Ineffective`, `Degraded`, or `Compromised` results require investigation.

**Step 3 — Verify HMAC integrity status:**

```bash
kubectl get siderealproberesults -n sidereal-system -o json \
  | jq '[.items[] | select(.spec.result.integrityStatus != "Verified")] | length'
```

A count of `0` indicates no tamper events. Any `TamperedResult` records are an immediate
significant finding.

**Step 4 — Verify SIEM export status:**

```bash
kubectl get siderealproberesults -n sidereal-system -o json \
  | jq '[.items[] | select(.spec.audit.exportStatus == "Failed")] | length'
```

A count of `0` indicates all records reached the SIEM. Any `Failed` records require
investigation.

**Step 5 — Verify coverage gap (no scheduling gaps > 2× interval):**

```bash
kubectl get siderealproberesults -n sidereal-system \
  --field-selector='spec.probe.type=<PROBE_TYPE>' \
  -o json \
  | jq '[.items | sort_by(.spec.execution.timestamp) | to_entries[]
         | .value.spec.execution.timestamp] | @sh' \
  | xargs -n2 bash -c 'echo "Gap between $1 and $2"'
```

[Agency: Calculate expected probe interval from Helm values. Any gap exceeding
2× the configured interval is a finding — the probe was not executing continuously.]

**Step 6 — Verify SIEM export format:**

```bash
helm get values sidereal -n sidereal-system | grep -A5 'siem\|export'
```

Confirm the configured export format (JSON, CEF, LEEF, Syslog, or OCSF) matches the
agency's SIEM ingestion requirements.

**Step 7 — Cross-reference with SIEM:**

Pull the same date range from the SIEM and confirm the record counts match the
in-cluster `SiderealProbeResult` count. A mismatch indicates an export or retention gap.

### 4.3 Evidence Rating Scale

For each control, the assessor assigns one of the following ratings after completing the
Track 2 review:

| Rating | Criteria |
|---|---|
| **Satisfied** | Zero probe failures during assessment period; all `controlEffectiveness` values `Effective`; all records HMAC-verified; SIEM export complete; no coverage gaps |
| **Other Than Satisfied — Low** | 1–2 probe failures or `Degraded` effectiveness assessments; all remediated within SLA; root cause documented |
| **Other Than Satisfied — Moderate** | 3+ probe failures; OR any `Ineffective` effectiveness assessment; OR any failure not remediated within SLA; OR coverage gap ≤ 48 hours |
| **Other Than Satisfied — High** | Any `TamperedResult` record; OR any `Compromised` effectiveness assessment; OR coverage gap > 48 hours; OR SIEM export failures with no recovery |

---

## 5. Test Procedures — Sidereal System Integrity

These tests verify Sidereal's own controls. They must be completed before Track 2 evidence
reviews begin.

---

### TEST-SYS-01 — Image Signature Verification (CM-14, SR-11)

**Objective**: Confirm that all running Sidereal containers were admitted through admission
enforcement policy cosign signature verification and that their digests match the signed images.

**Method**: Test

**Procedure**:

1. List all running Sidereal pods and their image digests:

```bash
kubectl get pods -n sidereal-system -o json \
  | jq '.items[].spec.containers[].image'
```

2. For each image digest, verify the cosign signature:

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/primaris-tech/sidereal' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  <image>@<digest>
```

3. Confirm the admission enforcement policy is active:

```bash
kubectl get clusterpolicy sidereal-image-signature-required -o yaml \
  | grep 'validationFailureAction'
```

> *Command shown for default profile. See deployment profile binding document for alternative commands.*

Expected: `validationFailureAction: Enforce` (not `Audit`)

4. Attempt to create a Pod with an unsigned image; confirm the admission controller blocks it:

```bash
kubectl run test-unsigned \
  --image=nginx:latest \
  --overrides='{"metadata":{"namespace":"sidereal-system"}}' \
  --dry-run=server 2>&1
```

Expected: admission webhook error citing signature requirement.

**Pass Criteria**: All running images have valid cosign signatures. Admission enforcement policy is in
Enforce mode. Unsigned image creation is blocked.

**Result**: [ ] Pass  [ ] Fail  [ ] Not Tested

**Assessor Notes**: [Agency: Record observations, evidence artifact IDs, and any deviations]

---

### TEST-SYS-02 — HMAC Result Integrity Chain (AU-9, SR-9)

**Objective**: Confirm that the HMAC result integrity mechanism is active and that any
tamper event would be detected and flagged.

**Method**: Test + Examine

**Procedure**:

1. Confirm no `TamperedResult` records exist:

```bash
kubectl get siderealproberesults -n sidereal-system -o json \
  | jq '[.items[] | select(.spec.result.integrityStatus == "TamperedResult")]'
```

Expected: empty array `[]`

2. Retrieve a recent `SiderealProbeResult` and confirm `integrityStatus: Verified` is present:

```bash
kubectl get siderealproberesults -n sidereal-system \
  --sort-by=.metadata.creationTimestamp -o yaml \
  | tail -50
```

Expected: `integrityStatus: Verified` in the most recent result.

3. Confirm the HMAC root Secret exists and is accessible only to the controller SA:

```bash
kubectl get secret sidereal-hmac-root -n sidereal-system -o yaml \
  | grep 'annotations\|labels'
kubectl get rolebinding -n sidereal-system -o yaml \
  | grep -A5 'sidereal-hmac'
```

4. Attempt to modify a `SiderealProbeResult` directly; confirm the admission controller blocks it:

```bash
RESULT=$(kubectl get siderealproberesults -n sidereal-system -o name | head -1)
kubectl patch $RESULT -n sidereal-system \
  --type='merge' \
  -p '{"spec":{"result":{"outcome":"Pass"}}}' \
  --dry-run=server 2>&1
```

Expected: admission webhook error citing append-only policy.

**Pass Criteria**: No `TamperedResult` records. Recent results show `Verified`. HMAC Secret
access is restricted. Modification of ProbeResult records is blocked by admission enforcement policy.

**Result**: [ ] Pass  [ ] Fail  [ ] Not Tested

**Assessor Notes**: [Agency: Record observations]

---

### TEST-SYS-03 — Append-Only Enforcement (AU-9, AU-10)

**Objective**: Confirm that `SiderealProbeResult` and `SiderealIncident` CRs cannot be
deleted or modified after creation.

**Method**: Test

**Procedure**:

1. Confirm the admission enforcement policy for append-only is in Enforce mode:

```bash
kubectl get clusterpolicy sidereal-proberesult-immutable -o yaml \
  | grep 'validationFailureAction'
```

> *Command shown for default profile. See deployment profile binding document for alternative commands.*

Expected: `validationFailureAction: Enforce`

2. Attempt to delete a `SiderealProbeResult` and confirm it is blocked:

```bash
RESULT=$(kubectl get siderealproberesults -n sidereal-system -o name | head -1)
kubectl delete $RESULT -n sidereal-system --dry-run=server 2>&1
```

Expected: admission webhook error.

3. Attempt to patch a `SiderealIncident` and confirm it is blocked:

```bash
INCIDENT=$(kubectl get siderealincidents -n sidereal-system -o name | head -1)
if [ -n "$INCIDENT" ]; then
  kubectl patch $INCIDENT -n sidereal-system \
    --type='merge' -p '{"spec":{"outcome":"Pass"}}' \
    --dry-run=server 2>&1
fi
```

Expected: admission webhook error (if any incidents exist).

**Pass Criteria**: Delete and modify operations on audit records are blocked by admission
enforcement policy in Enforce mode.

**Result**: [ ] Pass  [ ] Fail  [ ] Not Tested

**Assessor Notes**: [Agency: Record observations]

---

### TEST-SYS-04 — NetworkPolicy Default-Deny Enforcement (SC-7)

**Objective**: Confirm that the `sidereal-system` namespace has a default-deny
NetworkPolicy and that non-permitted traffic is blocked.

**Method**: Test + Examine

**Procedure**:

1. Confirm the NetworkPolicy exists:

```bash
kubectl get networkpolicy -n sidereal-system -o yaml
```

Expected: at least one policy with `podSelector: {}` (applies to all pods) and either
empty `ingress`/`egress` arrays (deny all) or explicit allow rules matching the topology
diagram.

2. Verify no unexpected egress is permitted by reviewing the policy spec:

```bash
kubectl get networkpolicy -n sidereal-system -o json \
  | jq '.items[].spec.egress[].ports'
```

Expected: only ports 443, 50051, 54321, 4245, 5443, and 8443 appear (matching
`compliance/diagrams/network-topology.md`).

3. Review the NetworkPolicy probe's most recent result to confirm self-validation is active:

```bash
kubectl get siderealproberesults -n sidereal-system \
  --field-selector='spec.probe.type=netpol' \
  --sort-by=.metadata.creationTimestamp -o yaml \
  | tail -30
```

Expected: `outcome: Pass` and `integrityStatus: Verified` in the most recent result.

**Pass Criteria**: Default-deny NetworkPolicy is present. Permitted egress ports match
the topology specification. NetworkPolicy probe is passing.

**Result**: [ ] Pass  [ ] Fail  [ ] Not Tested

**Assessor Notes**: [Agency: Record observations]

---

### TEST-SYS-05 — Probe Job Security Posture (SI-14, CM-7)

**Objective**: Confirm that probe runner Jobs are ephemeral, non-root, read-only,
capability-dropped, and cleaned up after execution.

**Method**: Examine + Interview

**Procedure**:

1. Review the security context of a recently completed Job's pod spec (or the Job template):

```bash
kubectl get jobs -n sidereal-system -o json \
  | jq '.items[0].spec.template.spec.containers[0].securityContext'
```

Expected: `runAsNonRoot: true`, `readOnlyRootFilesystem: true`,
`capabilities.drop: ["ALL"]`

2. Confirm probe Jobs are cleaned up by TTL controller:

```bash
kubectl get jobs -n sidereal-system \
  -o custom-columns='NAME:.metadata.name,AGE:.metadata.creationTimestamp,TTL:.spec.ttlSecondsAfterFinished'
```

Expected: `ttlSecondsAfterFinished` is set (not null) on all Jobs.

3. Confirm no PersistentVolumeClaim exists in `sidereal-system`:

```bash
kubectl get pvc -n sidereal-system
```

Expected: `No resources found`

4. Confirm the admission enforcement policy for no-PVC is in Enforce mode:

```bash
kubectl get clusterpolicy sidereal-no-writable-pvc -o yaml \
  | grep 'validationFailureAction'
```

> *Command shown for default profile. See deployment profile binding document for alternative commands.*

Expected: `validationFailureAction: Enforce`

5. Confirm probe Jobs use the expected pre-provisioned ServiceAccounts only:

```bash
kubectl get jobs -n sidereal-system -o json \
  | jq '.items[].spec.template.spec.serviceAccountName' | sort -u
```

Expected: only `sidereal-probe-rbac`, `sidereal-probe-netpol`, `sidereal-probe-admission`,
`sidereal-probe-secret`, `sidereal-probe-detection`, `sidereal-probe-discovery` (not `sidereal-controller` or `default`).

**Pass Criteria**: All Jobs run non-root, read-only, all-caps-dropped. TTL cleanup is configured.
No PVCs exist. Admission enforcement PVC policy enforces. Only pre-approved probe SAs are used.

**Result**: [ ] Pass  [ ] Fail  [ ] Not Tested

**Assessor Notes**: [Agency: Record observations]

---

### TEST-SYS-06 — FIPS Cryptographic Module (SC-13, IA-7)

**Objective**: Confirm that FIPS image variants are deployed and that non-FIPS codepaths
cannot be reached at runtime.

**Method**: Examine + Test

**Procedure**:

1. Confirm deployed images carry the FIPS image digest (not the standard variant):

```bash
kubectl get pods -n sidereal-system -o json \
  | jq '.items[].spec.containers[].image'
```

Compare each digest against the FIPS variant digests published in the Sidereal release manifest.

2. Confirm `global.fips: true` is set in the deployed Helm values:

```bash
helm get values sidereal -n sidereal-system | grep fips
```

Expected: `fips: true`

3. Confirm the controller log does not contain any non-FIPS cipher suite negotiation events:

```bash
kubectl logs deployment/sidereal-controller -n sidereal-system \
  | grep -i 'cipher\|tls\|fips' | head -20
```

Expected: only FIPS-approved cipher suite names (e.g., `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`);
no non-FIPS cipher suite names.

4. [Agency: If a FIPS compliance scanner is available, run it against the controller pod's process memory.]

**Pass Criteria**: FIPS image digests match published FIPS variant digests. `global.fips: true`
is set. No non-FIPS cipher suite negotiation is logged.

**Result**: [ ] Pass  [ ] Fail  [ ] Not Tested

**Assessor Notes**: [Agency: Record observations and FIPS scanner output if applicable]

---

### TEST-SYS-07 — Controller / Probe Identity Separation (AC-6, AC-3)

**Objective**: Confirm that the controller SA cannot perform probe operations and that probe
SAs cannot write CRDs.

**Method**: Test

**Procedure**:

1. Confirm the admission enforcement policy for Job constraints is in Enforce mode:

```bash
kubectl get clusterpolicy sidereal-job-constraints -o yaml \
  | grep 'validationFailureAction'
```

> *Command shown for default profile. See deployment profile binding document for alternative commands.*

Expected: `validationFailureAction: Enforce`

2. Confirm that each probe SA lacks CRD write permissions:

```bash
for SA in rbac netpol admission secret detection discovery; do
  echo "=== sidereal-probe-$SA ==="
  kubectl auth can-i create siderealproberesults \
    --as=system:serviceaccount:sidereal-system:sidereal-probe-$SA \
    -n sidereal-system
done
```

Expected: `no` for all probe SAs.

3. Confirm the controller SA cannot perform RBAC test operations in target namespaces:

```bash
kubectl auth can-i get secrets \
  --as=system:serviceaccount:sidereal-system:sidereal-controller \
  -n [Agency: target namespace]
```

Expected: `no`

4. Attempt to create a Job using the controller SA that references a non-probe SA
   (confirm the admission controller blocks it):

```bash
kubectl create job test-escalation \
  --image=nginx:latest \
  --overrides='{"spec":{"template":{"spec":{"serviceAccountName":"sidereal-controller"}}}}' \
  -n sidereal-system \
  --dry-run=server 2>&1
```

Expected: admission webhook error blocking the non-approved SA reference.

**Pass Criteria**: All probe SAs cannot create CRDs. Controller SA cannot perform probe operations.
Admission controller blocks Job creation with unapproved SAs.

**Result**: [ ] Pass  [ ] Fail  [ ] Not Tested

**Assessor Notes**: [Agency: Record observations]

---

### TEST-SYS-08 — Bootstrap Verification and Alert Generation (SI-6, AU-5)

**Objective**: Confirm that Sidereal's bootstrap verifier is active and that degraded-state
conditions generate `SiderealSystemAlert` CRs.

**Method**: Examine + Interview

**Procedure**:

1. Confirm no open `SiderealSystemAlert` CRs exist (or review any that do):

```bash
kubectl get siderealsystemalerts -n sidereal-system -o yaml
```

Expected: no unacknowledged alerts; if alerts exist, review and document.

2. Review controller logs for bootstrap verification messages:

```bash
kubectl logs deployment/sidereal-controller -n sidereal-system \
  | grep -i 'bootstrap\|prerequisite\|verify' | head -20
```

Expected: bootstrap verification completion messages with no failures logged.

3. Interview the ISSO or operations team:
   - How are `SiderealSystemAlert` CRs monitored?
   - What is the alert acknowledgment procedure?
   - Has any alert been received and acknowledged in the past 12 months?

[Agency: Document interview responses]

**Pass Criteria**: No unacknowledged `SiderealSystemAlert` CRs. Bootstrap verification completes
without errors in controller logs. Monitoring and acknowledgment procedure is documented and known
to operations staff.

**Result**: [ ] Pass  [ ] Fail  [ ] Not Tested

**Assessor Notes**: [Agency: Record observations and interview notes]

---

## 6. Test Procedures — Access Control (AC)

---

### TEST-AC-01 — RBAC Probe Effectiveness: Deny-Path Verification (AC-3)

**Control**: AC-3, AC-3(7)
**Track**: Track 2 (Evidence Review)

**Objective**: Confirm that Sidereal's RBAC probe is continuously verifying that unauthorized
operations are denied by Kubernetes RBAC in the target namespace(s).

**Procedure**: Execute the Track 2 evidence review (§4.2) for `spec.probe.type=rbac`.

Additionally, examine one recent probe result in detail:

```bash
kubectl get siderealproberesults -n sidereal-system \
  --field-selector='spec.probe.type=rbac' \
  --sort-by=.metadata.creationTimestamp \
  -o yaml | tail -60
```

Confirm the result contains:
- `result.outcome: Pass`
- `result.controlEffectiveness: Effective`
- `result.controlMappings` includes NIST 800-53 `AC-3` (and any additional framework mappings)
- `result.nistControls` includes `AC-3`
- `result.integrityStatus: Verified`
- `audit.exportStatus: Exported`

**Pass Criteria**: No probe failures during assessment period. All records HMAC-verified.
SIEM export complete. No coverage gaps exceeding 2× configured interval.

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Finding Reference**: [Agency: POA&M item if not Satisfied]

**Assessor Notes**: [Agency: Record evidence artifact IDs and observations]

---

### TEST-AC-02 — Secret Access Probe: Cross-Namespace Isolation (AC-3, AC-6)

**Control**: AC-3, AC-6
**Track**: Track 2 (Evidence Review)

**Objective**: Confirm that the Secret Access probe continuously verifies that cross-namespace
Secret access is denied.

**Procedure**: Execute the Track 2 evidence review (§4.2) for `spec.probe.type=secret`.

Examine one recent probe result:

```bash
kubectl get siderealproberesults -n sidereal-system \
  --field-selector='spec.probe.type=secret' \
  --sort-by=.metadata.creationTimestamp \
  -o yaml | tail -60
```

Confirm: `result.outcome: Pass` and that the probe tested cross-namespace access
(i.e., `probe.targetNamespace` is different from `sidereal-system`).

**Pass Criteria**: No probe failures during assessment period. All cross-namespace Secret access
attempts returned 403 as expected. SIEM export complete.

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Finding Reference**: [Agency: POA&M item if not Satisfied]

**Assessor Notes**: [Agency: Record evidence artifact IDs]

---

### TEST-AC-03 — NetworkPolicy Probe: Information Flow Enforcement (AC-4, SC-7)

**Control**: AC-4, AC-4(12), SC-7
**Track**: Track 2 (Evidence Review)

**Objective**: Confirm that the NetworkPolicy probe continuously verifies CNI enforcement
of traffic flow rules, reading verdicts from the authoritative CNI observability layer.

**Procedure**: Execute the Track 2 evidence review (§4.2) for `spec.probe.type=netpol`.

Examine one recent probe result and confirm it includes CNI verdict metadata:

```bash
kubectl get siderealproberesults -n sidereal-system \
  --field-selector='spec.probe.type=netpol' \
  --sort-by=.metadata.creationTimestamp \
  -o yaml | tail -60
```

Confirm:
- `result.outcome: Pass` for all deny-path tests (Forwarded where Dropped expected = Fail)
- `result.controlEffectiveness: Effective`
- `result.controlMappings` includes NIST 800-53 `AC-4` (and any additional framework mappings)
- `result.nistControls` includes `AC-4`
- CNI verdict source is documented in the result (CNI observability backend, e.g., Hubble or Calico)

**Pass Criteria**: No probe failures during assessment period. All denied-flow tests returned
`Dropped` verdicts. Allow-path tests returned `Forwarded` verdicts.

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Finding Reference**: [Agency: POA&M item if not Satisfied]

**Assessor Notes**: [Agency: Record evidence artifact IDs]

---

### TEST-AC-04 — Admission Control Probe: Policy Enforcement (CM-7)

**Control**: CM-7, AC-3
**Track**: Track 2 (Evidence Review)

**Objective**: Confirm that the Admission Control probe continuously verifies that the
admission controller (e.g., Kyverno or OPA/Gatekeeper) rejects non-compliant workloads.

**Procedure**: Execute the Track 2 evidence review (§4.2) for `spec.probe.type=admission`.

**Pass Criteria**: No probe failures during assessment period. All non-compliant resource
creation attempts were rejected by admission webhook.

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Finding Reference**: [Agency: POA&M item if not Satisfied]

**Assessor Notes**: [Agency: Record evidence artifact IDs]

---

### TEST-AC-05 — Session Termination: Token Expiry Enforcement (AC-12)

**Control**: AC-12
**Track**: Track 2 (Evidence Review) + Test

**Objective**: Confirm that probe runner tokens are time-bound and that the Secret Access
probe verifies expired token rejection.

**Procedure**:

1. Execute the Track 2 evidence review for `spec.probe.type=secret`, specifically
   examining whether expired-token rejection tests are included in the probe output.

2. Confirm token expiry setting in probe Job templates:

```bash
kubectl get jobs -n sidereal-system -o json \
  | jq '.items[0].spec.template.spec.volumes[]
        | select(.projected != null)
        | .projected.sources[]
        | select(.serviceAccountToken != null)
        | .serviceAccountToken.expirationSeconds'
```

Expected: `3600` (1 hour maximum).

**Pass Criteria**: Token `expirationSeconds` is 3600 or less. Secret Access probe confirms
expired token rejection. No probe failures.

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Assessor Notes**: [Agency: Record observations]

---

## 7. Test Procedures — Audit and Accountability (AU)

---

### TEST-AU-01 — Audit Record Content and Generation (AU-2, AU-3, AU-12)

**Control**: AU-2, AU-3, AU-12
**Track**: Track 1 (Direct Examination)

**Objective**: Confirm that `SiderealProbeResult` records contain all required AU-3 fields.

**Procedure**:

1. Retrieve a representative sample of recent probe results across all probe types:

```bash
for TYPE in rbac netpol admission secret detection discovery; do
  echo "=== $TYPE ==="
  kubectl get siderealproberesults -n sidereal-system \
    --field-selector="spec.probe.type=$TYPE" \
    --sort-by=.metadata.creationTimestamp \
    -o json | jq '.items[-1]'
done
```

2. For each result, verify the following fields are present and populated:

| Field | Required Value |
|---|---|
| `spec.probe.id` | UUID (not empty) |
| `spec.probe.type` | One of the five built-in probe types (or a custom probe type) |
| `spec.probe.targetNamespace` | Non-empty string |
| `spec.result.outcome` | Valid outcome value |
| `spec.result.controlEffectiveness` | `Effective`, `Ineffective`, `Degraded`, or `Compromised` |
| `spec.result.controlMappings` | Non-empty array (multi-framework mappings) |
| `spec.result.nistControls` | Non-empty array |
| `spec.result.integrityStatus` | `Verified` or `TamperedResult` |
| `spec.execution.timestamp` | RFC 3339 UTC format |
| `spec.audit.exportStatus` | `Exported`, `Pending`, or `Failed` |

**Pass Criteria**: All ten required fields are present and populated in a sample of
at least 5 results per probe type.

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Assessor Notes**: [Agency: Record sample size and any missing fields]

---

### TEST-AU-02 — Audit Log Storage Capacity (AU-4)

**Control**: AU-4
**Track**: Track 1 (Direct Examination) + Interview

**Objective**: Confirm that two-tier storage prevents audit capacity exhaustion and
that SIEM export is delivering records off-cluster.

**Procedure**:

1. Confirm 365-day TTL is set on `SiderealProbeResult` CRs:

```bash
kubectl get siderealproberesults -n sidereal-system -o json \
  | jq '.items[0].metadata.annotations["kubectl.kubernetes.io/ttl"]'
```

2. Confirm SIEM export is delivering records by checking that `exportStatus: Exported`
   is set on recent results:

```bash
kubectl get siderealproberesults -n sidereal-system -o json \
  | jq '[.items[-10:][].spec.audit.exportStatus] | group_by(.) | map({(.[0]): length})'
```

Expected: all recent records show `Exported`.

3. Interview the ISSO: What is the SIEM storage capacity? Is it sized for 3-year retention?

[Agency: Document SIEM storage sizing and capacity utilization]

4. If using S3: Confirm Object Lock COMPLIANCE mode is configured:

```bash
aws s3api get-object-lock-configuration \
  --bucket [Agency: S3 bucket name]
```

Expected: `ObjectLockEnabled: Enabled` and `Mode: COMPLIANCE` with retention ≥ 3 years.

**Pass Criteria**: 365-day TTL is set. SIEM export shows `Exported` for recent records.
SIEM storage is sized for 3-year retention. S3 Object Lock is in COMPLIANCE mode (if applicable).

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Assessor Notes**: [Agency: Record observations]

---

### TEST-AU-03 — Response to Audit Processing Failures (AU-5)

**Control**: AU-5
**Track**: Track 1 (Direct Examination) + Interview

**Objective**: Confirm that SIEM export failures generate `SiderealSystemAlert` CRs and
that fail-closed posture is configured if required.

**Procedure**:

1. Confirm no `SiderealSystemAlert` records with `reason: SIEMExportDegraded` are open:

```bash
kubectl get siderealsystemalerts -n sidereal-system -o json \
  | jq '.items[] | select(.spec.reason == "SIEMExportDegraded")'
```

2. Confirm Prometheus metric is exposed:

```bash
kubectl port-forward deployment/sidereal-controller 8080:8080 -n sidereal-system &
curl -s http://localhost:8080/metrics | grep 'sidereal_siem_export_failures_total'
```

Expected: metric is present (value of 0 indicates no failures since last restart).

3. Confirm `failClosedOnExportFailure` setting:

```bash
helm get values sidereal -n sidereal-system | grep failClosed
```

For High baseline systems, expected: `failClosedOnExportFailure: true`

4. Interview ISSO: Is there an alert rule configured for `sidereal_siem_export_failures_total > 0`?

[Agency: Document alert rule configuration]

**Pass Criteria**: No open export failure alerts. Prometheus metric is present. Fail-closed
setting matches documented agency decision. Alert rule is configured.

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Assessor Notes**: [Agency: Record observations]

---

### TEST-AU-04 — Timestamp Accuracy (AU-8)

**Control**: AU-8
**Track**: Track 1 (Direct Examination)

**Objective**: Confirm that audit record timestamps are in RFC 3339 UTC with nanosecond
precision and are accurate to within NTP synchronization tolerance.

**Procedure**:

1. Verify timestamp format in recent probe results:

```bash
kubectl get siderealproberesults -n sidereal-system \
  --sort-by=.metadata.creationTimestamp -o json \
  | jq '.items[-3:][].spec.execution.timestamp'
```

Expected: format `2026-01-15T14:30:45.123456789Z` (RFC 3339 UTC, nanosecond precision).

2. Compare a probe result timestamp to the node's current time:

```bash
kubectl get siderealproberesults -n sidereal-system \
  --sort-by=.metadata.creationTimestamp -o json \
  | jq '.items[-1].spec.execution.timestamp'
date -u +"%Y-%m-%dT%H:%M:%S.%NZ"
```

The difference should be within the NTP synchronization tolerance (typically < 1 second).

3. Confirm NTP configuration on cluster nodes:

[Agency: Document the NTP source and verify nodes are synchronized within tolerance]

**Pass Criteria**: Timestamps are RFC 3339 UTC with nanosecond precision. Timestamp values
are accurate to within NTP tolerance.

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Assessor Notes**: [Agency: Record observations]

---

### TEST-AU-05 — Audit Record Retention (AU-11)

**Control**: AU-11
**Track**: Track 1 (Direct Examination) + Interview

**Objective**: Confirm that audit records are retained for the required minimum periods.

**Procedure**:

1. Confirm in-cluster retention is set to 365 days minimum:

```bash
helm get values sidereal -n sidereal-system | grep retention
```

Expected: `retentionDays: 365` or higher.

2. Check that older records have not been deleted ahead of TTL:

```bash
kubectl get siderealproberesults -n sidereal-system \
  --sort-by=.metadata.creationTimestamp -o json \
  | jq '.items[0].metadata.creationTimestamp'
```

The oldest record should be within the 365-day TTL window.

3. Verify SIEM retention policy meets minimum 3-year requirement:

[Agency: Document SIEM retention policy evidence — Splunk index retention, Elasticsearch
ILM policy, or S3 Object Lock configuration]

**Pass Criteria**: In-cluster retention is ≥ 365 days. SIEM retention is ≥ 3 years.
Oldest in-cluster records are within the configured TTL (not prematurely deleted).

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Assessor Notes**: [Agency: Record observations]

---

## 8. Test Procedures — Configuration Management (CM)

---

### TEST-CM-01 — Baseline Configuration Documentation (CM-2)

**Control**: CM-2
**Track**: Track 1 (Examine + Interview)

**Objective**: Confirm that the Helm values file constitutes a documented baseline and
is version-controlled.

**Procedure**:

1. Confirm the Helm values file is committed to a Git repository:

[Agency: Show the Git commit history for the Helm values-override.yaml file]

2. Confirm the deployed values match the committed baseline:

```bash
helm get values sidereal -n sidereal-system > /tmp/deployed-values.yaml
diff /tmp/deployed-values.yaml [Agency: path to committed values-override.yaml]
```

Expected: no diff.

3. Confirm the configuration management plan is current:

[Agency: Review `compliance/plans/configuration-management-plan.md` and confirm
it reflects the current deployment]

**Pass Criteria**: Values file is version-controlled. Deployed values match committed baseline.
CMP is current and accurate.

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Assessor Notes**: [Agency: Record observations]

---

### TEST-CM-02 — Schema-Enforced Configuration Constraints (CM-6)

**Control**: CM-6
**Track**: Track 1 (Test)

**Objective**: Confirm that `values.schema.json` prevents out-of-bounds configuration values.

**Procedure**:

1. Attempt to install or upgrade with a value that violates schema constraints (dry-run):

```bash
helm upgrade sidereal . -n sidereal-system \
  --set probe.intervalSeconds=60 \
  --dry-run 2>&1 | grep -i 'schema\|invalid\|error'
```

Expected: schema validation error for `intervalSeconds` below minimum (300).

2. Confirm `global.impactLevel` is set appropriately for the system categorization:

```bash
helm get values sidereal -n sidereal-system | grep impactLevel
```

Expected: `impactLevel: high` (for NIST 800-53 High baseline systems).

3. Attempt to set `tls.required: false`:

```bash
helm upgrade sidereal . -n sidereal-system \
  --set tls.required=false \
  --dry-run 2>&1 | grep -i 'schema\|invalid\|error'
```

Expected: schema validation error.

**Pass Criteria**: Schema constraints are enforced at Helm upgrade time. Out-of-bounds values
are rejected.

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Assessor Notes**: [Agency: Record observations]

---

### TEST-CM-03 — SBOM Availability and Integrity (CM-8)

**Control**: CM-8
**Track**: Track 1 (Test)

**Objective**: Confirm that a CycloneDX SBOM is available and cosign-attested for each
deployed image.

**Procedure**:

For each distinct image digest deployed in `sidereal-system`:

```bash
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp 'https://github.com/primaris-tech/sidereal' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  <image>@<digest> \
  | jq '.payload | @base64d | fromjson | .predicate.metadata'
```

Expected: CycloneDX SBOM metadata is returned, including component list.

**Pass Criteria**: Valid cosign-attested CycloneDX SBOM is retrievable for all deployed digests.

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Assessor Notes**: [Agency: Record image digests tested and SBOM metadata]

---

## 9. Test Procedures — Identification and Authentication (IA)

---

### TEST-IA-01 — External System Authentication (IA-3)

**Control**: IA-3, IA-3(1)
**Track**: Track 1 (Examine + Test)

**Objective**: Confirm that Sidereal authenticates all external systems with SAN-validated
mTLS before establishing connections.

**Procedure**:

1. Confirm TLS configuration for detection backends (e.g., Falco, Tetragon) if deployed:

```bash
helm get values sidereal -n sidereal-system \
  | grep -A10 'falco\|tetragon'
```

Expected: TLS cert references present; `insecureSkipVerify` is absent or `false`.

2. Review controller logs for TLS handshake completions:

```bash
kubectl logs deployment/sidereal-controller -n sidereal-system \
  | grep -i 'tls\|handshake\|certificate' | head -20
```

Expected: successful TLS handshake messages; no certificate errors.

3. Confirm `tlsInsecureSkipVerify` is not set for any connection:

```bash
helm get values sidereal -n sidereal-system | grep -i insecure
```

Expected: no output, or explicit `false` values.

**Pass Criteria**: TLS is configured for all external connections. `insecureSkipVerify` is
not enabled. TLS handshakes complete successfully in controller logs.

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Assessor Notes**: [Agency: Record observations]

---

### TEST-IA-02 — FIPS Module Self-Authentication (IA-7)

**Control**: IA-7
**Track**: Track 1 (Examine)

**Objective**: Confirm that FIPS Known Answer Tests execute at startup and that failure
causes process exit (not silent continuation).

**Procedure**:

1. Review controller startup logs for FIPS KAT evidence:

```bash
kubectl logs deployment/sidereal-controller -n sidereal-system \
  | head -50 | grep -i 'fips\|kat\|boring\|crypto'
```

Expected: FIPS initialization or BoringCrypto initialization message at startup.

2. Confirm the deployed CMVP certificate numbers match the version deployed:

[Agency: Retrieve CMVP certificate status for BoringCrypto #3678 and aws-lc-rs #4816
from https://csrc.nist.gov/projects/cryptographic-module-validation-program]

**Pass Criteria**: FIPS initialization is logged at startup. CMVP certificates are active.

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Assessor Notes**: [Agency: Record CMVP certificate status]

---

## 10. Test Procedures — Security Assessment and Authorization (CA)

---

### TEST-CA-01 — Continuous Assessment Coverage (CA-2, CA-7)

**Control**: CA-2, CA-2(1), CA-7
**Track**: Track 2 (Evidence Review — all probe types)

**Objective**: Confirm that Sidereal is continuously assessing all five built-in probe surfaces
(plus any custom probes) and that the assessment record is complete for the assessment period.

**Procedure**:

Execute the Track 2 evidence review (§4.2) for all five built-in probe types and any deployed
custom probes. Compile a coverage matrix:

| Probe Type | Results Count | Failures | Coverage Gaps | SIEM Export Complete | Rating |
|---|---|---|---|---|---|
| rbac | [Agency] | [Agency] | [Agency] | [Agency] | [Agency] |
| netpol | [Agency] | [Agency] | [Agency] | [Agency] | [Agency] |
| admission | [Agency] | [Agency] | [Agency] | [Agency] | [Agency] |
| secret | [Agency] | [Agency] | [Agency] | [Agency] | [Agency] |
| detection | [Agency] | [Agency] | [Agency] | [Agency] | [Agency] |
| [Agency: custom] | [Agency] | [Agency] | [Agency] | [Agency] | [Agency] |

**Pass Criteria**: All five built-in probe surfaces (and any deployed custom probes) have continuous results for the assessment period.
No coverage gaps exceeding 2× the configured interval. All records HMAC-verified. SIEM export
complete for all records.

**Overall Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Assessor Notes**: [Agency: Attach coverage matrix as evidence artifact]

---

### TEST-CA-02 — Detection Probe AO Authorization (CA-8)

**Control**: CA-8
**Track**: Track 1 (Examine)

**Objective**: Confirm that detection probes execute only with a valid, non-expired
`SiderealAOAuthorization` CR and that the AO has explicitly authorized the techniques
and namespace scope.

**Procedure**:

1. Retrieve the current `SiderealAOAuthorization` CR:

```bash
kubectl get siderealaoauthorizations -n sidereal-system -o yaml
```

Verify:
- `spec.aoName` identifies a named individual (not a role or team)
- `spec.authorizedTechniques` lists only known MITRE ATT&CK technique IDs
- `spec.authorizedNamespaces` is appropriately scoped (not `*`)
- `spec.expiresAt` has not passed

2. Confirm detection probe results reference the authorization:

```bash
kubectl get siderealproberesults -n sidereal-system \
  --field-selector='spec.probe.type=detection' \
  -o json | jq '.items[0].spec.probe.aoAuthorizationRef'
```

Expected: reference to the `SiderealAOAuthorization` CR name.

3. Confirm that probe scheduling halts when no valid authorization exists:

[Agency: If the authorization has been allowed to expire at any point, confirm that
detection probes show `outcome: Blocked` or are absent from the result list during that period.]

**Pass Criteria**: A valid, non-expired `SiderealAOAuthorization` exists with named AO,
scoped techniques, and scoped namespaces. All detection probe results reference the authorization.

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Assessor Notes**: [Agency: Record authorization details and AO identity verification]

---

## 11. Test Procedures — System and Communications Protection (SC)

---

### TEST-SC-01 — Boundary Protection (SC-7, SC-7(3), SC-7(5))

**Control**: SC-7 and enhancements
**Track**: Track 1 (Test) + Track 2 (Evidence Review)

**Objective**: Confirm the `sidereal-system` default-deny boundary and that the NetworkPolicy
probe validates it continuously.

**Procedure**: Execute TEST-SYS-04 (§5) for the Track 1 component, then execute the Track 2
evidence review for `spec.probe.type=netpol` for the Track 2 component.

Additionally, confirm Sidereal has no public-facing services:

```bash
kubectl get svc -n sidereal-system
```

Expected: all services are `ClusterIP` type; no `LoadBalancer` or `NodePort` services.

**Pass Criteria**: TEST-SYS-04 passes. NetworkPolicy probe shows no failures during assessment
period. No public-facing services.

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Assessor Notes**: [Agency: Reference TEST-SYS-04 result]

---

### TEST-SC-02 — Transmission Integrity and Confidentiality (SC-8, SC-8(1))

**Control**: SC-8, SC-8(1), SC-8(2)
**Track**: Track 1 (Examine + Test)

**Objective**: Confirm that all Sidereal transmissions use TLS 1.2+ with FIPS cipher suites
and that HMAC provides transport-independent integrity.

**Procedure**:

1. Confirm TLS minimum version configuration:

```bash
helm get values sidereal -n sidereal-system | grep -i 'tls\|cipher\|version'
```

Expected: `tls.minVersion: TLS12` or `TLS13`.

2. Test TLS negotiation to the metrics endpoint:

```bash
kubectl port-forward deployment/sidereal-controller 8080:8080 -n sidereal-system &
openssl s_client -connect localhost:8443 -tls1_1 2>&1 | grep -i 'alert\|error\|cipher'
```

Expected: TLS 1.1 connection should fail (not accepted).

3. Confirm HMAC result signing is active (see TEST-SYS-02 §5).

**Pass Criteria**: TLS 1.2+ enforced. TLS 1.1 and earlier are rejected. HMAC result signing
is active (TEST-SYS-02 passed).

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Assessor Notes**: [Agency: Record observations]

---

### TEST-SC-03 — Cryptographic Key Management (SC-12, SC-13)

**Control**: SC-12, SC-13
**Track**: Track 1 (Examine + Interview)

**Objective**: Confirm that cryptographic keys have documented lifecycles, are properly
protected, and that FIPS-approved algorithms are used exclusively.

**Procedure**:

1. Confirm the HMAC root Secret is KMS-encrypted (IL4/IL5):

```bash
kubectl get secret sidereal-hmac-root -n sidereal-system -o yaml \
  | grep 'annotations'
```

Expected: KMS key ARN or reference in annotations (if KMS integration is configured).

2. Confirm mTLS certificate expiry dates are within the approved key rotation schedule:

[Agency: List all TLS certificates in use by Sidereal and their expiry dates. Confirm
expiry is within the approved key rotation window.]

3. Interview the operations team: What is the procedure for rotating the cosign signing key?
   Has it been rotated within the last 2 years?

[Agency: Document key rotation status and schedule]

4. Execute TEST-SYS-06 (§5) for FIPS algorithm enforcement.

**Pass Criteria**: HMAC root Secret is KMS-protected. mTLS certificates are within rotation
schedule. Cosign key rotation procedure is documented and practiced. TEST-SYS-06 passes.

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Assessor Notes**: [Agency: Record key inventory and rotation status]

---

## 12. Test Procedures — System and Information Integrity (SI)

---

### TEST-SI-01 — Flaw Remediation (SI-2)

**Control**: SI-2, SI-2(2), SI-2(3)
**Track**: Track 1 (Examine + Interview)

**Objective**: Confirm that CVE scanning is in place and that the remediation SLA is
being met for the deployed image digests.

**Procedure**:

1. Run Trivy against the deployed Sidereal image digests:

```bash
for IMAGE in $(kubectl get pods -n sidereal-system -o json \
  | jq -r '.items[].spec.containers[].image'); do
  echo "=== $IMAGE ==="
  trivy image --severity CRITICAL,HIGH $IMAGE 2>&1 | grep -E 'Total|CRITICAL|HIGH'
done
```

Expected: zero Critical and High CVEs in deployed images (or documented exceptions with
remediation timelines in the POA&M).

2. Confirm CI pipeline CVE gates are in place:

[Agency: Review the Sidereal CI pipeline configuration or release notes to confirm
Critical/High CVEs block builds]

3. Interview the operations team: What is the procedure for responding to a CVE advisory
   for a deployed Sidereal image? Has any advisory required a response during the past year?

[Agency: Document CVE response history and SLA compliance]

**Pass Criteria**: Zero unaddressed Critical or High CVEs in deployed images. CVE gate is
documented in CI pipeline. CVE response procedure is known to operations staff.

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Assessor Notes**: [Agency: Attach Trivy output as evidence artifact]

---

### TEST-SI-02 — Security Function Verification (SI-6)

**Control**: SI-6
**Track**: Track 1 (Examine) + Track 2 (Evidence Review — all probe types)

**Objective**: Confirm that Sidereal verifies its own security functions at startup and
continuously, and that failures halt operations.

**Procedure**:

1. Execute TEST-SYS-08 (§5) for bootstrap verification.

2. Execute the Track 2 evidence review (§4.2) for all five built-in probe types (and any
   deployed custom probes), confirming that continuous security function verification is
   producing current results.

3. Confirm the halt-on-failure posture:

```bash
kubectl get siderealsystemalerts -n sidereal-system -o json \
  | jq '.items[] | select(.spec.acknowledged == false)'
```

Expected: no unacknowledged system alerts (or investigate any that exist).

**Pass Criteria**: TEST-SYS-08 passes. All probe surfaces have current results. No
unacknowledged system alerts.

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Assessor Notes**: [Agency: Reference TEST-SYS-08 result]

---

### TEST-SI-03 — Non-Persistence (SI-14)

**Control**: SI-14
**Track**: Track 1 (Test)

**Objective**: Confirm that probe runner Jobs are strictly non-persistent and do not
carry state between executions.

**Procedure**: Execute TEST-SYS-05 (§5).

**Pass Criteria**: TEST-SYS-05 passes.

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Assessor Notes**: [Agency: Reference TEST-SYS-05 result]

---

## 13. Test Procedures — Supply Chain Risk Management (SR)

---

### TEST-SR-01 — Supply Chain Controls and Provenance (SR-3, SR-4)

**Control**: SR-3, SR-4
**Track**: Track 1 (Test)

**Objective**: Confirm that SLSA provenance attestations are available for all deployed
images and that they trace the full build provenance.

**Procedure**:

For each deployed image digest:

```bash
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp 'https://github.com/primaris-tech/sidereal' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  <image>@<digest> \
  | jq '.payload | @base64d | fromjson | .predicate'
```

Verify:
- `buildType` references the GitHub Actions workflow
- `materials[].uri` references the sidereal source repository
- `materials[].digest.sha1` matches a known commit SHA

**Pass Criteria**: Valid SLSA provenance attestation is retrievable for all deployed digests.
Provenance traces to a known source commit in the official repository.

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Assessor Notes**: [Agency: Record provenance chain for each deployed digest]

---

### TEST-SR-02 — Tamper Resistance and Component Authenticity (SR-9, SR-11)

**Control**: SR-9, SR-11
**Track**: Track 1 (Test)

**Objective**: Confirm that image digest pinning and cosign signature verification
provide tamper resistance against component substitution.

**Procedure**:

1. Confirm all running images are referenced by digest, not by tag:

```bash
kubectl get pods -n sidereal-system -o json \
  | jq '.items[].spec.containers[].image' \
  | grep -v '@sha256:'
```

Expected: no output (all images reference a digest, not a mutable tag).

2. Execute TEST-SYS-01 (§5) for cosign signature verification.

3. Verify that Rekor inclusion proofs exist for the deployed digests:

```bash
rekor-cli search --sha <image-digest> 2>/dev/null | head -5
```

Expected: one or more Rekor log entry UUIDs returned.

**Pass Criteria**: All images are digest-pinned. TEST-SYS-01 passes. Rekor inclusion proofs exist.

**Rating**: [ ] Satisfied  [ ] Other Than Satisfied — Low  [ ] Moderate  [ ] High

**Assessor Notes**: [Agency: Record Rekor entry UUIDs as evidence artifacts]

---

## 14. Assessment Schedule

[Agency: Complete the schedule below with actual dates and responsible parties.]

| Test ID | Test Name | Scheduled Date | Responsible Assessor | Status |
|---|---|---|---|---|
| TEST-SYS-01 | Image Signature Verification | [Agency] | [Agency] | [ ] |
| TEST-SYS-02 | HMAC Result Integrity Chain | [Agency] | [Agency] | [ ] |
| TEST-SYS-03 | Append-Only Enforcement | [Agency] | [Agency] | [ ] |
| TEST-SYS-04 | NetworkPolicy Default-Deny | [Agency] | [Agency] | [ ] |
| TEST-SYS-05 | Probe Job Security Posture | [Agency] | [Agency] | [ ] |
| TEST-SYS-06 | FIPS Cryptographic Module | [Agency] | [Agency] | [ ] |
| TEST-SYS-07 | Controller/Probe Identity Separation | [Agency] | [Agency] | [ ] |
| TEST-SYS-08 | Bootstrap Verification | [Agency] | [Agency] | [ ] |
| TEST-AC-01 | RBAC Probe Effectiveness | [Agency] | [Agency] | [ ] |
| TEST-AC-02 | Secret Access Probe | [Agency] | [Agency] | [ ] |
| TEST-AC-03 | NetworkPolicy Probe | [Agency] | [Agency] | [ ] |
| TEST-AC-04 | Admission Control Probe | [Agency] | [Agency] | [ ] |
| TEST-AC-05 | Session Termination | [Agency] | [Agency] | [ ] |
| TEST-AU-01 | Audit Record Content | [Agency] | [Agency] | [ ] |
| TEST-AU-02 | Audit Log Storage Capacity | [Agency] | [Agency] | [ ] |
| TEST-AU-03 | Audit Processing Failures | [Agency] | [Agency] | [ ] |
| TEST-AU-04 | Timestamp Accuracy | [Agency] | [Agency] | [ ] |
| TEST-AU-05 | Audit Record Retention | [Agency] | [Agency] | [ ] |
| TEST-CM-01 | Baseline Configuration | [Agency] | [Agency] | [ ] |
| TEST-CM-02 | Schema-Enforced Constraints | [Agency] | [Agency] | [ ] |
| TEST-CM-03 | SBOM Availability | [Agency] | [Agency] | [ ] |
| TEST-IA-01 | External System Authentication | [Agency] | [Agency] | [ ] |
| TEST-IA-02 | FIPS Module Self-Authentication | [Agency] | [Agency] | [ ] |
| TEST-CA-01 | Continuous Assessment Coverage | [Agency] | [Agency] | [ ] |
| TEST-CA-02 | Detection Probe AO Authorization | [Agency] | [Agency] | [ ] |
| TEST-SC-01 | Boundary Protection | [Agency] | [Agency] | [ ] |
| TEST-SC-02 | Transmission Integrity | [Agency] | [Agency] | [ ] |
| TEST-SC-03 | Key Management | [Agency] | [Agency] | [ ] |
| TEST-SI-01 | Flaw Remediation | [Agency] | [Agency] | [ ] |
| TEST-SI-02 | Security Function Verification | [Agency] | [Agency] | [ ] |
| TEST-SI-03 | Non-Persistence | [Agency] | [Agency] | [ ] |
| TEST-SR-01 | Supply Chain and Provenance | [Agency] | [Agency] | [ ] |
| TEST-SR-02 | Tamper Resistance and Authenticity | [Agency] | [Agency] | [ ] |

---

## 15. Findings Summary

[Agency: Complete after assessment execution. All findings with a rating of Other Than
Satisfied must have a corresponding POA&M entry.]

### 15.1 Executive Summary

| Metric | Value |
|---|---|
| Total tests executed | [Agency] |
| Tests Satisfied | [Agency] |
| Tests Other Than Satisfied — Low | [Agency] |
| Tests Other Than Satisfied — Moderate | [Agency] |
| Tests Other Than Satisfied — High | [Agency] |
| Tests Not Executed | [Agency] |
| New POA&M items opened | [Agency] |
| Prior POA&M items closed | [Agency] |

### 15.2 Findings Detail

[Agency: For each Other Than Satisfied finding, complete one entry using the finding
template in Appendix B. Reference the `SiderealIncident` CR if applicable.]

| Finding ID | Test ID | Control | Severity | Description | POA&M Reference |
|---|---|---|---|---|---|
| [Agency] | [Agency] | [Agency] | [Agency] | [Agency] | [Agency] |

### 15.3 Significant Findings Requiring Immediate Action

[Agency: List any findings that represent an immediate risk requiring action before
the ATO decision is made.]

---

## 16. Approvals and Signatures

### Lead Assessor

I certify that the assessment was conducted in accordance with this Security Assessment Plan
and that the findings are accurately documented.

| Field | Value |
|---|---|
| Name | [Agency: Print name] |
| Organization | [Agency: Organization] |
| Signature | _____________________________ |
| Date | [Agency: Date] |

---

### ISSO

I have reviewed the findings and confirm that the POA&M entries have been opened for all
Other Than Satisfied findings.

| Field | Value |
|---|---|
| Name | [Agency: Print name] |
| Signature | _____________________________ |
| Date | [Agency: Date] |

---

### Authorizing Official

I have reviewed the Security Assessment Report derived from this plan and accept the residual
risk associated with the Other Than Satisfied findings documented above.

| Field | Value |
|---|---|
| Name | [Agency: Print name] |
| Title | [Agency: Title] |
| Signature | _____________________________ |
| Date | [Agency: Date] |

---

## Appendix A — Evidence Collection Commands

These commands produce output suitable for attachment as assessment evidence artifacts.

### Export all probe results for an assessment period

```bash
kubectl get siderealproberesults -n sidereal-system \
  -o json > sidereal-probe-results-$(date +%Y%m%d).json
```

### Export all incidents

```bash
kubectl get siderealincidents -n sidereal-system \
  -o json > sidereal-incidents-$(date +%Y%m%d).json
```

### Export all system alerts

```bash
kubectl get siderealsystemalerts -n sidereal-system \
  -o json > sidereal-system-alerts-$(date +%Y%m%d).json
```

### Export all AO authorizations

```bash
kubectl get siderealaoauthorizations -n sidereal-system \
  -o json > sidereal-ao-authorizations-$(date +%Y%m%d).json
```

### Export all probe recommendations

```bash
kubectl get siderealproberecommendations -n sidereal-system \
  -o json > sidereal-probe-recommendations-$(date +%Y%m%d).json
```

### Export all reports

```bash
kubectl get siderealreports -n sidereal-system \
  -o json > sidereal-reports-$(date +%Y%m%d).json
```

### Generate an assessment report via CLI

```bash
sidereal report \
  --namespace sidereal-system \
  --start-date [Agency: Insert start date] \
  --end-date [Agency: Insert end date] \
  --output sidereal-assessment-report-$(date +%Y%m%d).json
```

### Export current Helm values (deployed configuration baseline)

```bash
helm get values sidereal -n sidereal-system \
  > sidereal-helm-values-$(date +%Y%m%d).yaml
```

### Export probe result summary by type and outcome

```bash
kubectl get siderealproberesults -n sidereal-system -o json \
  | jq '[.items[] | {type: .spec.probe.type, outcome: .spec.result.outcome,
          effectiveness: .spec.result.controlEffectiveness,
          integrity: .spec.result.integrityStatus, exported: .spec.audit.exportStatus,
          ts: .spec.execution.timestamp}]
        | group_by(.type)
        | map({type: .[0].type,
               count: length,
               failures: map(select(.outcome != "Pass" and .outcome != "Blocked")) | length,
               tampered: map(select(.integrity == "TamperedResult")) | length,
               exportFailed: map(select(.exported == "Failed")) | length})'
```

### Check for any open SiderealSystemAlerts

```bash
kubectl get siderealsystemalerts -n sidereal-system \
  -o custom-columns='NAME:.metadata.name,REASON:.spec.reason,ACKNOWLEDGED:.spec.acknowledged,CREATED:.metadata.creationTimestamp'
```

### Verify cosign signatures for all deployed images

```bash
kubectl get pods -n sidereal-system -o json \
  | jq -r '.items[].spec.containers[].image' \
  | sort -u \
  | while read IMAGE; do
      echo "Verifying: $IMAGE"
      cosign verify \
        --certificate-identity-regexp 'https://github.com/primaris-tech/sidereal' \
        --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
        "$IMAGE" 2>&1 | grep -E 'Verification|Error'
    done
```

---

## Appendix B — Finding Template

Use this template for each Other Than Satisfied finding.

---

**Finding ID**: [Agency: e.g., SIDEREAL-2026-001]

**Test ID**: [Agency: Reference the test procedure that produced this finding]

**Controls Affected**: [Agency: List NIST 800-53 control identifiers]

**Severity**: [ ] Low  [ ] Moderate  [ ] High  [ ] Critical

**Description**:

[Agency: Describe what was observed. Include specific commands run and output received.
Reference any `SiderealIncident` CR names if applicable (e.g., `incident-ac3-2026-01-15`).]

**Evidence Artifacts**:

[Agency: List filenames or reference numbers for supporting evidence:
- Kubectl output files
- SIEM query results
- SiderealProbeResult CR names
- SiderealIncident CR names
- SiderealReport CR names (if applicable)]

**Root Cause**:

[Agency: Describe the underlying cause of the finding.]

**Risk Statement**:

[Agency: Describe the security risk if this finding is not remediated.]

**Recommended Remediation**:

[Agency: Describe the specific actions required to remediate this finding.]

**POA&M Entry**:

| Field | Value |
|---|---|
| POA&M Item ID | [Agency] |
| Scheduled Completion | [Agency] |
| Responsible Party | [Agency] |
| Milestone 1 | [Agency: Action + date] |
| Milestone 2 | [Agency: Action + date] |
| Current Status | Open |

**Closure Criteria**:

[Agency: Define what constitutes closure. For probe-surface findings, closure requires
`SiderealProbeResult` records showing `Pass` with `controlEffectiveness: Effective` for
a minimum of 3 consecutive executions after the remediation action. Review any
`SiderealProbeRecommendation` CRs for remediation guidance.]

---

*This document was prepared using the Sidereal ATO Documentation Package.
The OSCAL Component Definition (`compliance/trestle-workspace/component-definitions/sidereal/component-definition.json`)
is the machine-readable source of record for all control implementations referenced in this plan.
Sidereal defines 9 CRDs: SiderealProbe, SiderealProbeResult, SiderealIncident, SiderealSystemAlert,
SiderealAOAuthorization, SiderealProbeRecommendation, SiderealReport, SiderealFramework, and 7 built-in ServiceAccounts.*
