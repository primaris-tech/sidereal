# System Security Plan (SSP) Template
## Gauntlet Continuous Security Control Validation Operator

**Classification**: [Agency: Insert applicable classification marking]
**Version**: 1.0
**Date**: [Agency: Insert date]
**Status**: [Draft / Final]

> **How to use this template**: Sections marked `[Agency: ...]` require agency-specific input.
> All other sections document Gauntlet's control implementations as pre-filled content.
> Do not alter pre-filled Gauntlet sections without consulting your Gauntlet representative —
> changes may invalidate the supporting OSCAL Component Definition.
>
> This template assumes deployment on a **NIST 800-53 Rev 5 High Baseline** system.
> For Moderate baseline, annotate which High-only enhancements your agency has waived.

---

## Table of Contents

1. [System Identification](#1-system-identification)
2. [System Owner and Points of Contact](#2-system-owner-and-points-of-contact)
3. [System Description](#3-system-description)
4. [Authorization Boundary](#4-authorization-boundary)
5. [Network Architecture](#5-network-architecture)
6. [Data Flows](#6-data-flows)
7. [System Environment](#7-system-environment)
8. [Leveraged Systems](#8-leveraged-systems)
9. [Control Implementation Summary](#9-control-implementation-summary)
10. [Access Control (AC)](#10-access-control-ac)
11. [Audit and Accountability (AU)](#11-audit-and-accountability-au)
12. [Configuration Management (CM)](#12-configuration-management-cm)
13. [Contingency Planning (CP)](#13-contingency-planning-cp)
14. [Identification and Authentication (IA)](#14-identification-and-authentication-ia)
15. [Incident Response (IR)](#15-incident-response-ir)
16. [Risk Assessment (RA)](#16-risk-assessment-ra)
17. [Security Assessment and Authorization (CA)](#17-security-assessment-and-authorization-ca)
18. [System and Communications Protection (SC)](#18-system-and-communications-protection-sc)
19. [System and Information Integrity (SI)](#19-system-and-information-integrity-si)
20. [Supply Chain Risk Management (SR)](#20-supply-chain-risk-management-sr)
21. [Continuous Monitoring Strategy](#21-continuous-monitoring-strategy)
22. [Plan of Action and Milestones (POA&M)](#22-plan-of-action-and-milestones-poam)
23. [Approvals and Signatures](#23-approvals-and-signatures)

---

## 1. System Identification

| Field | Value |
|---|---|
| System Name | Gauntlet Continuous Security Control Validation Operator |
| System Abbreviation / Acronym | Gauntlet |
| System Version | [Agency: Insert deployed Helm chart version, e.g., `gauntlet-1.2.0`] |
| FIPS 199 Impact Level | High |
| System Type | Minor Application / Platform Component |
| Operational Status | [Agency: Operational / Under Development / Major Modification] |
| System Owner Organization | [Agency: Insert organization name] |
| Authorizing Official (AO) | [Agency: Insert AO name and title] |
| Date of Last ATO | [Agency: Insert date or "Initial Authorization"] |
| ATO Expiration | [Agency: Insert date] |
| ISSO | [Agency: Insert ISSO name] |
| ISSM | [Agency: Insert ISSM name] |

---

## 2. System Owner and Points of Contact

**System Owner**

| Field | Value |
|---|---|
| Name | [Agency: Insert name] |
| Title | [Agency: Insert title] |
| Organization | [Agency: Insert organization] |
| Address | [Agency: Insert address] |
| Phone | [Agency: Insert phone] |
| Email | [Agency: Insert email] |

**Information System Security Officer (ISSO)**

| Field | Value |
|---|---|
| Name | [Agency: Insert name] |
| Title | [Agency: Insert title] |
| Phone | [Agency: Insert phone] |
| Email | [Agency: Insert email] |

**Technical Point of Contact**

| Field | Value |
|---|---|
| Name | [Agency: Insert name] |
| Title | [Agency: Insert title] |
| Phone | [Agency: Insert phone] |
| Email | [Agency: Insert email] |

---

## 3. System Description

### 3.1 Purpose and Function

Gauntlet is a Kubernetes-native security operator that provides **continuous, active validation
of security control effectiveness**. Rather than verifying configuration state, Gauntlet
continuously executes targeted probes against a live cluster to verify that security controls
are *operationally effective* — producing evidence that would be accepted by a NIST 800-53
assessor.

Gauntlet addresses the gap between configuration verification (what most tools do) and
operational validation (whether controls actually stop or detect adversarial actions). Each probe
maps directly to one or more NIST 800-53 controls and, where applicable, a MITRE ATT&CK for
Containers technique.

### 3.2 Probe Surfaces

Gauntlet executes five probe surfaces:

| Probe Surface | What It Validates | Primary Controls |
|---|---|---|
| **RBAC** | Kubernetes RBAC denies unauthorized operations (both deny-path and allow-path verification) | AC-3, AC-6 |
| **NetworkPolicy** | CNI enforcement plane drops traffic that NetworkPolicy rules prohibit | AC-4, SC-7 |
| **Admission Control** | Admission controller policies reject non-compliant workloads | CM-7, SI-3 |
| **Secret Access** | Cross-namespace Secret access is denied; least-privilege enforced | AC-3, AC-6 |
| **Detection Coverage** | Detection backend raises alerts when adversarial syscall patterns are emitted | SI-3, SI-4, CA-8 |

### 3.3 Key Design Properties

- **Continuous, not point-in-time**: Probes execute on configurable schedules (default: every 6 hours) with ±10% jitter
- **HMAC result integrity**: Every probe result is signed with a per-execution HMAC key; the controller verifies the signature before accepting the result; a tampered result suspends the probe surface
- **Append-only audit log**: `GauntletProbeResult` CRs are immutable after creation (enforced by admission enforcement policy); they cannot be deleted or modified during the 365-day minimum retention period
- **Separation of identity**: The controller cannot perform the operations the probes perform; a compromised controller cannot produce a falsified result without also defeating HMAC verification
- **FIPS 140-2 cryptography**: Go components use BoringCrypto (CMVP #3678); Rust detection probe uses aws-lc-rs (CMVP #4816); no non-FIPS codepath is reachable at runtime
- **AO authorization for detection probes**: Detection probes require an active `GauntletAOAuthorization` CR bearing the AO's identity, scope, and expiry before execution proceeds

### 3.4 System Deployment Context

[Agency: Describe the cluster(s) Gauntlet is deployed into, their classification, and how Gauntlet fits into the overall system architecture.]

Gauntlet is deployed as a Kubernetes operator into the `gauntlet-system` namespace using the
official Helm chart. It does not require persistent storage. It does not expose any external
services. It does not process mission application data.

---

## 4. Authorization Boundary

### 4.1 Boundary Description

The Gauntlet authorization boundary is the `gauntlet-system` Kubernetes namespace, which is
protected by a default-deny NetworkPolicy. All components inside the boundary are deployed and
managed by the Gauntlet Helm chart.

See `compliance/diagrams/authorization-boundary.md` for the full Mermaid diagram.

### 4.2 Components Inside the Boundary

| Component | Type | Notes |
|---|---|---|
| Controller Manager | Kubernetes Deployment | Go / BoringCrypto FIPS; always running |
| Probe Runner Jobs | Kubernetes Jobs (ephemeral) | One per execution; TTL-cleaned; short-lived |
| GauntletProbe CRDs | Kubernetes custom resources | Probe configuration |
| GauntletProbeResult CRDs | Kubernetes custom resources | Append-only audit records; 365-day minimum TTL |
| GauntletIncident CRDs | Kubernetes custom resources | Control failure records |
| GauntletSystemAlert CRDs | Kubernetes custom resources | Degraded state indicators |
| GauntletAOAuthorization CRDs | Kubernetes custom resources | Detection probe authorization tokens |
| Admission enforcement policies | Kubernetes custom resources | Admission-layer blast radius controls |
| `gauntlet-system` NetworkPolicy | Kubernetes NetworkPolicy | Default-deny with explicit allow rules |
| HMAC root Secret | Kubernetes Secret | KMS-encrypted at IL4/IL5 |

### 4.3 Components Outside the Boundary

| Capability | System | Connection Direction | Data Type | ISA Required |
|---|---|---|---|---|
| Kubernetes platform | Kubernetes API Server | Bidirectional | Job creation; CRD read/write | No (same infrastructure) |
| Admission controller | [Agency: Per deployment profile] | Inbound (enforces) | Admission decisions | No (same cluster) |
| Detection backend | [Agency: Per deployment profile] | Inbound (read) | Alert/event records | [Agency: Yes/No + agreement reference] |
| CNI observability layer | [Agency: Per deployment profile] | Inbound (read) | Flow verdicts/records | [Agency: Yes/No + agreement reference] |
| SIEM | Splunk HEC / Elasticsearch | Outbound (write) | Audit records | [Agency: Yes — insert ISA/MOU reference] |
| Object storage | S3 | Outbound (write) | Audit records | [Agency: Yes — insert ISA/MOU reference] |

[Agency: Per deployment profile, document which admission controller (e.g., Kyverno or OPA Gatekeeper), detection backend (e.g., Falco or Tetragon), and CNI observability layer (e.g., Hubble/Cilium or Calico) are deployed.]

*Complete with actual ISA/MOU agreement references per CA-3 requirements.*

---

## 5. Network Architecture

See `compliance/diagrams/network-topology.md` for the full Mermaid diagram.

### 5.1 Summary

The `gauntlet-system` namespace operates under a default-deny NetworkPolicy for both ingress
and egress. All traffic is explicit allowlist-based.

**Permitted Ingress:**

| Source | Port | Purpose |
|---|---|---|
| kube-system (admission controller) | 8443/TCP | Webhook callbacks |
| monitoring (Prometheus) | 8080/TCP | Metrics scrape |

**Permitted Egress — Controller:**

| Destination | Port | Purpose |
|---|---|---|
| Kubernetes API Server | 443/TCP | Job creation, CRD operations |
| Detection backend | 50051/TCP | Detection alert query (gRPC) |
| Detection backend | 54321/TCP | Detection event query (gRPC) |
| CNI observability relay | 4245/TCP | Flow verdict query (gRPC) |
| CNI observability API | 5443/TCP | Flow verdict query (REST) |
| SIEM endpoint(s) | 443/TCP | Audit record export |

**Permitted Egress — Probe Runner Jobs (non-detection):**

| Destination | Port | Purpose |
|---|---|---|
| Kubernetes API Server | 443/TCP | Probe operations |

**Detection Probe:** No egress permitted. Isolated network namespace.

### 5.2 Agency Network Configuration

[Agency: Document the specific CIDRs configured in `values-override.yaml` for
`API_SERVER_CIDR` and `SIEM_ENDPOINT_CIDR`. Document the CNI in use and its observability
layer. Per deployment profile, document which admission controller, detection backend,
and CNI observability layer are deployed, and any cluster-level NetworkPolicy configuration
that supplements the namespace policy.]

---

## 6. Data Flows

See `compliance/diagrams/data-flows.md` for the full Mermaid diagrams.

### 6.1 Data Flow Summary

| Flow ID | Source | Destination | Data | Classification |
|---|---|---|---|---|
| DF-1 | Controller / Probe Jobs | Kubernetes API | Job specs; HMAC-signed result ConfigMaps; CRD records | System operational data |
| DF-2 | Controller | Detection backend (e.g., Falco or Tetragon) | Detection alert query; alert records (no PII) | System telemetry |
| DF-3 | Controller | CNI observability layer (e.g., Hubble or Calico) | Flow verdict query; flow records (no PII) | System telemetry |
| DF-4 | Controller | Splunk / Elasticsearch / S3 | Structured audit records | [Agency: Determine classification — see PIA] |

### 6.2 Data at Rest

| Location | Data | Protection |
|---|---|---|
| etcd (in-cluster) | GauntletProbeResult, GauntletIncident CRs | Kubernetes etcd encryption at rest; HMAC integrity |
| etcd (in-cluster) | HMAC root Secret | KMS-encrypted (IL4/IL5 requirement) |
| S3 | Exported audit records | SSE-KMS (FIPS key); Object Lock COMPLIANCE mode; 3-year retention |
| Splunk / Elasticsearch | Exported audit records | [Agency: Document at-rest encryption controls] |

### 6.3 Privacy Considerations

Gauntlet processes no mission application data and no end-user PII by design. It records:

- Kubernetes namespace names and workload labels (may be considered sensitive in some contexts)
- Probe execution timestamps and outcomes
- NIST control identifiers and MITRE ATT&CK technique identifiers

See the Privacy Impact Assessment (`compliance/plans/privacy-impact-assessment-template.md`)
for full analysis and the agency-specific privacy determination.

[Agency: Complete the Privacy Impact Assessment. If namespace names or workload labels
are considered sensitive, enable `privacy.redactNamespaceNames` and
`privacy.redactWorkloadIdentities` in the Helm values.]

---

## 7. System Environment

### 7.1 Infrastructure

[Agency: Describe the Kubernetes cluster(s) Gauntlet is deployed on, including:
- Cluster type (EKS, GKE, AKS, OpenShift, bare-metal, etc.)
- Kubernetes version
- Node operating system and hardening baseline (e.g., STIG-hardened RHEL 8)
- Impact level and hosting environment (GovCloud, on-premises, etc.)
- Whether the cluster itself has an active ATO]

### 7.2 Software Dependencies

Gauntlet depends on the following cluster-level software. These are external to the Gauntlet
boundary; their control implementations are inherited by Gauntlet but governed by the cluster ATO.

| Capability | Required | Purpose | Options (per deployment profile) |
|---|---|---|---|
| Admission controller | Required (one of) | Admission control enforcement for probe Job constraints and result immutability | Kyverno (≥ 1.10) *or* OPA Gatekeeper (≥ 3.14) |
| Kubernetes | Required | Operator platform | ≥ 1.26 |
| Detection backend | Optional (detection probes) | Syscall detection backend | Falco (≥ 0.37) *or* Tetragon (≥ 1.0) |
| CNI observability layer | Optional (NetworkPolicy probe) | CNI + flow observability | Cilium with Hubble (≥ 1.14) *or* Calico (≥ 3.26) |
| Prometheus | Optional | Metrics collection | Any |

[Agency: Per deployment profile, document which admission controller, detection backend,
and CNI observability layer are deployed. If no detection backend is deployed, detection
probes must be disabled. If no CNI observability layer is deployed, the NetworkPolicy
probe will produce `BackendUnreachable` outcomes.]

### 7.3 FIPS Compliance

Gauntlet ships two image variants:

| Variant | Cryptographic Library | Use Case |
|---|---|---|
| Standard | Go standard crypto (non-FIPS) | Development and testing only |
| FIPS | BoringCrypto (Go, CMVP #3678) / aws-lc-rs (Rust, CMVP #4816) | All federal deployments |

**Federal deployments must use FIPS image variants.** FIPS variants are identified by the
`-fips` suffix in the image tag and a distinct image digest. The Helm chart enforces FIPS
images when `global.fips: true` is set in values.

---

## 8. Leveraged Systems

Gauntlet inherits security controls from the underlying Kubernetes infrastructure. The
following table identifies inherited controls and the system from which they are inherited.

[Agency: Complete with references to the applicable system ATOs.]

| Control | Inherited From | ATO Reference |
|---|---|---|
| Physical and environmental protections (PE) | Data center / cloud provider | [Agency: Insert reference] |
| Media protection (MP) | Kubernetes etcd encryption | [Agency: Insert cluster ATO reference] |
| Personnel security (PS) | Agency HR processes | [Agency: Insert reference] |
| Kubernetes API server authentication | Kubernetes platform | [Agency: Insert cluster ATO reference] |
| Node OS hardening | Cluster node baseline | [Agency: Insert reference] |
| Network perimeter controls | Agency network | [Agency: Insert reference] |

---

## 9. Control Implementation Summary

The following table summarizes Gauntlet's implementation status for all NIST 800-53 Rev 5
High Baseline controls within scope. Controls marked **Inherited** rely on the underlying
platform; controls marked **Provided** are fully implemented by Gauntlet; controls marked
**Shared** have both Gauntlet and agency/platform components.

Machine-readable control implementations are available in the OSCAL Component Definition
at `compliance/trestle-workspace/component-definitions/gauntlet/component-definition.json`.

| Family | Control | Status | Implementation Owner |
|---|---|---|---|
| AC | AC-2 | Inherited | Kubernetes platform |
| AC | AC-3 | Provided | Gauntlet |
| AC | AC-4 | Provided | Gauntlet |
| AC | AC-6 | Provided | Gauntlet |
| AC | AC-12 | Provided | Gauntlet |
| AU | AU-2 | Provided | Gauntlet |
| AU | AU-3 | Provided | Gauntlet |
| AU | AU-4 | Provided | Gauntlet |
| AU | AU-5 | Provided | Gauntlet |
| AU | AU-8 | Shared | Gauntlet + platform (NTP) |
| AU | AU-9 | Provided | Gauntlet |
| AU | AU-10 | Provided | Gauntlet |
| AU | AU-11 | Provided | Gauntlet |
| AU | AU-12 | Provided | Gauntlet |
| CA | CA-2 | Provided | Gauntlet |
| CA | CA-7 | Provided | Gauntlet |
| CA | CA-8 | Provided | Gauntlet |
| CM | CM-2 | Provided | Gauntlet |
| CM | CM-3 | Shared | Gauntlet + agency |
| CM | CM-6 | Provided | Gauntlet |
| CM | CM-7 | Provided | Gauntlet |
| CM | CM-8 | Provided | Gauntlet |
| CM | CM-14 | Provided | Gauntlet |
| IA | IA-3 | Provided | Gauntlet |
| IA | IA-7 | Provided | Gauntlet |
| IA | IA-8 | Provided | Gauntlet |
| SC | SC-7 | Provided | Gauntlet |
| SC | SC-8 | Provided | Gauntlet |
| SC | SC-12 | Provided | Gauntlet |
| SC | SC-13 | Provided | Gauntlet |
| SI | SI-2 | Provided | Gauntlet |
| SI | SI-6 | Provided | Gauntlet |
| SI | SI-14 | Provided | Gauntlet |
| SR | SR-3 | Provided | Gauntlet |
| SR | SR-4 | Provided | Gauntlet |
| SR | SR-9 | Provided | Gauntlet |
| SR | SR-11 | Provided | Gauntlet |

---

## 10. Access Control (AC)

### AC-3 — Access Enforcement

**Gauntlet Implementation (Provided):**

Gauntlet continuously validates AC-3 enforcement across two dimensions:

1. **Deny-path validation**: The RBAC probe attempts operations that should be denied (e.g., accessing Secrets in a namespace where the test SA has no permissions) and verifies that a 403 Forbidden response is returned. A 200 or 404 constitutes a probe Failure and generates a `GauntletIncident`.

2. **Allow-path validation**: The RBAC probe verifies that expected operations succeed, confirming that policy misconfiguration has not accidentally over-denied legitimate access.

The Secret Access probe provides cross-namespace AC-3 validation by attempting to read Secrets in namespaces the probe SA has no permissions in, expecting HTTP 403 for all attempts.

**Per-component permission inventory**: Each Gauntlet component uses a pre-provisioned ServiceAccount with minimal RBAC. The controller SA cannot perform probe operations. Probe runner SAs cannot write CRDs. The detection probe SA has no Kubernetes API access.

An admission enforcement policy (`gauntlet-job-constraints`) prevents the controller from creating Jobs referencing any ServiceAccount other than the five pre-provisioned probe SAs, preventing privilege escalation through Job creation.

**Customer Responsibility:**

[Agency: Document the RBAC policies in place for the target namespaces Gauntlet probes.
Configure `GauntletProbe` resources with appropriate `targetNamespace` values.
Review probe Failures in the `GauntletIncident` log and remediate RBAC misconfigurations.]

---

### AC-4 — Information Flow Enforcement

**Gauntlet Implementation (Provided):**

The NetworkPolicy probe validates that the CNI enforcement plane is actively dropping traffic
that NetworkPolicy rules prohibit. Rather than inferring enforcement from TCP responses
(which are ambiguous between application-layer rejection and network-layer drop), Gauntlet
reads verdicts directly from the CNI observability API (e.g., Hubble for Cilium or Calico
flow logs). The CNI enforcement plane's verdict — `Dropped` or `Forwarded` — is the
authoritative source of whether the NetworkPolicy rule was enforced.

The probe generates a test flow with a unique probe-id label, then queries the CNI for the
flow record matching that probe-id. A `Forwarded` verdict where `Dropped` was expected
constitutes a Failure and generates a `GauntletIncident` with the control gap documented.

Gauntlet's own `gauntlet-system` namespace is protected by a default-deny NetworkPolicy.
The NetworkPolicy probe validates this policy continuously (tests 1–5 in the topology
validation section of `compliance/diagrams/network-topology.md`).

**Customer Responsibility:**

[Agency: Configure `GauntletProbe` resources with target namespaces and flow paths to
test. Ensure the CNI observability API is accessible from `gauntlet-system`. Review
probe Failures and remediate NetworkPolicy gaps.]

---

### AC-6 — Least Privilege

**Gauntlet Implementation (Provided):**

Gauntlet enforces and continuously validates least privilege at two levels:

**Gauntlet-internal enforcement**: Five separate ServiceAccounts with non-overlapping minimal
RBAC, each scoped to exactly the operations required by that probe type. The admission
enforcement policy (`gauntlet-job-constraints`) prevents the controller from creating Jobs
that reference any other ServiceAccount, making privilege escalation through Job creation impossible even
if the controller is compromised.

**Cluster-wide validation**: The RBAC probe continuously tests that service accounts in target
namespaces cannot perform operations outside their intended scope. Failures surface as
`GauntletIncident` CRs with the offending RBAC binding identified.

**Customer Responsibility:**

[Agency: Review `GauntletIncident` records for AC-6 findings. Configure least-privilege
RBAC for the namespaces Gauntlet probes. Respond to RBAC Failure incidents within the
timeframes specified in your Incident Response Plan.]

---

### AC-12 — Session Termination

**Gauntlet Implementation (Provided):**

Probe runner Jobs use time-bound Kubernetes service account tokens with a maximum 1-hour
lifetime (`expirationSeconds: 3600`). The token is audience-restricted to the Kubernetes API
server; it cannot be reused for other services. When the token expires, all subsequent API
calls return 401 Unauthorized, terminating the session.

The probe runner container exits on completion (or on first API error). The Kubernetes TTL
controller deletes the Job and Pod after `ttlSecondsAfterFinished`. There is no persistent
session state.

The Secret Access probe validates that expired tokens are correctly rejected by the API server
by confirming that requests with expired credentials receive 401, not 200.

**Customer Responsibility:**

[Agency: No additional agency action required for Gauntlet's own sessions. Document token
expiry policy for service accounts in target namespaces if those are in scope for this SSP.]

---

## 11. Audit and Accountability (AU)

### AU-2 / AU-3 / AU-12 — Audit Events and Content

**Gauntlet Implementation (Provided):**

Gauntlet generates two classes of audit records on every probe execution:

**Tier 1 — Operational status** (mutable): `GauntletProbe.status` subresource stores the
last N results and consecutive failure count. This tier supports real-time dashboards and
alerting but is not the authoritative audit record.

**Tier 2 — Audit log** (append-only): `GauntletProbeResult` CRs are created by the Result
Reconciler and enforced as append-only by the admission enforcement policy
(`gauntlet-proberesult-immutable`). Once created, a ProbeResult cannot be modified or deleted during its TTL
window. Each record contains:

| Field | Content |
|---|---|
| `probe.id` | UUID — unique per execution; correlation key across all audit systems |
| `probe.type` | `rbac`, `netpol`, `admission`, `secret`, `detection` |
| `probe.targetNamespace` | Namespace under test |
| `result.outcome` | `Pass`, `Fail`, `Undetected`, `Indeterminate`, `TamperedResult` |
| `result.nistControls` | NIST control identifiers validated by this execution |
| `result.integrityStatus` | `Verified` or `TamperedResult` |
| `execution.timestamp` | RFC 3339 UTC with nanosecond precision |
| `audit.exportStatus` | `Exported`, `Pending`, `Failed` |

All audit events are additionally recorded in the Kubernetes audit log at RequestResponse level
by virtue of the API calls Gauntlet makes. The Kubernetes audit log is external to the Gauntlet
boundary and governed by the cluster ATO.

**Customer Responsibility:**

[Agency: Configure Kubernetes audit logging at RequestResponse level for the
`gauntlet-system` namespace. Ensure the SIEM export pipeline is configured and
`audit.exportStatus` for all ProbeResult records reaches `Exported`. Review any records
with `audit.exportStatus: Failed`.]

---

### AU-4 — Audit Log Storage Capacity

**Gauntlet Implementation (Provided):**

Gauntlet uses a two-tier storage architecture to prevent audit capacity exhaustion:

- **In-cluster** (etcd): `GauntletProbeResult` CRs are subject to a 365-day minimum TTL. After TTL expiry, the Kubernetes TTL controller reclaims storage. The `gauntlet-system` ResourceQuota limits the number of concurrent Jobs and related resources, preventing runaway probe execution from filling etcd.
- **Off-cluster SIEM** (authoritative long-term): All records are exported in real time. S3 export uses Object Lock in COMPLIANCE mode with a 3-year retention lock. Elasticsearch and Splunk retention is agency-configured (minimum 3 years for federal deployments).

Gauntlet does not purge audit records to manage storage — the two-tier architecture separates
the retention enforcement concern (SIEM, 3-year) from the operational view concern (etcd, 365-day).

**Customer Responsibility:**

[Agency: Ensure SIEM storage capacity is sized for 3-year retention of Gauntlet audit
records. Monitor `gauntlet_siem_export_failures_total` Prometheus metric. Configure
S3 bucket lifecycle policy and Object Lock if using S3 export.]

---

### AU-5 — Response to Audit Processing Failures

**Gauntlet Implementation (Provided):**

Gauntlet has two separate failure detection paths:

**SIEM export failure**: On any export failure, Gauntlet retries with exponential backoff
(5 seconds initial, up to 5 minutes maximum, 24-hour window). After consecutive failures:
1. `gauntlet_siem_export_failures_total` Prometheus metric increments
2. `GauntletSystemAlert` CR is created with `reason: SIEMExportDegraded`
3. If `audit.failClosedOnExportFailure: true`, probe scheduling halts

**etcd write failure**: On failure to write a `GauntletProbeResult` CR, the Result Reconciler
creates a `GauntletSystemAlert` with `reason: AuditWriteFailure` and suspends the probe surface.

All `GauntletSystemAlert` CRs require individual principal acknowledgment before the system
returns to normal operation. Acknowledgment is logged with the acknowledging principal's identity.

**Customer Responsibility:**

[Agency: Configure alerting on `GauntletSystemAlert` CRs. Document the response procedure
for `SIEMExportDegraded` alerts (see IRP). Determine whether `failClosedOnExportFailure`
should be `true` for your deployment (recommended for High systems).]

---

### AU-8 — Time Stamps

**Gauntlet Implementation (Provided):**

All `GauntletProbeResult` timestamps use RFC 3339 UTC format with nanosecond precision.
Go components use `time.Now().UTC()` which reads `CLOCK_REALTIME` from the Linux kernel.
Rust components use `chrono::Utc::now()` which also reads `CLOCK_REALTIME`. Both are
therefore accurate to within the node's NTP synchronization tolerance.

Gauntlet does not run its own NTP daemon — it relies on the cluster node NTP infrastructure.
An indirect NTP failure signal is available through JWT expiry: if a node's clock drifts
beyond token acceptance tolerance, Gauntlet's API calls will begin returning 401 errors,
which surface as `Indeterminate` outcomes and a `GauntletSystemAlert`.

**Customer Responsibility:**

[Agency: Configure NTP on cluster nodes per your agency policy. Document the NTP source(s)
and synchronization tolerance. Ensure NTP configuration is included in your cluster baseline
(CM-6).]

---

### AU-9 / AU-10 — Audit Record Protection and Non-Repudiation

**Gauntlet Implementation (Provided):**

**Integrity**: Every `GauntletProbeResult` record contains an `integrityStatus` field set by
HMAC verification. The HMAC key is derived per execution using HKDF from a root key held
in a Kubernetes Secret (KMS-encrypted at IL4/IL5). If the HMAC verification fails, the
`integrityStatus` is set to `TamperedResult` and a `GauntletSystemAlert` is created.

**Append-only enforcement**: The admission enforcement policy (`gauntlet-proberesult-immutable`)
intercepts all UPDATE and DELETE operations on `GauntletProbeResult` CRs and denies them.
This enforcement is independent of the controller — it operates at the Kubernetes admission
layer and cannot be bypassed by a compromised controller.

**Non-repudiation**: All image signatures are submitted to the Sigstore Rekor append-only
transparency log. Rekor provides an independently verifiable, append-only record of all
build and signing events. SIEM export events carry the probe-id UUID, creating a correlation
key across all audit systems.

**Customer Responsibility:**

[Agency: Protect the admission enforcement policies (e.g., Kyverno ClusterPolicy or OPA Constraint) from unauthorized modification. Ensure the
HMAC root Secret is encrypted with a KMS key (required for IL4/IL5). Monitor Rekor inclusion
proofs for all Gauntlet image versions deployed.]

---

### AU-11 — Audit Record Retention

**Gauntlet Implementation (Provided):**

| Storage Tier | Retention | Mechanism |
|---|---|---|
| In-cluster (etcd) | 365 days minimum | Kubernetes TTL controller; admission enforcement policy blocks premature deletion |
| S3 | 3 years | S3 Object Lock COMPLIANCE mode; WORM; cannot be shortened by any principal |
| Splunk | [Agency-configured] | [Agency: document Splunk index retention policy; minimum 3 years] |
| Elasticsearch | [Agency-configured] | [Agency: document index lifecycle policy; minimum 3 years] |

The S3 Object Lock COMPLIANCE mode is the most tamper-resistant storage tier. No AWS principal,
including root, can delete or shorten the retention lock during the lock period. This satisfies
the "tamper-proof" requirement for long-term audit storage.

**Customer Responsibility:**

[Agency: Set S3 Object Lock retention to minimum 3 years. Configure Splunk and Elasticsearch
retention policies. Document the retention policy in your Records Management program.]

---

## 12. Configuration Management (CM)

### CM-2 — Baseline Configuration

**Gauntlet Implementation (Provided):**

The authoritative baseline configuration for a Gauntlet deployment is the Helm `values.yaml`
committed in the agency's GitOps repository. The `values.schema.json` in the Helm chart
enforces schema constraints at deploy time, preventing out-of-range values.

Drift detection is continuous: Gauntlet's bootstrap verifier checks prerequisites on startup and
after each reconciliation cycle. Deviations from expected state generate `GauntletSystemAlert`
CRs. The Helm chart version and image digests present in the cluster are the operational
baseline record.

**Customer Responsibility:**

[Agency: Maintain the Helm values file in a Git repository. Document the approved baseline
in your Configuration Management Plan (see `compliance/plans/configuration-management-plan.md`).
Do not apply configuration changes outside the GitOps workflow.]

---

### CM-6 — Configuration Settings

**Gauntlet Implementation (Provided):**

The `values.schema.json` enforces the following critical configuration constraints:

| Parameter | Constraint | Rationale |
|---|---|---|
| `probe.intervalSeconds` | 300–86400 | Minimum 5 min; maximum 24 hr |
| `audit.retentionDays` | ≥ 365 | Minimum retention floor |
| `tls.required` | Must be `true` | Disabling TLS is not a valid configuration |
| `global.dryRun` | Default: `true` | Live execution requires explicit opt-in |
| `global.fips` | Default: `true` on FIPS variant | FIPS cannot be disabled on FIPS images |

These constraints are enforced at Helm install and upgrade time by the schema validation
webhook, preventing drift from the approved security configuration.

**Customer Responsibility:**

[Agency: Review all `values.schema.json` parameters before deployment. Document approved
parameter values in the Configuration Management Plan. Do not override schema constraints
via `--set` flags outside the change control process.]

---

### CM-7 — Least Functionality

**Gauntlet Implementation (Provided):**

Gauntlet minimizes attack surface through four layers:

1. **Image composition**: Distroless or scratch base images; no shell, no package manager, no debug utilities; single-binary containers
2. **Disabled endpoints**: No debug endpoints, no profiling endpoints, no admin endpoints exposed outside the container; only `:8080` metrics and `:8081` health on the controller
3. **NetworkPolicy egress**: Per the NetworkPolicy specification, each component has exactly the egress paths needed and no others
4. **Pod security posture**: `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, all capabilities dropped (`securityContext.capabilities.drop: [ALL]`)

**Customer Responsibility:**

[Agency: Do not enable optional features (debug endpoints, profiling) in production.
Review the NetworkPolicy specification and confirm it is appropriate for your environment.]

---

### CM-8 — System Component Inventory

**Gauntlet Implementation (Provided):**

A Software Bill of Materials (SBOM) in CycloneDX format is generated for each Gauntlet
image at build time using `syft` (Go components) and `cargo cyclonedx` (Rust components).
SBOMs are cosign-attested and stored in the image registry alongside the image.

The SBOM can be retrieved for any deployed image:

```bash
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp 'https://github.com/primaris-tech/gauntlet' \
  <image>@<digest> \
  | jq '.payload | @base64d | fromjson | .predicate'
```

**Customer Responsibility:**

[Agency: Retrieve and archive SBOMs for all deployed Gauntlet image digests as part of
your component inventory. Configure your agency's SBOM tooling to ingest Gauntlet SBOMs.
Cross-reference SBOM contents against your approved software list.]

---

### CM-14 — Signed Components

**Gauntlet Implementation (Provided):**

All Gauntlet container images are signed with cosign using a KMS-backed signing key at
build time. The admission enforcement policy (`gauntlet-image-signature-required`) verifies
the cosign signature at every Pod admission — not once at deploy time, but on every scheduled
reconciliation and every new probe Job creation.

All signing events are published to the Sigstore Rekor transparency log. Rekor provides
an independently auditable, append-only record of every signing event, making signature
repudiation impossible.

**Customer Responsibility:**

[Agency: Ensure the admission enforcement policies are deployed and active before deploying Gauntlet.
For air-gapped environments, configure an internal Sigstore stack or use cosign's
`--insecure-skip-tlog-upload` with a documented exception. Do not disable signature
verification in production.]

---

## 13. Contingency Planning (CP)

See `compliance/plans/contingency-plan.md` for the full Contingency Plan.

**Recovery Objectives:**

| Metric | Target |
|---|---|
| Recovery Time Objective (RTO) | 4 hours |
| Recovery Point Objective (RPO) | Continuous (real-time SIEM export) |
| Maximum Tolerable Downtime (MTD) | 8 hours |

[Agency: Validate these targets against your agency's contingency planning requirements.
Complete the agency-specific sections of the Contingency Plan.]

---

## 14. Identification and Authentication (IA)

### IA-3 — Device Identification and Authentication

**Gauntlet Implementation (Provided):**

Gauntlet authenticates all external systems before establishing connections. Each external
system is authenticated through a combination of:

| System | Authentication Mechanism |
|---|---|
| Kubernetes API Server | Cluster CA-issued certificate; mTLS; SAN validation |
| Detection backend gRPC API (e.g., Falco) | mTLS client certificate or SPIFFE SVID; SAN-validated server cert |
| Detection backend gRPC API (e.g., Tetragon) | mTLS client certificate or SPIFFE SVID; SAN-validated server cert |
| CNI observability relay (e.g., Hubble) | mTLS client certificate or SPIFFE SVID; SAN-validated server cert |
| CNI observability API (e.g., Calico) | mTLS client certificate; SAN-validated server cert |
| Splunk HEC | TLS 1.2+ with SAN-validated server cert; HEC token |
| Elasticsearch | TLS 1.2+ with SAN-validated server cert; API key |
| S3 | TLS 1.2+ with SAN-validated server cert; AWS SigV4 |

SAN validation is required for all connections to prevent certificate substitution attacks.
`tlsInsecureSkipVerify` is not a supported configuration option.

For IL4/IL5 deployments, SPIFFE/SPIRE SVIDs (short-lived, automatically rotated) are
recommended over long-lived certificates for all gRPC connections.

**Customer Responsibility:**

[Agency: Issue and configure mTLS certificates for detection backend and CNI observability
layer connections. For SPIFFE/SPIRE, deploy a SPIRE server and configure the Gauntlet
workload registration. Execute ISA/MOU agreements for connections to separately-owned systems.]

---

### IA-7 — Cryptographic Module Authentication

**Gauntlet Implementation (Provided):**

Gauntlet's FIPS variant images use FIPS-validated cryptographic modules exclusively:

- **Go components**: BoringCrypto (CMVP Certificate #3678). Go's `crypto/tls`, `crypto/hmac`, `crypto/sha256`, and related packages automatically route to BoringCrypto when built with the `boringcrypto` build tag. Any call to a non-FIPS-approved algorithm causes an immediate process panic.

- **Rust detection probe**: aws-lc-rs (CMVP Certificate #4816). A compile-time algorithm allow-list ensures only FIPS-approved algorithms are callable. FIPS Known Answer Tests (KATs) execute at process initialization; failure causes an immediate `process::exit(1)`.

Both failure modes surface as `Indeterminate` probe outcomes and a `GauntletSystemAlert`,
preventing silent FIPS compliance degradation.

**Customer Responsibility:**

[Agency: Deploy FIPS image variants (identified by `-fips` image tag suffix and distinct
digest). Validate CMVP certificates are current for the deployed version.
Set `global.fips: true` in Helm values.]

---

### IA-8 — Identification and Authentication (Non-Organizational Users)

**Gauntlet Implementation (Provided):**

External systems that connect to Gauntlet (inbound connections) are authenticated at the
admission layer:

- **Admission controller webhook**: Gauntlet's controller presents a TLS certificate issued by the cluster CA. The admission controller verifies this certificate before sending admission requests. Gauntlet verifies the admission controller's client certificate in return (mTLS).
- **Prometheus scrape**: Gauntlet exposes `:8080/metrics` only on a ClusterIP-bound interface. Prometheus authentication is governed by the monitoring namespace's configuration.

All inbound connections are restricted by NetworkPolicy to the specific source namespaces
listed in section 5.1. Inbound connections from unlisted sources are dropped at the
network layer before reaching Gauntlet components.

**Customer Responsibility:**

[Agency: Configure Prometheus authentication per your monitoring namespace policy.
Ensure NetworkPolicy source restrictions match your actual monitoring namespace labels.]

---

## 15. Incident Response (IR)

See `compliance/plans/incident-response-plan.md` for the full Incident Response Plan.

### Gauntlet-Generated IR Artifacts

When a probe Fails, Gauntlet automatically creates a `GauntletIncident` CR. This CR contains:
- The failing control identifier (NIST control)
- The MITRE ATT&CK technique identifier
- The probe execution timestamp and probe-id
- A structured description of the control gap

IR teams can query incidents:

```bash
kubectl get gauntletincidents -n gauntlet-system --sort-by=.metadata.creationTimestamp
```

**Customer Responsibility:**

[Agency: Configure IR webhook in `ir.webhook.url`. Document IR procedures in the
Incident Response Plan (see `compliance/plans/incident-response-plan.md`). Train IR staff
on `GauntletIncident` interpretation and response procedures.]

---

## 16. Risk Assessment (RA)

[Agency: Document the risk assessment process for the system that Gauntlet is monitoring.
Note that Gauntlet generates continuous evidence of control effectiveness that can be used
to update the risk posture and POA&M status in near-real-time.]

**Risk posture benefit**: Each probe Failure generates a `GauntletIncident` that directly
maps to one or more NIST 800-53 controls. These incidents can be imported directly into
the agency's risk management tooling as documented control findings, with timestamps,
probe-ids, and NIST control identifiers for full traceability.

---

## 17. Security Assessment and Authorization (CA)

### CA-2 — Control Assessments

**Gauntlet Implementation (Provided):**

Gauntlet is the continuous assessment infrastructure for the controls it covers. For each
probe surface, Gauntlet produces `GauntletProbeResult` records that map directly to OSCAL
`assessment-results` finding structures:

| OSCAL Field | Gauntlet Source |
|---|---|
| `finding.title` | Probe type + outcome |
| `finding.related-observations[].collected` | `execution.timestamp` |
| `finding.target.status.state` | Satisfied / Not-Satisfied |
| `finding.related-risks` | `GauntletIncident` reference (on Failure) |

For an annual Assessment and Authorization cycle, Gauntlet's SIEM export provides the
assessor with a complete chronological record of control effectiveness for the assessment period.
The assessor does not need to conduct point-in-time control tests for controls covered by Gauntlet
— the continuous record replaces them.

**Assessment independence**: The controller cannot produce a falsified probe result through
direct API manipulation. The probe runner executes the actual operation; the controller only
reads the HMAC-signed result. A falsification requires defeating both the probe runner
execution *and* HMAC verification — two independent mechanisms.

**Customer Responsibility:**

[Agency: Provide Gauntlet SIEM records to the assessor as evidence for covered controls.
Run `kubectl get gauntletproberesults -n gauntlet-system -o yaml` to export in-cluster records
for the assessment period. Reference probe-ids in the SAR for full traceability.]

---

### CA-7 — Continuous Monitoring

**Gauntlet Implementation (Provided):**

Gauntlet is the continuous monitoring mechanism for the controls it covers. Probes execute
on configurable schedules (default: every 6 hours) with ±10% jitter to prevent predictable
timing gaps. Any probe Failure immediately creates a `GauntletIncident` and (via IR webhook)
alerts the monitoring team.

The continuous monitoring strategy is documented in section 21 below.

---

### CA-8 — Penetration Testing

**Gauntlet Implementation (Provided):**

The Detection Coverage probe constitutes continuous automated penetration testing of the
detection layer. Each execution emits a known adversarial syscall pattern (drawn from the
AO-approved technique catalog) and verifies that the detection backend (e.g., Falco or Tetragon) raises an alert within
60 seconds.

**AO authorization is mandatory**: Before any detection probe executes, the controller verifies
that an active `GauntletAOAuthorization` CR exists, signed by the AO, covering the requested
technique and namespace, and not yet expired. This ensures every detection probe execution
has been explicitly authorized by the Authorizing Official.

Example authorization CR:

```yaml
apiVersion: gauntlet.io/v1alpha1
kind: GauntletAOAuthorization
metadata:
  name: ao-authorization-q1-2026
  namespace: gauntlet-system
spec:
  aoName: "[Agency: AO Name and Title]"
  authorizedTechniques:
    - T1611  # Escape to Host
    - T1059  # Command Execution
  authorizedNamespaces:
    - production
    - staging
  validFrom: "2026-01-01T00:00:00Z"
  expiresAt: "2026-04-01T00:00:00Z"
  justification: "Quarterly detection coverage validation per CA-8"
```

**Customer Responsibility:**

[Agency: Create a `GauntletAOAuthorization` CR for each detection probe authorization period.
Document the authorization in the POA&M. Review `Undetected` outcomes and create detection
rules for gaps. Coordinate with the security operations team before enabling detection probes.]

---

## 18. System and Communications Protection (SC)

### SC-7 — Boundary Protection

**Gauntlet Implementation (Provided):**

The `gauntlet-system` namespace operates under a default-deny NetworkPolicy for both ingress
and egress. All traffic is explicit allowlist-based (section 5.1).

The NetworkPolicy probe continuously validates that this boundary is being enforced by the CNI.
The five reference test flows in `compliance/diagrams/network-topology.md` are executed on
each probe cycle. A `Forwarded` verdict where `Dropped` was expected constitutes a Failure.

Gauntlet has no LoadBalancer, NodePort, or HostNetwork services. No ports below 1024 are
opened by any Gauntlet component.

**Customer Responsibility:**

[Agency: Confirm CNI NetworkPolicy enforcement is enabled. Configure `GauntletProbe`
resources to test the specific flow paths relevant to your deployment. Review Forwarded
verdict incidents promptly.]

---

### SC-8 — Transmission Confidentiality and Integrity

**Gauntlet Implementation (Provided):**

All Gauntlet network transmissions use TLS 1.2 or higher with FIPS-approved cipher suites:

| Connection | Protocol | Cipher Constraint |
|---|---|---|
| Controller → Kubernetes API | mTLS | FIPS cipher suites (BoringCrypto) |
| Controller → Detection backend | gRPC/TLS | FIPS cipher suites (BoringCrypto) |
| Controller → CNI observability layer | HTTPS/TLS | FIPS cipher suites (BoringCrypto) |
| Controller → Splunk/Elasticsearch/S3 | HTTPS/TLS 1.2+ | FIPS cipher suites (BoringCrypto) |

In addition to transport-layer integrity, probe results are HMAC-signed before transmission
over any channel, providing integrity protection that is independent of the transport layer.
A tampered result is detectable even if the TLS channel is compromised.

**Customer Responsibility:**

[Agency: Confirm FIPS TLS cipher suites are enforced at the cluster level. For connections
to externally-operated systems (Splunk, S3), confirm the remote endpoint supports TLS 1.2+
with FIPS cipher suites.]

---

### SC-12 / SC-13 — Key Management and Cryptographic Protection

**Gauntlet Implementation (Provided):**

**Key categories and lifecycle:**

| Key Type | Algorithm | Lifetime | Rotation |
|---|---|---|---|
| HMAC per-execution key | HKDF-SHA256 | Single probe execution | Automatic (per execution) |
| mTLS certificates | ECDSA P-256 or RSA 2048 | ≤ 1 year | Manual (or SPIFFE/SPIRE automatic) |
| cosign signing key | ECDSA P-256 | ≤ 2 years | Manual (KMS rotation procedure) |
| HMAC root key (envelope) | AES-256-GCM (KMS) | Indefinite | [Agency: per rotation schedule] |

All cryptographic operations use FIPS-validated modules (BoringCrypto #3678, aws-lc-rs #4816).
The cosign signing key is stored in a KMS HSM; it is never in plaintext outside the HSM.

**Customer Responsibility:**

[Agency: Configure KMS encryption for the HMAC root Secret (required for IL4/IL5).
Establish a key rotation schedule for mTLS certificates. Follow the 6-step cosign key
rotation procedure in the CM-12 control implementation when rotating the signing key.
Ensure KMS key policies allow access only from the `gauntlet-system` namespace SA.]

---

## 19. System and Information Integrity (SI)

### SI-2 — Flaw Remediation

**Gauntlet Implementation (Provided):**

CVE scanning is integrated into the Gauntlet CI pipeline using Trivy. All images are scanned
on every build. New CVEs in deployed digests trigger automated alerts through the SBOM
monitoring pipeline.

| Severity | CI Gate | Remediation SLA |
|---|---|---|
| Critical | Blocks build | 30 calendar days |
| High | Blocks build | 60 calendar days |
| Medium | Warning (non-blocking) | 90 calendar days |
| Low / Informational | Tracked | Best effort |

Patching is done by building a new image with the updated dependency and rotating to the
new digest through the standard CM-3 change control process.

**Customer Responsibility:**

[Agency: Monitor CVE advisories for all Gauntlet image digests deployed. Maintain contact
with the Gauntlet project for security patch notifications. Comply with SLA timelines for
deployment of patched images.]

---

### SI-6 — Security and Privacy Function Verification

**Gauntlet Implementation (Provided):**

Gauntlet verifies its own security functions through a bootstrap verification checklist on
startup and through continuous self-probing:

**Bootstrap verification** (at startup and after each significant change):
1. All probe ServiceAccounts are present with expected RBAC
2. Admission enforcement policies are active (signature verification, append-only, Job constraints)
3. NetworkPolicy is in place with default-deny
4. HMAC root Secret is accessible
5. Detection backend(s) are reachable (if configured)

Any bootstrap verification failure creates a `GauntletSystemAlert` and blocks probe scheduling.

**Continuous verification**: Each probe cycle validates security functions for the probe surface
covered. Probe Failures are immediate findings requiring response.

**Customer Responsibility:**

[Agency: Configure alerting on `GauntletSystemAlert` CRs. Do not acknowledge alerts without
investigating the underlying condition. Review probe Failures within the response timeframes
in the Incident Response Plan.]

---

### SI-14 — Non-Persistence

**Gauntlet Implementation (Provided):**

Probe runner Jobs are strictly non-persistent:

- **Immutable image**: pinned by digest; read-only root filesystem
- **No environment carryover**: each Job pod starts from a clean container state
- **Per-execution HMAC key**: derived fresh via HKDF for each execution; previous key material is deleted
- **Fresh SA token**: time-bound token issued for each Job; not shared between executions
- **No volume mounts**: no PersistentVolumeClaims; admission enforcement policy (`gauntlet-no-writable-pvc`) enforces this at admission
- **TTL cleanup**: Job, Pod, and result ConfigMap are all deleted after `ttlSecondsAfterFinished`

The detection probe is the strictest posture: no network, no mounts, no credentials, custom
seccomp profile blocking filesystem writes beyond the initial binary execution.

**Customer Responsibility:**

[Agency: Confirm `ttlSecondsAfterFinished` is set to an appropriate value (default: 3600).
Confirm the admission enforcement policy (`gauntlet-no-writable-pvc`) is active before deploying Gauntlet.]

---

## 20. Supply Chain Risk Management (SR)

### SR-3 / SR-4 / SR-9 / SR-11 — Supply Chain Controls

**Gauntlet Implementation (Provided):**

Gauntlet implements a full software supply chain security stack:

| Control | Mechanism |
|---|---|
| SR-3 (Supplier Controls) | Only Go stdlib + CNCF-vetted dependencies; automated dependency review in CI |
| SR-4 (Provenance) | SLSA Level 2 provenance attestations; cosign-attested SBOMs; Rekor transparency log |
| SR-9 (Tamper Resistance) | cosign image signing + admission controller verification; HMAC result signing; S3 Object Lock |
| SR-11 (Component Authenticity) | Image digest pinning (not tag); cosign signature verification at every Pod admission |

The complete provenance chain for any Gauntlet image:

```
Source commit (GitHub) → CI build (GitHub Actions) → Image digest → cosign signature
  → SLSA provenance attestation → CycloneDX SBOM attestation → Rekor inclusion → admission controller verification
```

Every step is independently verifiable and append-only in Rekor.

**Customer Responsibility:**

[Agency: Verify cosign signatures before deploying new Gauntlet image versions.
Retrieve and compare SLSA provenance attestations for all deployed digests.
Configure your container registry to require cosign verification for images in the
`gauntlet-system` namespace.]

---

## 21. Continuous Monitoring Strategy

### 21.1 Monitoring Cadence

| Control Family | Probe Surface | Default Frequency | SIEM Export |
|---|---|---|---|
| AC-3, AC-6 | RBAC probe | Every 6 hours ± 10% jitter | Real-time on execution |
| AC-4, SC-7 | NetworkPolicy probe | Every 6 hours ± 10% jitter | Real-time on execution |
| CM-7, SI-3 | Admission control probe | Every 6 hours ± 10% jitter | Real-time on execution |
| AC-3, IA | Secret access probe | Every 6 hours ± 10% jitter | Real-time on execution |
| SI-3, SI-4, CA-8 | Detection coverage probe | [Agency: per AO authorization period] | Real-time on execution |

[Agency: Adjust probe intervals based on your risk posture and operational tempo.
Intervals below 5 minutes are not supported by schema constraints.]

### 21.2 Key Monitoring Metrics

| Metric | Alert Threshold | Response |
|---|---|---|
| `gauntlet_probe_failures_total` | Any increment | IR ticket; see IRP |
| `gauntlet_siem_export_failures_total` | Any increment | SIEM team notification |
| `gauntlet_consecutive_failures` | ≥ 3 for any probe | Escalation per IRP |
| `GauntletSystemAlert` CR created | Any creation | Immediate ISSO notification |
| `GauntletIncident` CR created | Any creation | IR ticket within 1 hour |

### 21.3 Annual Review

The following items are reviewed annually or upon significant system change:

- Review all `GauntletProbe` configurations against current threat model
- Rotate mTLS certificates and HMAC root key if approaching expiry
- Update the `GauntletAOAuthorization` CR for the new fiscal year
- Validate FIPS module CMVP certificate status for deployed Gauntlet version
- Review and update the ISA/MOU agreements for all boundary connections

[Agency: Document the annual review process owner and schedule.]

---

## 22. Plan of Action and Milestones (POA&M)

[Agency: Import open `GauntletIncident` CRs into your POA&M system. Each incident includes
the NIST control identifier, MITRE technique, timestamp, and probe-id — sufficient
information to populate a POA&M entry without additional manual analysis.

The following is a template for a Gauntlet-sourced POA&M entry:

| Field | Source |
|---|---|
| Weakness ID | GauntletIncident `.metadata.name` |
| Weakness Name | GauntletIncident `.spec.controlId` + `.spec.mitreId` |
| Description | GauntletIncident `.spec.description` |
| Date Identified | GauntletIncident `.metadata.creationTimestamp` |
| Source Identifier | `Gauntlet Probe Runner` |
| Milestone | [Agency: enter remediation plan and date] |
| Status | Open until probe returns `Pass` for 3 consecutive cycles |

Close a POA&M item when `GauntletProbeResult` records show `Pass` for 3 consecutive executions
after the remediation action. The probe-id provides an audit trail linking the POA&M item to
the specific execution records that demonstrate closure.]

---

## 23. Approvals and Signatures

### System Owner

I certify that the information contained in this System Security Plan is accurate and that
the security controls described herein are implemented or planned as stated.

| Field | Value |
|---|---|
| Name | [Agency: Print name] |
| Title | [Agency: Title] |
| Organization | [Agency: Organization] |
| Signature | _____________________________ |
| Date | [Agency: Date] |

---

### Information System Security Officer (ISSO)

I have reviewed this System Security Plan and certify that it accurately reflects the
security posture of the system.

| Field | Value |
|---|---|
| Name | [Agency: Print name] |
| Title | [Agency: Title] |
| Signature | _____________________________ |
| Date | [Agency: Date] |

---

### Authorizing Official (AO)

I have reviewed this System Security Plan and grant Authority to Operate (ATO) for
the Gauntlet Continuous Security Control Validation Operator as documented herein.

| Field | Value |
|---|---|
| Name | [Agency: Print name] |
| Title | [Agency: Title] |
| Signature | _____________________________ |
| Date | [Agency: Date] |
| ATO Expiration | [Agency: Date — maximum 3 years from signature date] |

---

*This document was prepared using the Gauntlet ATO Documentation Package.
The OSCAL Component Definition (`compliance/trestle-workspace/component-definitions/gauntlet/component-definition.json`)
is the machine-readable source of record for all control implementations. In the event of
conflict between this SSP narrative and the OSCAL Component Definition, the OSCAL
Component Definition governs.*
