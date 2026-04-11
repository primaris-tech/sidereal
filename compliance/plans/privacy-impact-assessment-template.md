# Sidereal Privacy Impact Assessment Template

**Document Type**: PIA Template — NIST 800-53 PT Family  
**Baseline**: NIST SP 800-53 Rev 5 High  
**Status**: Template — Agency Completion Required  

---

## Instructions for Use

This template must be completed by the deploying agency's Privacy Officer
or designated privacy official before deploying Sidereal in an environment
where monitored workloads process Personally Identifiable Information (PII).

Sidereal itself does not process PII in its normal probe operations — it
monitors the security posture of Kubernetes infrastructure. However, probe
results and audit records capture metadata (namespace names, workload
identities, ServiceAccount names, timestamps, behavioral telemetry) that
may constitute PII depending on how workloads in monitored namespaces are
named and organized.

Complete each section below. Sections marked *[Agency]* require agency-specific
input. Sections with pre-filled content document Sidereal's built-in
privacy controls.

---

## Section 1: System Description and Data Inventory

### 1.1 System Overview

**System Name**: Sidereal Continuous Security Control Validation Operator  
**Deployment Context**: *[Agency: Describe the environment (IL level, agency, mission system)]*  
**System Owner**: *[Agency: Name and title]*  
**Privacy Officer**: *[Agency: Name and title]*  
**Date of Assessment**: *[Agency: Date]*  

### 1.2 Data Elements Collected by Sidereal

Sidereal audit records (`SiderealProbeResult`, `SiderealIncident`) contain
the following data elements:

| Data Element | Example | PII? | Basis |
|---|---|---|---|
| Namespace name | `production`, `hr-system` | Potentially | Namespace names may reflect organizational structure |
| Workload identity | `ServiceAccount/payroll-processor` | Potentially | SA names may reflect system function tied to individuals |
| Probe outcome | `Pass`, `Fail` | No | Technical result |
| Timestamp | `2026-04-10T14:32:01Z` | No | System event time |
| NIST control ID | `AC-3`, `SC-7` | No | Control reference |
| HMAC status | `Verified` | No | Integrity flag |
| Target API operation | `GET secrets/db-password` | Potentially | Resource names may reveal system function |
| Behavioral telemetry (detection probe) | Syscall patterns | No | Technical patterns only; no user content |

*[Agency: Review the data elements above in the context of your monitored
namespaces. If namespace names or workload identities can be linked to
individual persons, check the PII column.]*

### 1.3 Privacy Threshold Analysis

Answer the following questions to determine if a full PIA is required:

1. Do any namespaces monitored by Sidereal have names that identify
   individual persons (e.g., `user-john-smith`, `analyst-team-3`)?
   **[Agency: Yes / No]**

2. Do workload names or ServiceAccount names in monitored namespaces
   reference individual persons or their roles in ways traceable to
   specific individuals?  
   **[Agency: Yes / No]**

3. Is Sidereal deployed in an environment where individual user behavior
   is attributable (e.g., a system where each namespace corresponds to
   a specific user's workloads)?  
   **[Agency: Yes / No]**

**If any answer above is Yes**: A full PIA is required. Continue to Section 2.  
**If all answers are No**: Document the determination and retain this threshold
analysis. A full PIA may not be required, but this determination must be
reviewed annually and on any significant system change.

---

## Section 2: Privacy Risk Analysis

### 2.1 Data Collection Minimization

Sidereal collects the minimum metadata required to produce actionable ATO
evidence. It does not:
- Read Secret values (only verifies access control enforcement, not content)
- Capture network payload content (only flow verdicts)
- Record user authentication events (only ServiceAccount operations)
- Monitor individual user sessions

However, Sidereal does capture namespace and workload identity metadata
in every audit record, which may have privacy implications in some
deployment contexts.

### 2.2 Privacy Configuration Options

Sidereal provides the following Helm values to reduce PII collection in
audit records:

| Setting | Default | Effect |
|---|---|---|
| `privacy.redactNamespaceNames: true` | `false` | Replaces namespace names with opaque identifiers (e.g., `ns-a3f2`) in all probe results and SIEM exports |
| `privacy.redactWorkloadIdentities: true` | `false` | Replaces ServiceAccount and workload names with opaque identifiers |

**[Agency: Determine whether these settings should be enabled based on your
PIA findings. If PII is present, enabling both settings is recommended.]**

When redaction is enabled:
- The mapping between opaque identifiers and real names is stored as a
  Kubernetes Secret in `sidereal-system`, accessible only to the ISSO role
- Probe results are still actionable (a failure on `ns-a3f2` can be
  investigated using the mapping)
- SIEM records do not expose real names to SIEM operators without the mapping

### 2.3 Data Flow Inventory

*[Agency: Document the data flows for your specific deployment.]*

| Data Flow | Source | Destination | PII Elements | Protection |
|---|---|---|---|---|
| Probe results → etcd | Controller | sidereal-system namespace | Namespace names, workload identities | RBAC-restricted; append-only |
| Probe results → SIEM | Controller | [Agency SIEM] | As above (or redacted) | TLS 1.2+, FIPS cipher suites |
| Probe results → S3 | Controller | [Agency S3 bucket] | As above | SSE-KMS, object lock |
| SiderealIncident → IR webhook | Controller | [Agency IR system] | Namespace, workload identity | TLS, API credential |

### 2.4 Privacy Risk Register

*[Agency: Document identified privacy risks and mitigations here.]*

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Namespace names expose organizational structure | [Agency] | [Agency] | Enable `privacy.redactNamespaceNames: true` |
| SIEM operators can infer workload relationships | [Agency] | [Agency] | Enable `privacy.redactWorkloadIdentities: true`; restrict SIEM access |
| Audit records retained longer than necessary | Low | Medium | Implement SIEM retention policy; enforce in-cluster TTL |

---

## Section 3: Legal Authorities and Purpose

### 3.1 Legal Authority

*[Agency: Cite the legal authority under which Sidereal is deployed.]*

- FISMA (44 U.S.C. § 3554) — system security controls
- OMB Circular A-130 — federal information system security
- [Agency-specific authority]: *[Agency: Add here]*

### 3.2 Purpose Specification

Sidereal collects namespace and workload identity metadata for the following
specific, documented purpose:

**Security monitoring and ATO evidence generation** — to continuously verify
that security controls protecting federal information systems are operationally
effective, and to produce machine-readable evidence for use in Authority to
Operate packages and continuous monitoring reports under FISMA.

Audit records are not used for:
- Individual performance evaluation
- Employee monitoring unrelated to security posture
- Any purpose beyond security control validation and ATO evidence

### 3.3 System of Records Notice (SORN)

*[Agency: Determine whether a SORN is required for Sidereal audit records.]*

A SORN may be required if Sidereal audit records are retrieved by individual
identifier (e.g., ServiceAccount name traceable to a specific person).

**[Agency determination required: Yes / No / N/A — justify]**

---

## Section 4: Access and Use Limitations

### 4.1 Access Controls for Privacy-Sensitive Records

| Role | Access to Audit Records | Justification |
|---|---|---|
| `sidereal-audit-admin` | Read-only `SiderealProbeResult` | ATO evidence review; ISSO function |
| `sidereal-reader` | Read `SiderealProbe` and results | Operational monitoring |
| SIEM operators | Query SIEM records | Incident response and reporting |
| Cluster-admin | All resources | Restricted per agency privileged access policy |

The mapping between opaque identifiers and real names (when redaction is
enabled) is accessible only to the ISSO via a separately managed Secret.

### 4.2 Data Retention and Disposal

| Record Type | In-Cluster Retention | SIEM Retention | Disposal Method |
|---|---|---|---|
| `SiderealProbeResult` | 365 days minimum | 3 years minimum | Kubernetes TTL; SIEM retention policy |
| `SiderealIncident` | 365 days minimum | 3 years minimum | As above |
| Redaction mapping Secret | Duration of deployment | N/A | Kubernetes Secret deletion; KMS key retirement |

*[Agency: Confirm SIEM retention policy meets both AU-11 and privacy requirements.]*

---

## Section 5: Privacy Officer Determination

*[Agency: Complete this section with the Privacy Officer's determination.]*

**Privacy Officer**: ____________________________________  
**Date**: ____________________________________  
**Determination**: [ ] Full PIA required  [ ] PIA not required — basis documented above  
**Privacy controls required**:
- [ ] `privacy.redactNamespaceNames: true`
- [ ] `privacy.redactWorkloadIdentities: true`
- [ ] SORN required
- [ ] Other: ____________________________________

**Signature**: ____________________________________

---

## Section 6: Related Controls

- **PT-1** Privacy Policy — agency privacy program
- **PT-2** Authority to Process — Section 3 of this PIA
- **PT-3** Purpose Specification — Section 3.2 of this PIA
- **PT-4** Information in Public-Facing Content — not applicable (no public interface)
- **PT-5** Privacy Notice — *[Agency: Determine if users of monitored systems require notice]*
- **AU-3** Content of Audit Records — data elements in Sidereal audit records
- **AU-11** Audit Record Retention — retention requirements in Section 4.2
