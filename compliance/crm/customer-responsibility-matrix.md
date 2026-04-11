# Gauntlet Customer Responsibility Matrix
## NIST 800-53 Rev 5 — Configurable Baseline (High Default)

This matrix defines responsibility allocation for every applicable NIST 800-53 baseline
control between Gauntlet (the software) and the deploying agency. Agencies use this document
to understand their residual security obligations before beginning their ATO process.

Gauntlet's FIPS 199 impact level is operator-configurable (`global.impactLevel: high | moderate | low`). This CRM documents responsibilities at the High baseline. Agencies operating at Moderate or Low may find that some controls listed here are not required by their selected baseline — consult NIST SP 800-53B for baseline applicability.

Gauntlet supports multi-framework compliance mapping (`global.controlFrameworks`). While this CRM is organized by NIST 800-53, probe results can simultaneously map to CMMC, CJIS, IRS 1075, HIPAA, and NIST 800-171 via configurable crosswalk tables.

### Responsibility Key

| Code | Meaning |
|---|---|
| **G** | Gauntlet Implemented — Gauntlet fully satisfies this control through its design and operation |
| **S** | Shared — Both Gauntlet and the deploying agency share responsibility; see Notes for split |
| **C** | Customer Responsibility — The deploying agency is fully responsible |
| **I** | Inherited — Satisfied by the underlying Kubernetes platform or cloud provider |
| **N/A** | Not Applicable — This control does not apply to Gauntlet's operational context |

### Important Notes

- Controls marked **I** (Inherited) require the deploying agency to verify their Kubernetes
  platform and cloud provider satisfy these controls and document the inheritance in their SSP.
- Controls marked **S** (Shared) have a Notes column explaining the split. Agencies must
  document their portion of shared controls in their SSP.
- Control enhancements follow the same responsibility as the base control unless noted otherwise.

---

## AC — Access Control

| Control | Name | Responsibility | Notes |
|---|---|---|---|
| AC-1 | Policy and Procedures | S | Gauntlet provides RBAC role definitions and access design; agency writes and enforces access control policy |
| AC-2 | Account Management | S | Gauntlet defines roles and requires individual accounts; agency provisions, reviews, and deprovisions accounts per AC-2 procedures |
| AC-3 | Access Enforcement | G | Kubernetes RBAC enforced by Gauntlet's role definitions; probe results validate enforcement effectiveness |
| AC-4 | Information Flow Enforcement | G | NetworkPolicy probes continuously validate east-west traffic enforcement |
| AC-5 | Separation of Duties | S | Gauntlet provides technically separate roles (operator, approver, live-executor, audit-admin); agency policy must prohibit same individual holding conflicting roles |
| AC-6 | Least Privilege | G | Per-probe ServiceAccounts provisioned with minimum required RBAC; controller never holds probe-class permissions |
| AC-7 | Unsuccessful Logon Attempts | I | Kubernetes API server and platform authentication layer |
| AC-8 | System Use Notification | C | Agency configures system use notification banners per their policy |
| AC-9 | Previous Logon Notification | I | Kubernetes platform |
| AC-10 | Concurrent Session Control | I | Kubernetes platform |
| AC-11 | Device Lock | N/A | No interactive user sessions in Gauntlet's operational context |
| AC-12 | Session Termination | G | ServiceAccount token bound expiry configured to 1-hour maximum; sessions terminate automatically |
| AC-14 | Permitted Actions Without Identification | C | Agency defines any permitted unauthenticated actions in their environment |
| AC-16 | Security and Privacy Attributes | S | Gauntlet applies probe-id labels, NIST control tags, and multi-framework `controlMappings`; agency manages broader attribute policy |
| AC-17 | Remote Access | C | Agency controls remote access to Kubernetes management plane |
| AC-18 | Wireless Access | N/A | Not applicable to containerized operator deployment |
| AC-19 | Access Control for Mobile Devices | N/A | Not applicable |
| AC-20 | Use of External Systems | C | Agency governs external system use policy |
| AC-21 | Information Sharing | C | Agency governs information sharing agreements |
| AC-22 | Publicly Accessible Content | C | Agency governs public content policy |
| AC-23 | Data Mining Protection | N/A | Not applicable to Gauntlet's operational context |
| AC-24 | Access Control Decisions | I | Kubernetes RBAC decision engine |
| AC-25 | Reference Monitor | I | Kubernetes admission control layer |

---

## AT — Awareness and Training

| Control | Name | Responsibility | Notes |
|---|---|---|---|
| AT-1 | Policy and Procedures | C | Agency writes and enforces security awareness and training policy |
| AT-2 | Literacy Training and Awareness | C | Agency trains personnel |
| AT-3 | Role-Based Training | S | Gauntlet provides documentation on role responsibilities (CMP, IRP, RoB); agency conducts role-based training for Gauntlet operators |
| AT-4 | Training Records | C | Agency maintains training records |
| AT-6 | Training Feedback | C | Agency manages training program improvement |

---

## AU — Audit and Accountability

| Control | Name | Responsibility | Notes |
|---|---|---|---|
| AU-1 | Policy and Procedures | S | Gauntlet provides audit design and AU-12 event enumeration; agency writes audit policy and procedures |
| AU-2 | Event Logging | G | Gauntlet defines and generates all audit-relevant events per AU-12 enumeration in the engineering design |
| AU-3 | Content of Audit Records | G | All audit records include: outcome, `controlEffectiveness`, timestamp, probe ID, target namespace, multi-framework `controlMappings`, principal identity, HMAC verification status |
| AU-4 | Audit Log Storage Capacity | G | Configurable retention with impact-level-dependent minimums (365d High/Moderate, 180d Low); SIEM export provides long-term storage; in-cluster backup prevents capacity exhaustion |
| AU-5 | Response to Audit Processing Failures | G | Export failures surfaced as Prometheus metrics with alerting; retry with backoff; records never silently dropped |
| AU-6 | Audit Record Review, Analysis, and Reporting | S | Gauntlet exports structured records to SIEM (JSON, CEF, LEEF, Syslog, or OCSF format) and generates continuous monitoring reports via `gauntlet report` CLI; agency is responsible for review, analysis, and formal reporting procedures |
| AU-7 | Audit Record Reduction and Report Generation | G | Gauntlet provides built-in report generation: continuous monitoring summaries, POA&M generation, coverage matrices, and OSCAL-native evidence packages via `gauntlet report` CLI and optional `GauntletReport` CRD |
| AU-8 | Time Stamps | G | All audit records include RFC 3339 timestamps; time synchronization inherited from Kubernetes platform |
| AU-9 | Protection of Audit Information | G | HMAC signing of all results; admission enforcement policy enforces append-only GauntletProbeResult; TLS + payload signing on SIEM export; S3 object lock in COMPLIANCE mode |
| AU-10 | Non-Repudiation | G | Individual Kubernetes principals required for all security-sensitive actions; HMAC verification chain from probe execution to audit record |
| AU-11 | Audit Record Retention | S | Gauntlet enforces impact-level-dependent in-cluster TTL minimums (365d High/Moderate, 180d Low); agency configures SIEM for long-term retention (3yr High/Moderate, 1yr Low) per their AU-11 policy |
| AU-12 | Audit Record Generation | G | All components generate audit records; full event enumeration documented in engineering design |
| AU-13 | Monitoring for Information Disclosure | C | Agency monitors for unauthorized disclosure of audit data |
| AU-14 | Session Audit | I | Kubernetes API server audit logging |
| AU-15 | Alternate Audit Logging Capability | G | In-cluster GauntletProbeResult records serve as resilient backup if SIEM is unavailable |
| AU-16 | Cross-Organizational Audit Logging | C | Agency governs cross-organization audit sharing agreements |

---

## CA — Assessment, Authorization, and Monitoring

| Control | Name | Responsibility | Notes |
|---|---|---|---|
| CA-1 | Policy and Procedures | C | Agency writes assessment, authorization, and monitoring policy |
| CA-2 | Control Assessments | S | Gauntlet produces continuous multi-framework-mapped control evidence with `controlEffectiveness` normalization and automated assessment evidence packages (`gauntlet report evidence-package`); agency conducts formal control assessments using Gauntlet evidence as primary input |
| CA-3 | Information Exchange | S | Gauntlet documents all external connections with direction, data type, protocol, and security controls; agency executes required ISAs with each external system owner |
| CA-5 | Plan of Action and Milestones | S | Gauntlet generates GauntletIncident resources from control failures (in `enforce` execution mode) and provides automated POA&M generation via `gauntlet report poam`; agency manages formal POA&M process and tracks remediation |
| CA-6 | Authorization | C | AO authorization is the deploying agency's responsibility; detection probes require documented AO authorization referencing GauntletAOAuthorization CRD |
| CA-7 | Continuous Monitoring | G | Core Gauntlet capability; continuous probe execution with NIST-mapped results is the continuous monitoring implementation |
| CA-8 | Penetration Testing | S | Gauntlet detection probes require AO authorization per CA-8; agency conducts annual formal penetration testing as a separate activity |
| CA-9 | Internal System Connections | S | Gauntlet documents internal connections; agency documents full internal connection inventory in SSP |

---

## CM — Configuration Management

| Control | Name | Responsibility | Notes |
|---|---|---|---|
| CM-1 | Policy and Procedures | S | Gauntlet provides CMP; agency writes configuration management policy |
| CM-2 | Baseline Configuration | G | Helm values file is the documented configuration baseline; security-relevant values have defined defaults and valid ranges |
| CM-3 | Configuration Change Control | G | Security-relevant Helm value changes require gauntlet-security-override role; changes generate audit records exported to SIEM |
| CM-4 | Impact Analysis | S | Agency conducts impact analysis for Gauntlet changes; Gauntlet documents security-relevant configuration parameters to assist analysis |
| CM-5 | Access Restrictions for Change | G | gauntlet-security-override role restricts who can modify security-relevant configuration |
| CM-6 | Configuration Settings | G | Helm values schema defines valid configuration ranges; impact level cascades appropriate defaults; controller enforces settings (e.g., impact-level-dependent TTL floor) |
| CM-7 | Least Functionality | G | No debug endpoints, admin APIs, or unnecessary services; probe runners have no shell, no package manager |
| CM-8 | System Component Inventory | G | SBOM generated and published with each release; covers all Go/Rust dependencies, base images, and Helm chart dependencies |
| CM-9 | Configuration Management Plan | G | CMP document provided in compliance/plans/ |
| CM-10 | Software Usage Restrictions | C | Agency governs software licensing compliance |
| CM-11 | User-Installed Software | N/A | No user-installable software in Gauntlet's operational context |
| CM-12 | Information Location | C | Agency documents where Gauntlet data resides within their broader information architecture |
| CM-13 | Data Action Mapping | C | Agency maps data actions within their system boundary |
| CM-14 | Signed Components | G | All probe images signed with cosign; admission enforcement policy (e.g., Kyverno or OPA/Gatekeeper) verifies signatures before any Job is admitted |

---

## CP — Contingency Planning

| Control | Name | Responsibility | Notes |
|---|---|---|---|
| CP-1 | Policy and Procedures | S | Gauntlet provides CP document; agency writes contingency planning policy |
| CP-2 | Contingency Plan | G | Contingency plan provided in compliance/plans/ covering RTO (4 hours), RPO, backup, and recovery procedures |
| CP-3 | Contingency Training | C | Agency trains personnel on Gauntlet contingency procedures |
| CP-4 | Contingency Plan Testing | C | Agency conducts contingency plan testing on defined schedule |
| CP-6 | Alternate Storage Site | C | Agency provisions alternate storage for Gauntlet data per their CP |
| CP-7 | Alternate Processing Site | C | Agency provisions alternate processing per their CP |
| CP-8 | Telecommunications Services | C | Agency manages telecommunications redundancy |
| CP-9 | System Backup | S | Gauntlet provides Velero-based backup guidance for GauntletProbe configurations; agency executes and validates backups |
| CP-10 | System Recovery and Reconstitution | S | Gauntlet provides recovery procedures; agency executes and tests recovery |

---

## IA — Identification and Authentication

| Control | Name | Responsibility | Notes |
|---|---|---|---|
| IA-1 | Policy and Procedures | S | Gauntlet provides authentication design; agency writes IA policy |
| IA-2 | Identification and Authentication (Organizational Users) | S | Gauntlet requires individual (non-shared) accounts; agency provisions and manages identity lifecycle |
| IA-3 | Device Identification and Authentication | G | mTLS required for all external system connections; controller verifies backend identity before transmitting |
| IA-4 | Identifier Management | S | Gauntlet uses Kubernetes principal names as identifiers; agency manages identifier lifecycle per IA-4 |
| IA-5 | Authenticator Management | S | Gauntlet documents credential rotation requirements; agency manages credential lifecycle and rotation for backend integrations |
| IA-6 | Authentication Feedback | I | Kubernetes platform handles authentication feedback |
| IA-7 | Cryptographic Module Authentication | G | FIPS 140-2 validated cryptographic modules (BoringCrypto for Go, aws-lc-rs for Rust) |
| IA-8 | Identification and Authentication (Non-Organizational Users) | G | mTLS with certificate validation for all non-organizational system connections |
| IA-9 | Service Identification and Authentication | G | All backend service connections use mTLS with certificate pinning or CA trust anchor verification |
| IA-10 | Adaptive Authentication | C | Agency implements adaptive authentication at their identity provider layer |
| IA-11 | Re-Authentication | I | Kubernetes platform manages re-authentication on token expiry |
| IA-12 | Identity Proofing | C | Agency conducts identity proofing for Gauntlet operators per PS-2 position risk designations |

---

## IR — Incident Response

| Control | Name | Responsibility | Notes |
|---|---|---|---|
| IR-1 | Policy and Procedures | S | Gauntlet provides IRP template; agency writes incident response policy |
| IR-2 | Incident Response Training | C | Agency trains personnel on incident response procedures |
| IR-3 | Incident Response Testing | C | Agency tests incident response procedures on defined schedule |
| IR-4 | Incident Handling | S | Gauntlet generates GauntletIncident resources for control failures when `executionMode: enforce` (incidents are suppressed in `dryRun` and `observe` modes) and exports to configured IR webhook; agency handles incidents per their IRP |
| IR-5 | Incident Monitoring | S | Gauntlet tracks control failure incidents via GauntletIncident resources; agency monitors and tracks incidents in their IR system |
| IR-6 | Incident Reporting | S | Gauntlet generates incident records with mandatory reporting window configuration; agency executes required US-CERT/CISA reporting |
| IR-7 | Incident Response Assistance | C | Agency provides incident response assistance resources |
| IR-8 | Incident Response Plan | S | Gauntlet provides IRP template in compliance/plans/; agency customizes and maintains their IRP |
| IR-9 | Information Spillage Response | C | Agency manages information spillage response procedures |
| IR-10 | Integrated Information Security Analysis Team | C | Agency manages their security analysis team |

---

## MA — Maintenance

| Control | Name | Responsibility | Notes |
|---|---|---|---|
| MA-1 | Policy and Procedures | C | Agency writes maintenance policy |
| MA-2 | Controlled Maintenance | S | Agency conducts Gauntlet maintenance activities; Gauntlet provides upgrade procedures |
| MA-3 | Maintenance Tools | I | Inherited from platform |
| MA-4 | Nonlocal Maintenance | C | Agency governs nonlocal maintenance access |
| MA-5 | Maintenance Personnel | C | Agency manages maintenance personnel |
| MA-6 | Timely Maintenance | S | Gauntlet publishes critical patches within 30 days; agency schedules and applies patches |

---

## MP — Media Protection

| Control | Name | Responsibility | Notes |
|---|---|---|---|
| MP-1 through MP-8 | All Media Protection controls | C | Agency manages physical and digital media; Gauntlet has no physical media |

---

## PE — Physical and Environmental Protection

| Control | Name | Responsibility | Notes |
|---|---|---|---|
| PE-1 through PE-23 | All Physical and Environmental controls | I | Inherited from data center/cloud provider; agency verifies platform inheritance |

---

## PL — Planning

| Control | Name | Responsibility | Notes |
|---|---|---|---|
| PL-1 | Policy and Procedures | C | Agency writes planning policy |
| PL-2 | System Security Plan | S | Gauntlet provides pre-written SSP template with control implementations; agency customizes for their environment, personnel, and infrastructure |
| PL-4 | Rules of Behavior | S | Gauntlet provides RoB template in compliance/plans/; agency customizes and obtains signatures |
| PL-8 | Security and Privacy Architectures | S | Gauntlet provides system boundary, data flow, and architecture documentation; agency incorporates into their enterprise security architecture |
| PL-9 | Central Management | C | Agency manages centralized security control administration |
| PL-10 | Baseline Selection | S | Agency selects and documents applicable NIST 800-53 baseline; Gauntlet's `global.impactLevel` setting auto-tunes operational parameters to the selected baseline |
| PL-11 | Baseline Tailoring | C | Agency tailors baseline and documents in SSP |

---

## PS — Personnel Security

| Control | Name | Responsibility | Notes |
|---|---|---|---|
| PS-1 | Policy and Procedures | C | Agency writes personnel security policy |
| PS-2 | Position Risk Designation | C | Agency designates risk level for positions with Gauntlet access; gauntlet-operator, gauntlet-live-executor, gauntlet-approver positions are security-sensitive |
| PS-3 | Personnel Screening | C | Agency screens personnel per PS-2 risk designations |
| PS-4 | Personnel Termination | C | Agency deprovisions Gauntlet access on termination per AC-2 procedures |
| PS-5 | Personnel Transfer | C | Agency reviews and adjusts Gauntlet access on personnel transfer |
| PS-6 | Access Agreements | C | Agency obtains signed access agreements from all Gauntlet operators |
| PS-7 | External Personnel Security | C | Agency applies PS-7 requirements to contractors with Gauntlet access |
| PS-8 | Personnel Sanctions | C | Agency manages sanctions for policy violations |
| PS-9 | Position Descriptions | C | Agency includes Gauntlet responsibilities in position descriptions |

---

## PT — PII Processing and Transparency

| Control | Name | Responsibility | Notes |
|---|---|---|---|
| PT-1 | Policy and Procedures | C | Agency writes PII processing policy |
| PT-2 | Authority to Process PII | C | Agency documents legal authority to process any PII in Gauntlet audit records |
| PT-3 | Personally Identifiable Information Processing Purposes | S | Gauntlet documents what data probe results contain; agency determines PII applicability and documents processing purposes |
| PT-4 | Consent for PII Processing | C | Agency manages consent requirements |
| PT-5 | Privacy Notice | C | Agency provides privacy notices to affected individuals |
| PT-6 | System of Records Notice | C | Agency publishes SORN if applicable |
| PT-7 | Specific Categories of PII | C | Agency assesses special category PII applicability |
| PT-8 | Computer Matching Requirements | C | Agency manages computer matching compliance |

---

## RA — Risk Assessment

| Control | Name | Responsibility | Notes |
|---|---|---|---|
| RA-1 | Policy and Procedures | C | Agency writes risk assessment policy |
| RA-2 | Security Categorization | S | Agency categorizes Gauntlet per FIPS 199 and sets `global.impactLevel` accordingly; Gauntlet cascades appropriate defaults for the selected impact level |
| RA-3 | Risk Assessment | S | Gauntlet provides formal risk classifications for each probe type (detection: Medium, others: Low); agency conducts formal system-level risk assessment |
| RA-5 | Vulnerability Monitoring and Scanning | S | Gauntlet scans its own dependencies (Dependabot, Grype, Trivy) and publishes results with each release; agency scans running Gauntlet deployment per their RA-5 program |
| RA-7 | Risk Response | C | Agency manages risk response decisions |
| RA-9 | Criticality Analysis | C | Agency conducts criticality analysis for their Gauntlet deployment |

---

## SA — System and Services Acquisition

| Control | Name | Responsibility | Notes |
|---|---|---|---|
| SA-1 | Policy and Procedures | C | Agency writes system acquisition policy |
| SA-3 | System Development Life Cycle | S | Gauntlet follows a documented SDLC with security integrated throughout; agency manages their acquisition and deployment lifecycle |
| SA-4 | Acquisition Process | C | Agency manages software acquisition processes |
| SA-5 | System Documentation | G | This documentation package (engineering design, SSP template, CRM, supporting plans, diagrams) satisfies SA-5 |
| SA-8 | Security and Privacy Engineering Principles | G | Security-by-design throughout: least privilege, separation of duties, defense in depth, fail secure, audit everywhere |
| SA-9 | External System Services | S | Gauntlet documents all external system connections; agency governs external service agreements (ISAs, contracts) |
| SA-10 | Developer Configuration Management | G | Version-controlled Helm chart, signed releases, SBOM, Trestle-managed compliance artifacts |
| SA-11 | Developer Testing and Evaluation | G | CI/CD pipeline with automated security scanning, OSCAL validation, and schema compliance checks |
| SA-15 | Development Process, Standards, and Tools | S | Gauntlet documents development toolchain; agency verifies toolchain meets their acquisition standards |
| SA-16 | Developer-Provided Training | S | Gauntlet provides operator documentation; agency delivers training to operators |
| SA-17 | Developer Security and Privacy Architecture and Design | G | Engineering design document provides full security architecture rationale |
| SA-22 | Unsupported System Components | G | Dependabot and CI scanning flag unsupported/EOL dependencies; critical patching within 30 days |

---

## SC — System and Communications Protection

| Control | Name | Responsibility | Notes |
|---|---|---|---|
| SC-1 | Policy and Procedures | S | Gauntlet provides communications protection design; agency writes SC policy |
| SC-2 | Separation of System and User Functionality | G | Controller and probe runners are strictly separated; no user-facing functionality mixed with security functions |
| SC-3 | Security Function Isolation | G | Controller ServiceAccount cannot execute probes; probe runners cannot write their own results without HMAC verification |
| SC-4 | Information in Shared System Resources | G | GauntletProbeResult resources are namespace-scoped; results for one namespace not accessible to operators of another |
| SC-5 | Denial-of-Service Protection | S | Gauntlet applies ResourceQuota to gauntlet-system; agency provides platform-level DoS protection |
| SC-7 | Boundary Protection | G | NetworkPolicy probes continuously validate boundary enforcement; gauntlet-system NetworkPolicy enforces explicit egress rules |
| SC-8 | Transmission Confidentiality and Integrity | G | TLS 1.2+ with FIPS-approved cipher suites on all external connections; mTLS for backend integrations; payload signing for SIEM export |
| SC-10 | Network Disconnect | I | Kubernetes platform and underlying network infrastructure |
| SC-11 | Trusted Path | I | Kubernetes API server TLS |
| SC-12 | Cryptographic Key Establishment and Management | G | Full SC-12 key lifecycle documented: HSM/KMS generation, rotation schedule, revocation, destruction |
| SC-13 | Cryptographic Protection | G | FIPS 140-2 validated modules throughout (BoringCrypto, aws-lc-rs); all TLS restricted to FIPS-approved cipher suites |
| SC-17 | Public Key Infrastructure Certificates | S | Gauntlet uses certificates for mTLS; agency operates or selects the PKI/CA issuing certificates |
| SC-23 | Session Authenticity | G | mTLS for all backend sessions; probe Job identity verified via pod labels and HMAC |
| SC-24 | Fail in Known State | G | Degraded mode on admission policy absence; GauntletSystemAlert halts execution until acknowledged |
| SC-28 | Protection of Information at Rest | S | Gauntlet requires SSE-KMS for S3 and object lock in COMPLIANCE mode; agency configures etcd encryption for in-cluster data at rest |
| SC-39 | Process Isolation | I | Kubernetes container runtime isolation |
| SC-45 | System Time Synchronization | I | Kubernetes node time synchronization (NTP) |

---

## SI — System and Information Integrity

| Control | Name | Responsibility | Notes |
|---|---|---|---|
| SI-1 | Policy and Procedures | S | Gauntlet provides integrity design documentation; agency writes SI policy |
| SI-2 | Flaw Remediation | G | Dependabot + Grype/Trivy in CI; critical CVEs patched within 30 days, high within 90 days; images rebuilt and re-signed on remediation |
| SI-3 | Malicious Code Protection | S | Gauntlet probe images scanned in CI before signing; agency manages host-level and network-level malicious code protection |
| SI-4 | System Monitoring | G | Core Gauntlet capability; continuous active probing with execution jitter (SI-4 timing attack mitigation) and NIST-mapped results |
| SI-5 | Security Alerts, Advisories, and Directives | C | Agency monitors and acts on security advisories for their environment |
| SI-6 | Security and Privacy Function Verification | G | Probes continuously verify that security functions (RBAC, NetworkPolicy, Admission, Detection) are operating as intended |
| SI-7 | Software, Firmware, and Information Integrity | G | HMAC signing of probe results; cosign image signing; admission enforcement policy signature verification at admission; append-only audit records |
| SI-9 | Information Input Restrictions | G | Admission control probes validate input restriction enforcement; GauntletProbe spec validated at admission |
| SI-10 | Information Input Validation | G | Controller validates HMAC signatures and probe result format before accepting any result |
| SI-11 | Error Handling | G | All error conditions produce defined outcomes (TamperedResult, BackendUnreachable, NotApplicable); no silent failures |
| SI-12 | Information Management and Retention | G | Impact-level-dependent in-cluster retention enforced (365d High/Moderate, 180d Low); SIEM retention per impact level (3yr High/Moderate, 1yr Low) |
| SI-13 | Predictable Failure Prevention | S | Gauntlet provides degraded mode and GauntletSystemAlert; agency monitors and responds to degraded state |
| SI-14 | Non-Persistence | G | Probe Jobs are ephemeral (TTL-based cleanup); no persistent state in probe runners; result ConfigMaps cleaned up after controller reads |
| SI-15 | Information Output Filtering | G | Probe results contain only defined fields; no raw system data or unfiltered output in audit records |
| SI-17 | Fail-Safe Procedures | G | Controller fails safe to degraded mode (halts probe execution) on admission policy absence; probes fail to TamperedResult on HMAC verification failure |
| SI-18 | Personally Identifiable Information Quality Operations | S | Gauntlet provides redaction configuration options; agency determines PII applicability and enables redaction as needed |
| SI-19 | De-Identification | S | Gauntlet provides privacy.redactNamespaceNames and privacy.redactWorkloadIdentities; agency determines when de-identification is required |

---

## SR — Supply Chain Risk Management

| Control | Name | Responsibility | Notes |
|---|---|---|---|
| SR-1 | Policy and Procedures | S | Gauntlet provides supply chain design documentation; agency writes SCRM policy |
| SR-2 | Supply Chain Risk Management Plan | S | Gauntlet documents supply chain controls (signing, SBOM, digest pinning); agency writes formal SCRM plan |
| SR-3 | Supply Chain Controls and Processes | G | cosign image signing, SBOM generation, digest-pinned images, HSM/KMS key management, admission enforcement policy verification |
| SR-4 | Provenance | G | SBOM published with every release; cosign signatures provide cryptographic provenance chain |
| SR-5 | Acquisition Strategies, Tools, and Methods | C | Agency manages acquisition strategy for Gauntlet procurement |
| SR-6 | Supplier Assessments and Reviews | C | Agency assesses Gauntlet as a supplier per their SCRM program |
| SR-7 | Supply Chain Operations Security | C | Agency manages operational security of their supply chain |
| SR-8 | Notification Agreements | C | Agency manages notification agreements with suppliers |
| SR-9 | Tamper Resistance and Detection | G | HMAC result signing detects in-transit tampering; cosign verifies image integrity; admission enforcement policy prevents unsigned image execution |
| SR-10 | Inspection of Systems or Components | C | Agency conducts component inspection per their SCRM procedures |
| SR-11 | Component Authenticity | G | cosign signatures verified at admission for all probe images; no unsigned components admitted |
| SR-12 | Component Disposal | C | Agency manages disposal of hardware and media |

---

## Summary Totals

| Responsibility | Count |
|---|---|
| **G** — Gauntlet Implemented | ~65 |
| **S** — Shared | ~55 |
| **C** — Customer Responsibility | ~60 |
| **I** — Inherited | ~20 |
| **N/A** — Not Applicable | ~15 |

### Agency Residual Obligation Summary

The controls requiring the most significant agency effort are:

- **AT family** — All training and awareness controls are agency responsibility
- **PE family** — All physical/environmental controls are inherited from the platform
- **PS family** — All personnel security controls are agency responsibility
- **PT family** — PII assessment and privacy notice obligations are agency responsibility
- **Shared AU/CA/IR controls** — Agency must configure SIEM retention, execute ISAs, manage formal POA&M, and conduct mandatory incident reporting

The controls where Gauntlet provides the most complete implementation are:

- **AU-2, AU-3, AU-9, AU-10, AU-12** — Full audit trail with integrity protection
- **CA-7** — Continuous monitoring is Gauntlet's core capability
- **CM-2, CM-3, CM-5, CM-6, CM-7, CM-8, CM-14** — Full configuration management implementation
- **SC-7, SC-8, SC-12, SC-13** — Communications protection and cryptographic controls
- **SI-4, SI-6, SI-7, SI-14** — System monitoring and integrity verification
- **SR-3, SR-4, SR-9, SR-11** — Supply chain integrity controls
