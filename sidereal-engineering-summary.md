# Sidereal
### Kubernetes-Native Continuous Security Control Validation for Federal Systems

---

## Problem Statement

Federal systems operating under FISMA, FedRAMP, and NIST 800-53 are required to implement continuous monitoring of security controls. In practice, this requirement is largely unmet at the Kubernetes layer. Existing tools — Kubescape, kube-bench, Stratus Red Team, and similar — share a common architectural limitation: they test point-in-time state.

A cluster is not a static artifact. RBAC bindings, NetworkPolicies, admission webhooks, and runtime detection rules drift continuously as workloads are deployed, Helm charts upgraded, and configurations patched. The gap between the last scan and the present moment is precisely where real-world compromises occur — and where ATO evidence goes stale.

No existing open-source, cloud-native tool continuously and automatically validates that security controls are **operationally effective**, produces NIST 800-53 mapped audit records, and exports them to a SIEM for use as ATO evidence.

---

## Concept

Sidereal is a Kubernetes-native security operator purpose-built for Federal systems that must demonstrate continuous monitoring compliance under FISMA, FedRAMP, and NIST 800-53. It runs a continuous loop of targeted, low-impact security probes against a live cluster, produces NIST 800-53-mapped audit records for every execution, and exports them to a SIEM as evidence for ATO packages and continuous monitoring reports.

Probes are mapped to both the MITRE ATT&CK for Containers framework and specific NIST 800-53 controls, and cover the following control surfaces:

| Surface | What Is Validated |
|---|---|
| RBAC | ServiceAccount permission boundaries are enforced as intended |
| NetworkPolicy | East-west traffic restrictions are actively blocking unauthorized paths |
| Admission Control | Admission controller policies reject non-compliant workload specs, including privileged spec requests (`hostPID`, `hostPath`, capability additions) |
| Secret Access | Workloads cannot enumerate secrets outside their authorized namespace |
| Detection Coverage | Known-bad behaviors — including runtime privilege escalation attempts — trigger expected alerts in Falco/Tetragon |

The final surface — **detection layer validation** — is the most differentiated capability. Sidereal emits a known-bad probe, then queries the detection backend to verify an alert was actually raised. This closes the assumption gap that most security programs carry: that because a detection rule is configured, it is functioning.

---

## Applicable Federal Standards and Frameworks

Sidereal's design is shaped by the following federal information security standards. Every architectural decision — from HMAC result signing to append-only audit records to FIPS-only cryptography — traces directly to one or more of these requirements. This section maps which standards govern which aspects of the design.

### Governing Law and Policy

| Standard | What It Is | How It Shapes Sidereal |
|---|---|---|
| **FISMA** (Federal Information Security Modernization Act, 2014) | The governing law requiring federal agencies to implement information security programs. Mandates continuous monitoring and periodic assessments for all federal information systems. | Sidereal exists because FISMA requires continuous monitoring. Every probe execution produces evidence that satisfies FISMA's requirement to verify security controls are operationally effective on an ongoing basis — not just at annual assessment time. |
| **OMB Circular A-130** (Managing Information as a Strategic Resource) | OMB policy implementing FISMA. Requires agencies to implement risk-based information security programs and authorizes NIST to develop supporting standards. | Establishes the risk management framework that drives the ATO process Sidereal supports. Sidereal's probe results feed directly into the agency's risk posture by identifying control gaps in near-real-time. |

### NIST Special Publications (Primary)

| Standard | What It Is | How It Shapes Sidereal |
|---|---|---|
| **NIST SP 800-53 Rev 5** (Security and Privacy Controls for Information Systems and Organizations) | The catalog of security controls that federal systems must implement. Organized by control families (AC, AU, CA, CM, IA, SC, SI, SR, etc.). The High baseline is the most stringent. | The **primary design driver**. Sidereal targets the **High baseline** — every probe surface maps to specific 800-53 controls. Every `SiderealProbeResult` record carries `nistControls` tags. The 40 OSCAL control implementation narratives in `compliance/trestle-workspace/` document exactly how Sidereal satisfies each control. Key families and their influence: |
| | | — **AC** (Access Control): Drives the RBAC probe (AC-3, AC-6), Secret Access probe (AC-3, AC-4), NetworkPolicy probe (AC-4), and the per-probe ServiceAccount separation model (AC-6) |
| | | — **AU** (Audit): Drives the entire result storage architecture — append-only `SiderealProbeResult` CRs (AU-9), HMAC result signing (AU-10), SIEM export (AU-4, AU-11), 365-day retention floor (AU-11), fail-closed on export failure (AU-5) |
| | | — **CA** (Security Assessment): Drives continuous assessment as a first-class capability (CA-2, CA-7) and the detection probe's AO authorization requirement (CA-8 penetration testing) |
| | | — **CM** (Configuration Management): Drives Helm values as configuration baseline (CM-2), `values.schema.json` enforcement (CM-6), image signature verification (CM-14), SBOM generation (CM-8) |
| | | — **IA** (Identification and Authentication): Drives mTLS for all external connections (IA-3), FIPS cryptographic module authentication (IA-7), SAN validation (IA-8) |
| | | — **SC** (System and Communications Protection): Drives NetworkPolicy default-deny boundary (SC-7), TLS 1.2+ FIPS cipher suites on all transmissions (SC-8), HKDF key derivation (SC-12), BoringCrypto and aws-lc-rs FIPS module selection (SC-13) |
| | | — **SI** (System and Information Integrity): Drives bootstrap verification (SI-6), non-persistent probe runners (SI-14), CVE remediation SLAs (SI-2) |
| | | — **SR** (Supply Chain): Drives cosign image signing (SR-11), SLSA provenance (SR-4), CycloneDX SBOM (SR-4), Rekor transparency log (SR-9), admission-layer tamper detection (SR-9) |
| **NIST SP 800-53A Rev 5** (Assessing Security and Privacy Controls) | The assessment procedures companion to 800-53. Defines how to evaluate whether controls are implemented correctly and operating effectively. | Drives the SAP template (`compliance/sap/`). Every SAP test procedure maps to an 800-53A assessment objective. Sidereal's continuous probe execution replaces point-in-time assessment for covered controls — the assessor reviews the probe result record instead of re-running the tests manually. |
| **NIST SP 800-37 Rev 2** (Risk Management Framework) | Defines the RMF lifecycle: Categorize → Select → Implement → Assess → Authorize → Monitor. | Sidereal operates in the **Monitor** step. It produces the continuous monitoring evidence that keeps an ATO current between annual assessments. `SiderealIncident` CRs feed directly into POA&M entries for the **Assess** step. |
| **NIST SP 800-137** (Information Security Continuous Monitoring) | Defines the continuous monitoring strategy: what to monitor, how often, and how to respond to findings. | The **operational mandate** Sidereal fulfills. Probe scheduling intervals are tied to FIPS 199 impact level per 800-137 guidance (High: every 6 hours, Moderate: every 24 hours). The continuous monitoring strategy in the SSP template (`compliance/ssp/` section 21) documents Sidereal's monitoring cadence per control family. |
| **NIST SP 800-207** (Zero Trust Architecture) | Defines zero trust principles: verify explicitly, least privilege, assume breach. | Sidereal applies ZTA to itself — the controller is a protected resource with per-request authentication, explicit egress NetworkPolicy, and blast radius controls assuming controller compromise. The per-probe ServiceAccount model is least-privilege by design. |

### NIST Special Publications (Supporting)

| Standard | What It Is | How It Shapes Sidereal |
|---|---|---|
| **NIST SP 800-190** (Application Container Security Guide) | Container-specific security guidance covering image provenance, registry security, runtime protection, and orchestrator hardening. | Directly informs the probe image supply chain (cosign signing, digest pinning, distroless images), the container security posture (non-root, read-only FS, drop ALL caps, seccomp), and the detection probe's sandboxing requirements. |
| **NIST SP 800-171 Rev 3** (Protecting CUI in Nonfederal Systems) | Controls for protecting Controlled Unclassified Information (CUI) — required for DoD contractors. | Sidereal's control coverage overlaps substantially with 800-171 requirements. Agencies using Sidereal on CUI systems get continuous validation of 800-171 controls through the same probe mechanisms. |
| **NIST SP 800-218** (Secure Software Development Framework, SSDF) | Practices for secure software development lifecycle. | Governs Sidereal's own development practices: CI/CD pipeline with CVE scanning (Trivy, govulncheck), dependency management (Dependabot), SBOM generation, and SLSA provenance attestations. |

### FIPS Standards

| Standard | What It Is | How It Shapes Sidereal |
|---|---|---|
| **FIPS 140-2** (Security Requirements for Cryptographic Modules) | The federal standard for cryptographic module validation. Required for all cryptographic operations in federal systems. | Sidereal ships FIPS-only image variants. Go components use BoringCrypto (CMVP #3678). Rust detection probe uses aws-lc-rs (CMVP #4816). No non-FIPS codepath is reachable at runtime — a call to a non-approved algorithm causes an immediate process panic (Go) or compile-time rejection (Rust). KAT self-test failure → process exit → `Indeterminate` outcome → `SiderealSystemAlert`. |
| **FIPS 199** (Standards for Security Categorization) | Defines impact levels (Low, Moderate, High) based on confidentiality, integrity, and availability impact. | Sidereal's impact level is **operator-configurable** via Helm values (`global.impactLevel: high | moderate | low`). The selected impact level cascades defaults for probe scheduling cadence, audit retention minimums, and fail-closed behavior (see Configuration Management section). The Helm chart ships with `high` as the default, but agencies operating at Moderate or Low can select their baseline and receive tuned defaults without manual override of individual parameters. Detection probes are classified as Medium risk under FIPS 199 methodology regardless of the system impact level. |

### FedRAMP

| Standard | What It Is | How It Shapes Sidereal |
|---|---|---|
| **FedRAMP** (Federal Risk and Authorization Management Program) | The government-wide program for standardizing security assessment and authorization of cloud services. Builds on NIST 800-53 with additional FedRAMP-specific requirements. | Drives several specific requirements: 365-day minimum in-cluster audit retention (AU-11), 3-year SIEM retention, 30-day Critical CVE remediation SLA, OSCAL-formatted ATO artifacts, and the Customer Responsibility Matrix (`compliance/crm/`). Sidereal's Phase 1 compliance package is structured for a FedRAMP ATO. |

### DoD-Specific (IL4/IL5)

| Standard | What It Is | How It Shapes Sidereal |
|---|---|---|
| **DoD CC SRG** (Cloud Computing Security Requirements Guide) | DoD-specific requirements for cloud services at Impact Levels 2–6. IL4 and IL5 require FIPS 140-2, CAC/PIV authentication, and specific data handling controls. | Drives the KMS-encrypted HMAC root Secret requirement, the SPIFFE/SPIRE recommendation for workload identity at IL4/IL5, and the S3 Object Lock COMPLIANCE mode requirement for audit record immutability. |

### Other Frameworks

| Standard | What It Is | How It Shapes Sidereal |
|---|---|---|
| **MITRE ATT&CK for Containers** | Adversary behavior taxonomy specific to container environments. | Every `SiderealProbe` maps to a MITRE technique ID. The detection probe's approved syscall catalog is organized by ATT&CK technique. This mapping makes Sidereal's output directly usable in threat-informed defense reporting. |
| **OSCAL** (Open Security Controls Assessment Language) | NIST's machine-readable format for security control documentation. | Sidereal's ATO package uses OSCAL as the foundation format. The 40 control implementation narratives compile from Trestle markdown to OSCAL JSON. `SiderealProbeResult` records are structured to map to OSCAL `assessment-results` findings. |
| **SLSA** (Supply-chain Levels for Software Artifacts) | Framework for supply chain integrity, from Google. Levels 1–4. | Sidereal targets **SLSA Level 2** — each image has a provenance attestation linking it to the source commit and CI build run. Provenance is cosign-attested and Rekor-logged. |
| **Sigstore** (cosign, Rekor, Fulcio) | Open-source signing and transparency infrastructure for software supply chains. | cosign for image signing, Rekor for append-only transparency logging. These are the concrete tools implementing SR-4 (provenance), SR-9 (tamper resistance), SR-11 (authenticity), and CM-14 (signed components). |

### How Standards Map to Sidereal Components

| Sidereal Component | Primary Standards |
|---|---|
| Probe execution engine | NIST 800-53 (CA-2, CA-7, CA-8), NIST 800-137, FISMA |
| HMAC result integrity | NIST 800-53 (AU-9, AU-10, SR-9), FIPS 140-2 |
| Append-only audit log | NIST 800-53 (AU-4, AU-9, AU-11), FedRAMP |
| SIEM export pipeline | NIST 800-53 (AU-4, AU-5, AU-11), FedRAMP |
| Per-probe ServiceAccounts | NIST 800-53 (AC-3, AC-6), NIST 800-207 (ZTA) |
| Detection probe sandbox | NIST 800-53 (CA-8, SI-14), NIST 800-190 |
| Image signing + admission verification | NIST 800-53 (CM-14, SR-4, SR-9, SR-11), SLSA, Sigstore |
| FIPS cryptography | FIPS 140-2, NIST 800-53 (SC-13, IA-7) |
| NetworkPolicy boundary | NIST 800-53 (SC-7, AC-4), NIST 800-207 (ZTA) |
| OSCAL documentation | OSCAL, NIST 800-53A, FedRAMP |
| Helm values schema | NIST 800-53 (CM-2, CM-6) |

---

## Why Continuous Matters

NIST 800-137 (Information Security Continuous Monitoring) requires that security controls be monitored on an ongoing basis, not assessed periodically. Point-in-time scanning cannot satisfy this requirement, nor can it catch:

- A NetworkPolicy silently dropped by a Helm upgrade
- A ServiceAccount over-provisioned during a maintenance window
- An admission webhook disabled for debugging and never re-enabled
- An admission policy exception scoped broader than intended
- A Falco rule inadvertently suppressed by a configuration change

Each of these is an ATO evidence gap — a period where the system's actual security posture diverged from its documented controls. Sidereal surfaces these regressions in near-real-time and records them in an immutable, SIEM-exported audit trail.

---

## Deployment Profiles and Abstract Capabilities

Sidereal is opinionated about *what* security capabilities must be present — but flexible about *which tools* provide them. The operator selects a deployment profile that binds Sidereal's abstract capability requirements to the concrete tools installed in the cluster. Sidereal adjusts its policy templates, backend connections, and compliance documentation output accordingly.

### Abstract Capabilities

Sidereal requires five external capabilities. Each has a defined interface contract and one or more supported implementations.

| Capability | What Sidereal Needs | Interface Contract | Supported Implementations |
|---|---|---|---|
| **Admission Enforcement** | Enforce 4 policies at Pod/resource admission: image signature verification, audit record immutability, Job SA constraints, no writable PVC | Kubernetes admission webhook that evaluates and enforces policy rules shipped with the Sidereal Helm chart | Kyverno (ClusterPolicy), OPA/Gatekeeper (ConstraintTemplate + Constraint) |
| **Image Signature Verification** | Verify cosign signatures on all Sidereal container images before Pod admission | Subset of admission enforcement — the admission controller must support cosign signature verification | Kyverno (cosign verifyImages), Sigstore policy-controller, Connaisseur |
| **Detection Backend** | Query for alerts matching a probe-id label within a time window | `DetectionBackend` interface: `QueryAlerts(ctx, probeID, window) → ([]Alert, error)` | Falco gRPC output API, Tetragon gRPC event API |
| **CNI Observability** | Query for flow verdict (Dropped/Forwarded) matching a probe-id label | `NetworkPolicyBackend` interface: `QueryFlowVerdict(ctx, probeID, window) → (Verdict, error)` | Hubble gRPC (Cilium), Calico flow log API, TCP inference (built-in, no external dependency) |
| **SIEM Export** | Deliver structured JSON audit records to an external log store | `AuditExportBackend` interface: `Export(ctx, record) → error` | Splunk HEC, Elasticsearch, S3, generic webhook |

### Profile Selection

The Helm chart accepts a profile configuration that binds abstract capabilities to concrete tools:

```yaml
sidereal:
  profile:
    admissionController: kyverno | opa        # Which admission controller is installed
    signatureVerifier: kyverno | policy-controller  # How image signatures are verified
    detectionBackend: falco | tetragon | none  # Which detection backend is available
    cniObservability: hubble | calico | tcp-inference  # How NetworkPolicy enforcement is verified
    siemExport:
      - splunk                                 # One or more export targets
      - s3
```

Based on the profile selection:
- The Helm chart renders the correct admission policy templates (Kyverno ClusterPolicies or OPA ConstraintTemplates)
- The controller connects to the correct backend endpoints
- The bootstrap verifier checks for the correct CRDs and policy resources
- The `helm template` static manifest output contains only the resources for the selected profile

### Pre-Built Profiles

Sidereal ships six pre-built profiles covering the most common federal Kubernetes platforms. Each profile is fully documented, tested, and ships with a companion profile binding document in `compliance/profiles/`.

| Profile | Admission | Signature Verification | Detection | CNI Observability | Target Environment |
|---|---|---|---|---|---|
| `kyverno-cilium-falco` | Kyverno | Kyverno cosign | Falco gRPC | Hubble gRPC (cni-verdict) | Cilium-based clusters with Falco |
| `opa-calico-tetragon` | OPA/Gatekeeper | Sigstore policy-controller | Tetragon gRPC | Calico flow logs (cni-verdict) | Calico-based clusters with Tetragon |
| `kyverno-eks` | Kyverno | Kyverno cosign | Falco gRPC | tcp-inference | Amazon EKS with VPC CNI (no Hubble) |
| `opa-aks` | OPA/Gatekeeper | Sigstore policy-controller | Falco gRPC | tcp-inference | Azure AKS with Azure CNI |
| `kyverno-gke` | Kyverno | Kyverno cosign | Falco gRPC | tcp-inference | Google GKE with Dataplane V2 (Cilium-based but Hubble availability varies) |
| `opa-rke2` | OPA/Gatekeeper | Sigstore policy-controller | Tetragon gRPC | tcp-inference or responder | RKE2/k3s on-premises (Rancher ecosystem) |

### Profile Compatibility Matrix

Not every profile supports every capability at full fidelity. The following matrix documents what is available and what is degraded per profile, so an ISSO can immediately assess fit:

| Capability | kyverno-cilium-falco | opa-calico-tetragon | kyverno-eks | opa-aks | kyverno-gke | opa-rke2 |
|---|---|---|---|---|---|---|
| Admission enforcement | Full | Full | Full | Full | Full | Full |
| Image signature verification | Full | Full | Full | Full | Full | Full |
| RBAC probe | Full | Full | Full | Full | Full | Full |
| NetworkPolicy probe (cni-verdict) | Full | Full | — | — | Varies | — |
| NetworkPolicy probe (tcp-inference) | Available | Available | **Default** | **Default** | **Default** | **Default** |
| NetworkPolicy probe (responder) | Available | Available | Available | Available | Available | Available |
| Detection probe (Falco) | Full | — | Full | Full | Full | — |
| Detection probe (Tetragon) | — | Full | — | — | — | Full |
| Secret Access probe | Full | Full | Full | Full | Full | Full |
| Admission Control probe | Full | Full | Full | Full | Full | Full |

**Legend**: Full = authoritative evidence; **Default** = the default verification mode for this profile; Available = supported but not the default; — = not applicable for this profile; Varies = depends on cluster configuration.

The managed Kubernetes profiles (`kyverno-eks`, `opa-aks`, `kyverno-gke`) default to `tcp-inference` for NetworkPolicy verification because managed CNI offerings don't consistently expose flow verdict APIs. The `responder` mode is available as an upgrade path for higher-evidence NetworkPolicy validation on these platforms.

Custom profiles are supported by mixing any combination of supported implementations. The Helm chart validates that the selected combination is coherent (e.g., `cniObservability: hubble` requires Cilium to be installed).

### Profile and Compliance Documentation

The OSCAL control narratives, SSP, SAP, and diagrams reference abstract capabilities — not specific tools. Each deployment profile has a companion **profile binding document** that maps abstract capabilities to concrete tools with:
- Tool-specific policy YAML
- Port numbers and connection parameters
- SAP test commands (`kubectl` commands referencing the correct policy names)
- Evidence collection commands

The compiled ATO package for a specific deployment names the concrete tools (because that is what the assessor tests), but the *source* compliance documentation is maintainable across profiles.

---

## Implementation Stack

**Controller Manager** — Go, using kubebuilder and controller-runtime. Go is the de facto standard for Kubernetes operators; all Kubernetes client libraries, Prometheus instrumentation, and CNCF ecosystem integrations (Falco gRPC, Tetragon gRPC, Hubble API, Calico) have mature, first-class Go SDKs. The controller is compiled with BoringCrypto FIPS build tags (CMVP Certificate #3678) to ensure all cryptographic operations use FIPS 140-2 validated modules, required for FedRAMP and IL4/IL5 deployments.

**Probe Runner Binaries** — split by probe risk profile:

| Probe | Language | Rationale |
|---|---|---|
| RBAC | Go | Kubernetes API interactions; first-class k8s client support |
| NetworkPolicy | Go | Kubernetes API interactions + TCP; first-class k8s client support |
| Admission Control | Go | Kubernetes API interactions; first-class k8s client support |
| Secret Access | Go | Kubernetes API interactions; first-class k8s client support |
| Detection | Rust | Executes adversarial syscall patterns in sandboxed containers — highest-risk execution context; memory safety guarantees are critical; produces minimal, auditable binaries consistent with distroless/scratch image requirement |

Rust probe binaries use `aws-lc-rs` (CMVP Certificate #4816) with FIPS-validated implementations for any cryptographic operations. All TLS connections across all components are restricted to FIPS-approved cipher suites. The boundary is explicit: probe runners that make Kubernetes API calls are written in Go; probe runners that execute low-level system behavior are written in Rust.

---

## Architecture

- **Deployment model**: Kubernetes Operator (controller pattern), deployed via Helm
- **Probe execution**: Short-lived, immutable Kubernetes Jobs per probe execution — scoped ServiceAccount, TTL-based cleanup, non-root with read-only root filesystem
- **Probe taxonomy**: CRD-defined `SiderealProbe` resources, each mapping to a MITRE ATT&CK technique and specific NIST 800-53 controls
- **Outcomes**: Per-probe type; detection probes use an extended outcome set (see Detection Probe Verification below) — all outcomes exported as Prometheus metrics and written to the audit log
- **Prometheus metrics**: `sidereal_probe_executions_total` (counter; labels: probe_type, outcome, control_effectiveness), `sidereal_probe_failures_total` (counter; labels: probe_type), `sidereal_consecutive_failures` (gauge; labels: probe_type, target_namespace), `sidereal_siem_export_failures_total` (counter; labels: backend, export_format), `sidereal_hmac_verification_failures_total` (counter), `sidereal_probe_duration_seconds` (histogram; labels: probe_type), `sidereal_bootstrap_verification_status` (gauge; 1=passed, 0=failed), `sidereal_control_effectiveness` (gauge; labels: probe_type, target_namespace, control_effectiveness; value: count of probes in each state — enables real-time compliance posture dashboards)
- **Integrations**: Detection backends (detection validation), admission controllers (admission validation), CNI observability (NetworkPolicy verdict), Prometheus + Alertmanager (observability), SIEM export targets (audit export). See Deployment Profiles section for supported implementations.
- **Controller endpoints**: `:8080/metrics` (Prometheus), `:8081/healthz` and `:8081/readyz` (liveness/readiness), `:8443` (webhook callbacks). No other ports are opened. No LoadBalancer or NodePort Services are created.
- **Scheduling**: Configurable probe cadence per probe with minimum frequencies derived from the operator-selected FIPS 199 impact level (`global.impactLevel`). Default cadence floors — High: every 6 hours, Moderate: every 24 hours, Low: every 72 hours. The controller surfaces a compliance warning if configured cadence exceeds the floor for the declared impact level. Operators may set cadence tighter than their impact level requires (a Moderate system running at 6-hour cadence is valid); they may not set it looser without an explicit override and audit record. Probe execution time is randomized with ±10% jitter to prevent predictable blind spots (SI-4)
- **Last-run state**: Stored in `status.lastExecutedAt` on `SiderealProbe`, surviving controller restarts without re-executing probes that recently ran

---

## System Boundary and Data Flows

The following defines the Sidereal authorization boundary for ATO package purposes.

**Inside the boundary:**
- Controller Manager (Go operator)
- Probe Runner Jobs (ephemeral)
- `SiderealProbe`, `SiderealProbeResult`, `SiderealAOAuthorization`, `SiderealSystemAlert`, `SiderealIncident` CRDs
- `sidereal-system` namespace and all resources within it

**External systems (outside the boundary):**

| System | Port | Direction | Data | Security Controls |
|---|---|---|---|---|
| Kubernetes API Server | 443/TCP | Bidirectional | Job creation, CRD read/write | mTLS via kubeconfig, RBAC-scoped ServiceAccount |
| Falco gRPC API | 50051/TCP | Inbound (read) | Alert records | mTLS, SAN validation, egress NetworkPolicy |
| Tetragon gRPC API | 54321/TCP | Inbound (read) | Event records | mTLS, SAN validation, egress NetworkPolicy |
| Hubble Relay (Cilium) | 4245/TCP | Inbound (read) | Flow verdicts | mTLS, SAN validation, egress NetworkPolicy |
| Calico API | 5443/TCP | Inbound (read) | Flow records | mTLS, SAN validation, egress NetworkPolicy |
| Splunk HEC | 443/TCP | Outbound (write) | Audit records | TLS 1.2+ FIPS, HEC token, payload signing, egress NetworkPolicy |
| Elasticsearch | 443 or 9200/TCP | Outbound (write) | Audit records | TLS 1.2+ FIPS, API key, payload signing, egress NetworkPolicy |
| S3-compatible storage | 443/TCP | Outbound (write) | Audit records | TLS 1.2+ FIPS, SigV4, SSE-KMS, object lock (COMPLIANCE mode) |
| Admission controller | — | Inbound (enforces) | Admission decisions | Kubernetes admission webhook, no direct connection |

Each external connection crosses the Sidereal authorization boundary. Per NIST 800-53 CA-3, the deploying agency must execute an Interconnection Security Agreement (ISA) with the owner of each external system. Sidereal's design documents the connection parameters (direction, data type, protocol, security controls) required to complete those agreements — the agency executes them.

---

## Authentication for External Systems

Sidereal authenticates to all external systems using individual, rotatable credentials. No anonymous or shared credential access is permitted.

- **gRPC backends (Falco, Tetragon, Hubble)**: mTLS with client certificate issued to the controller's ServiceAccount. Certificate pinning or CA trust anchor verification required. Certificates rotated per IA-5 schedule.
- **SIEM endpoints (Splunk HEC, Elasticsearch)**: API keys stored in Kubernetes Secrets, not embedded in Helm values or container images. Rotated on a defined schedule per IA-5. The controller verifies the endpoint's TLS certificate before transmitting.
- **S3-compatible storage**: IAM role-based access (IRSA or equivalent) preferred over static credentials. If static credentials are required, stored in Kubernetes Secrets with defined rotation.
- **Kubernetes API**: ServiceAccount tokens with bound expiry. Recommended maximum token TTL: 1 hour for probe runner ServiceAccounts. Configured via `spec.serviceAccountTokenExpirationSeconds` on projected volume mounts.

For IL4/IL5 environments, SPIFFE/SPIRE is the recommended workload identity provider. SPIFFE-issued SVIDs replace ServiceAccount tokens for all workload-to-workload authentication, providing short-lived, automatically-rotated identity certificates aligned with NIST 800-207 Zero Trust principles.

---

## Zero Trust Architecture

Under NIST 800-207, Sidereal is itself a protected resource — not merely a security tool. A compromised controller holds ATO evidence, can create Jobs with adversarial capabilities, and has connections to detection and network enforcement backends. The following ZTA controls apply to Sidereal as a resource:

- All access to Sidereal APIs (CRD reads/writes) is authenticated per-request via Kubernetes RBAC. No persistent privileged sessions.
- Controller network access is restricted to explicitly defined endpoints via NetworkPolicy egress rules. No broad outbound access.
- All controller actions (probe scheduling, result recording, alert acknowledgment) are logged to the Kubernetes audit log and exported to the SIEM.
- Sidereal RBAC role assignments are reviewed quarterly by the ISSO. Access reviews are documented and retained as AU evidence.
- The blast radius controls (admission enforcement policies) protect the cluster from a compromised controller — a compromised controller cannot create Jobs with unauthorized ServiceAccounts or unsigned images.

---

## Account Management and RBAC Roles

All Sidereal operator accounts must be individual (not shared service accounts) to satisfy AU-10 non-repudiation requirements. The following roles are defined:

| Role | Permissions | Notes |
|---|---|---|
| `sidereal-reader` | Read `SiderealProbe`, `SiderealProbeResult` | View-only access to probe configuration and results |
| `sidereal-operator` | Read/write `SiderealProbe` | Configure probes; cannot enable live execution |
| `sidereal-live-executor` | Set `executionMode: observe` or `enforce` on `SiderealProbe` | Enabling live execution (observe or enforce); restricted role |
| `sidereal-approver` | Create `SiderealAOAuthorization` | Second-party authorization for detection probes |
| `sidereal-audit-admin` | Read `SiderealProbeResult` | Audit log access; cannot delete or modify records |
| `sidereal-security-override` | Modify security-relevant Helm values | Required for `global.requireAdmissionController: false` |

**Separation of duty for live execution**: Enabling live probes (`executionMode: observe` or `enforce`) requires the `sidereal-live-executor` role. Detection probe execution additionally requires a valid `SiderealAOAuthorization` resource (see Detection Probe Verification). The `sidereal-operator` and `sidereal-live-executor` roles are separate. Per AC-5, the SSP and access management policy must prohibit assigning both roles to the same individual — this is an administrative control enforced by the ISSO during account provisioning and verified through Kubernetes audit log review. Kubernetes RBAC provides the technical separation; organizational policy enforces the human separation.

Account provisioning, modification, and deprovisioning follow the deploying agency's AC-2 procedures, documented in the SSP.

---

## Probe Runner Model and Job Lifecycle

Each probe execution is a short-lived, immutable, scoped Kubernetes Job, not a long-running pod and not inline execution inside the controller-manager. The Job is born, performs exactly one action, and is garbage collected via TTL. The permission surface only exists for the duration of the execution.

```
Controller queues probe execution
  → Generates per-execution HMAC key, stores in a Job-scoped Secret
  → Creates a ProbeJob (Kubernetes Job) with:
       - Probe-specific ServiceAccount (least privilege, pre-provisioned)
       - Explicit namespace targeting
       - HMAC key injected via Secret volume mount
       - TTL after completion (auto-cleanup)
       - CPU and memory resource limits
       - Pod Security Standards: Restricted profile
           (runAsNonRoot: true, allowPrivilegeEscalation: false,
            seccompProfile: RuntimeDefault, readOnlyRootFilesystem: true,
            capabilities: drop ALL)
       - ServiceAccount token bound expiry: 1 hour maximum
       - No ServiceAccount token automount beyond minimum required
  → Probe runner performs action, signs result payload with HMAC key
  → Probe runner writes signed result to a result ConfigMap
  → Controller reads result ConfigMap, verifies HMAC signature
  → Controller rejects result if signature is invalid — records TamperedResult outcome
  → Controller writes SiderealProbeResult (append-only)
  → Job TTLs out and is garbage collected
```

The controller-manager holds a completely separate ServiceAccount with permissions only to create and watch Jobs and read/write `SiderealProbe` and `SiderealProbeResult` resources. It never holds probe-class permissions directly. If the controller is compromised, it cannot itself execute probes.

Result integrity is enforced end-to-end: the HMAC key is derived fresh per execution using HKDF-SHA256 with the probe ID as the info parameter, derived from a root key stored in a Kubernetes Secret (KMS-encrypted at IL4/IL5). The derived key is injected only into the specific Job via a tmpfs-mounted Secret volume, and verified by the controller before any result is trusted. A tampered result ConfigMap produces a detectable `TamperedResult` outcome rather than a falsified pass or fail.

---

## Admission Control Probe Design

The Admission Control probe validates that admission controller policies reject non-compliant workload specs. Before attempting a submission, the probe checks for the presence of a `ValidatingWebhookConfiguration` or `MutatingWebhookConfiguration`. If none is found, the outcome is `NotApplicable` — not `Pass`. Returning `Pass` when no admission webhook is installed would constitute a false positive ATO evidence record.

**`--dry-run=server` edge case**: Some admission webhooks are configured to skip dry-run requests. The probe detects this condition — if the API server response does not include evidence of webhook evaluation, the outcome is `Indeterminate` (not `Rejected`), preventing a false positive. The `SiderealProbeResult` detail field documents which webhooks were evaluated.

### Outcome State Machine

| Outcome | Meaning |
|---|---|
| `Rejected` | The known-bad spec was rejected by the admission webhook — policy is enforcing as intended |
| `Accepted` | The known-bad spec was accepted — admission control gap detected |
| `NotApplicable` | No ValidatingWebhookConfiguration or MutatingWebhookConfiguration detected — nothing to test |
| `BackendUnreachable` | The admission webhook endpoint could not be reached during probe execution |

### Known-Bad Spec: Default and Override

**Default (Option A) — Sidereal-shipped synthetic policy**
The Helm chart installs a lightweight admission policy (rendered for the configured admission controller — Kyverno ClusterPolicy or OPA Constraint) that rejects any resource carrying the label `sidereal.cloud/admission-probe: "true"`. The probe always submits a resource with this label. Sidereal controls both sides — the policy and the probe spec — making the test deterministic and requiring zero operator configuration.

**Override (Option B) — Operator-configured policy reference**
For federal environments with mandated policy sets, operators can override the default by specifying a target policy and a known-bad resource spec in `SiderealProbe`:

```yaml
spec:
  admissionProbe:
    targetPolicy: kyverno/disallow-privileged-containers
    knownBadSpec:
      apiVersion: v1
      kind: Pod
      spec:
        containers:
          - name: test
            image: scratch
            securityContext:
              privileged: true
```

When an override is configured, the Sidereal-shipped synthetic policy is not used. The probe submits the operator-specified spec and expects rejection by the referenced policy. This allows the probe to validate specific mandated controls directly, producing audit records that map to named policies in the system's security plan.

### Privileged Spec Category

Admission Control is also the validation layer for privilege escalation via spec — `hostPID: true`, `hostPath` mounts, `privileged: true`, and capability additions. These are spec-based escalation paths; if admission rejects them, escalation via that path is prevented. There is no separate Privilege Escalation probe surface — spec-based escalation is a category within the Admission Control probe, covered by the default Sidereal-shipped policy and configurable via operator override.

Runtime privilege escalation attempts from within an already-running container (syscall-based escape patterns, capability abuse) are covered by the Detection Coverage probe.

---

## NetworkPolicy Probe Design

The NetworkPolicy probe validates that east-west traffic restrictions are actively blocking unauthorized paths. Rather than inferring enforcement from connection success or failure (which requires a persistent responder and produces ambiguous results), Sidereal reads verdicts directly from the CNI's observability layer — the authoritative source of what the enforcement plane actually decided.

### Mechanism

The probe container sends a TCP SYN to a ClusterIP in the target namespace. This is a real packet from a real source IP, causing the CNI to make an actual policy decision. The controller then queries the CNI observability API for the flow record and reads the verdict.

This follows the same pattern as detection probes: **fire the action → read the verdict from the enforcement layer → correlate back to the probe**.

### Verification Modes

NetworkPolicy enforcement can be verified at three different levels of authoritativeness. The operator selects the verification mode based on the cluster's CNI and observability capabilities via the deployment profile (`cniObservability` setting).

**Mode 1: `cni-verdict`** (most authoritative)

Reads the enforcement decision directly from the CNI observability layer — the enforcement plane's own record of what it decided. This is the strongest evidence for ATO purposes because it eliminates ambiguity between application-layer behavior and network-layer enforcement.

- Requires: Cilium with Hubble enabled, or Calico with flow logging enabled
- The controller queries the CNI observability API for flow records matching the probe's `sidereal.cloud/probe-id` label
- Returns the CNI's own verdict: `Dropped` or `Forwarded`
- Evidence strength: **Authoritative** — the enforcement plane's decision record

**Mode 2: `tcp-inference`** (works on any CNI)

The probe sends a TCP SYN to the target and interprets the network behavior. No external observability dependency — this works on any Kubernetes cluster with NetworkPolicy support, including AWS VPC CNI, Azure CNI, and vanilla kube-proxy with a NetworkPolicy provider.

- The probe sends a TCP SYN and observes: connection timeout (inferred drop), connection refused/reset (inferred forward or host-level rejection), connection established (confirmed forward)
- Returns `InferredDropped` or `InferredForwarded` — distinct outcome values from the `cni-verdict` outcomes, so the assessor knows the evidence source
- Cannot distinguish NetworkPolicy drop from routing failure or unresponsive destination
- Evidence strength: **Behavioral** — the probe observed behavior consistent with enforcement, but cannot confirm the enforcement mechanism

**Mode 3: `responder`** (higher confidence than tcp-inference, broader blast radius)

Sidereal deploys a lightweight responder pod in the target namespace that always responds on a known port. The probe sends traffic to the responder. If the response arrives, traffic was forwarded. If it times out, it was dropped. This eliminates the "destination not running" ambiguity from tcp-inference.

- Requires: Sidereal must be able to create pods in the target namespace (expanded RBAC for the `sidereal-probe-netpol` ServiceAccount)
- The responder pod is ephemeral — created before the probe, deleted after, TTL-cleaned
- Returns `Dropped` or `Forwarded` (same outcome values as cni-verdict — the responder eliminates ambiguity)
- Cannot distinguish NetworkPolicy drop from a CNI bug, but can distinguish from routing/destination issues
- Evidence strength: **Reliable behavioral** — stronger than tcp-inference, weaker than cni-verdict

### Outcome State Machine

| Outcome | Verification Mode | Meaning |
|---|---|---|
| `Dropped` | cni-verdict, responder | CNI dropped the packet — NetworkPolicy is blocking as intended |
| `Forwarded` | cni-verdict, responder | CNI forwarded the packet — NetworkPolicy gap detected |
| `InferredDropped` | tcp-inference | Timeout observed — behavior consistent with NetworkPolicy drop |
| `InferredForwarded` | tcp-inference | Connection established — traffic was not blocked |
| `BackendUnreachable` | cni-verdict | CNI observability API could not be queried — enforcement cannot be verified |
| `Indeterminate` | tcp-inference, responder | Ambiguous result (e.g., connection reset — could be app or policy) |

Every `SiderealProbeResult` for a NetworkPolicy probe includes `spec.result.verificationMode` (`cni-verdict`, `tcp-inference`, or `responder`) so the assessor knows exactly what level of evidence the result represents.

### Alert Correlation

The probe Job pod carries the label `sidereal.cloud/probe-id: <uuid>`. In `cni-verdict` mode, CNI observability layers enrich flow records with Kubernetes pod metadata, causing this label to appear on the flow record. The controller queries for flow records matching the probe ID to establish correlation — identical to the detection probe correlation mechanism.

In `tcp-inference` and `responder` modes, correlation is implicit — the probe runner is the only entity generating the test traffic, and the result is returned directly by the probe.

### CNI Backend Interface

The controller uses a pluggable `NetworkPolicyBackend` interface:

```
NetworkPolicyBackend interface {
    QueryFlowVerdict(ctx, probeID string, window time.Duration) (Verdict, error)
}
```

Implementations:
- **Hubble** (Cilium) — queries the Hubble gRPC flow API for verdict on flows matching the probe pod label
- **Calico** — queries Calico flow log API for the matching flow record
- **TCP inference** (built-in) — sends TCP SYN directly from the probe runner; no external dependency
- **Responder** (built-in) — deploys ephemeral responder pod; sends TCP SYN; cleans up responder

---

## Detection Probe Verification

Detection probes follow a distinct lifecycle from other probe types, because the outcome being validated is not whether an action was blocked, but whether the detection pipeline observed and alerted on it.

### AO Authorization Requirement

Detection probes deliberately emit adversarial syscall patterns against a live federal system. Under NIST 800-53 CA-2 and CA-8, this constitutes active security testing and requires explicit Authorization Official (AO) authorization before execution.

Every `SiderealProbe` of type Detection must reference a `SiderealAOAuthorization` resource via `spec.aoAuthorizationRef`. Detection probe Jobs are not created if the referenced authorization is missing or expired. The `SiderealAOAuthorization` resource captures:

| Field | Type | Description |
|---|---|---|
| `spec.aoName` | string (required) | Named individual AO (not a role or team) |
| `spec.authorizedTechniques` | []string | MITRE ATT&CK technique IDs (e.g., `["T1611", "T1059"]`) |
| `spec.authorizedNamespaces` | []string | Namespaces in scope (not wildcards) |
| `spec.validFrom` | metav1.Time | Start of authorization window |
| `spec.expiresAt` | metav1.Time | End of authorization window |
| `spec.justification` | string | Stated justification for the authorization |
| `spec.catalogVersion` | string | Reference to the approved syscall catalog version |
| `status.active` | bool | Computed by controller from time bounds |

`SiderealAOAuthorization` resources are append-only and exported to the SIEM audit log. Authorization expiration surfaces as a `SiderealSystemAlert` requiring acknowledgment before detection probes resume.

### Approved Syscall Catalog

Detection probes execute only syscall patterns from a versioned, AO-approved catalog. Each catalog entry documents:

- Syscall pattern and parameters
- Corresponding MITRE ATT&CK technique
- FIPS 199 risk classification
- Containment mechanism
- Formal justification for why the pattern cannot cause harm if the detection layer misses it

The active catalog version is referenced in the `SiderealAOAuthorization` resource and included in the SSP. Catalog updates require a new AO authorization.

### Outcome State Machine

```
Probe Job created
  → Executing
  → Job completes, 60s verification window opens
  → VerifyingDetection (controller polls detection backend every 5s)
  → Window closes:
       alert correlated to probe    → Detected
       no alert within window       → Undetected
       behavior blocked at runtime  → Blocked
       backend unreachable          → BackendUnreachable
```

| Outcome | Meaning |
|---|---|
| `Detected` | Behavior completed; alert was raised within the window — detection is working |
| `Undetected` | Behavior completed; no correlated alert within the window — gap in detection coverage |
| `Blocked` | Behavior was prevented before completion by a runtime enforcement layer (e.g., Tetragon enforcement mode) — enforcement is working |
| `BackendUnreachable` | Detection backend could not be queried during the verification window — monitoring pipeline is down |

`Undetected` and `BackendUnreachable` are distinct outcomes. A flood of `BackendUnreachable` results signals that the monitoring pipeline itself is down, not that detection rules are misconfigured.

The verification window defaults to **60 seconds** and is configurable per probe via `spec.verificationWindowSeconds`.

### Alert Correlation

Every probe Job pod carries the label `sidereal.cloud/probe-id: <uuid>`. Falco and Tetragon both enrich alerts with Kubernetes pod metadata, causing this label to appear on any alert generated by activity inside the probe container. The controller queries the detection backend for alerts carrying the matching probe ID to establish correlation.

Cluster operators must not add exceptions to Falco or Tetragon rules that suppress alerts from pods carrying `sidereal.cloud/*` labels. Doing so would cause detection probes to return `Undetected` while leaving the same gap open for real attackers.

### Detection Backend Interface

The controller uses a pluggable `DetectionBackend` interface:

```
DetectionBackend interface {
    QueryAlerts(ctx, probeID string, window time.Duration) ([]Alert, error)
}
```

Concrete implementations are provided for:
- **Falco** — polls the Falco gRPC output API (`falco.org/output.v1`)
- **Tetragon** — polls the Tetragon gRPC API (`tetragon.FineGuidanceSensors/GetEventsStream`)

The `sidereal-system` NetworkPolicy must include explicit egress rules to each configured detection backend endpoint, auto-generated by the Helm chart based on configured backend addresses. The controller verifies at startup that backend endpoints are reachable within the defined egress rules and surfaces a misconfiguration warning if not. The backend type and endpoint are configured per-cluster in the Sidereal Helm values.

### Probe Risk Classification

Detection probes are formally classified as **Medium risk** under FIPS 199 methodology. Mitigating controls: sandboxed container execution, seccomp Localhost profile (custom, tighter than RuntimeDefault), all capabilities dropped, no network access, no volume mounts, AO authorization required, syscall patterns constrained to the approved catalog. All other probe types are classified as **Low risk** — blast radius controls (namespace scoping, ResourceQuota, rate limiting, immutable images) are the documented mitigating factors.

---

## Per-Probe ServiceAccounts

Each probe class is assigned a dedicated ServiceAccount, pre-provisioned at install time by the Helm chart, with the minimum RBAC required for that specific probe surface and nothing else. ServiceAccount tokens are bound with a maximum 1-hour expiry.

| Probe Class | ServiceAccount | Capability |
|---|---|---|
| RBAC | `sidereal-probe-rbac` | Attempt actual operations (e.g., `GET` a secret outside authorized namespace) and verify 403 rejection — not `can-i`. Tests: RoleBinding creation, impersonation, pod exec access, cross-namespace resource reads |
| NetworkPolicy | `sidereal-probe-netpol` | None — relies on CNI observability layer for flow verdicts, not API access |
| Admission | `sidereal-probe-admission` | Submit a known-bad resource spec, read the rejection |
| Secret Access | `sidereal-probe-secret` | Attempt to `get` secrets outside the authorized namespace — tests the data exfiltration vector specifically |
| Detection | `sidereal-probe-detection` | Execute known-bad syscall patterns — including runtime privilege escalation attempts — in a sandboxed container |
| Discovery | `sidereal-discovery` | Read-only cluster-wide access: list/get NetworkPolicies, WebhookConfigurations, RoleBindings, ClusterRoleBindings, Secrets (metadata only), Falco rules, Tetragon TracingPolicies. No write permissions. |

---

## Custom Probe Extensibility

The five built-in probe surfaces cover the most common Kubernetes security control boundaries. However, agencies have diverse control environments that extend beyond these surfaces — encryption at rest verification, logging pipeline integrity, certificate expiration monitoring, DNS policy enforcement, service mesh mTLS validation, and others. Rather than forcing agencies to wait for upstream additions, Sidereal provides a custom probe extension model.

### Custom Probe Contract

A custom probe is a container image that conforms to a standardized input/output contract. The controller handles scheduling, HMAC signing, audit recording, SIEM export, and incident creation — the custom probe handles only the domain-specific validation logic.

**Input contract** — the controller provides:
- Environment variable `SIDEREAL_PROBE_ID` — the unique execution ID (UUID)
- Environment variable `SIDEREAL_TARGET_NAMESPACE` — the namespace under test
- Environment variable `SIDEREAL_EXECUTION_MODE` — `dryRun`, `observe`, or `enforce`
- Volume mount `/sidereal/config` — probe-specific configuration from `SiderealProbe.spec.customProbe.config` (JSON)
- Volume mount `/sidereal/hmac` — the per-execution HMAC key (same mechanism as built-in probes)

**Output contract** — the probe writes a JSON result to `/sidereal/result/outcome.json`:
```json
{
  "outcome": "Pass | Fail | NotApplicable | Indeterminate",
  "detail": "Human-readable description of what was validated and what was found",
  "nistControls": ["SC-28", "SC-13"],
  "mitreAttackId": "T1552"
}
```

The result is HMAC-signed by the probe using the provided key, identical to built-in probes. The controller verifies the signature and maps the four custom probe outcomes to `controlEffectiveness` using the same normalization table as built-in probes.

### SiderealProbe Custom Probe Configuration

```yaml
apiVersion: sidereal.cloud/v1alpha1
kind: SiderealProbe
metadata:
  name: etcd-encryption-verify
spec:
  type: custom
  customProbe:
    image: ghcr.io/agency/sidereal-probe-etcd-encryption@sha256:abc123...
    serviceAccountRef: sidereal-probe-etcd-encryption
    config:
      encryptionProvider: "aescbc"
      verifyNamespaces: ["production", "staging"]
    nistControls: ["SC-28"]
    mitreAttackId: "T1552"
  targetNamespaceSelector:
    matchLabels:
      data-classification: "high"
  executionMode: observe
  intervalSeconds: 86400
```

### Security Model

Custom probes are subject to **all** the same security controls as built-in probes:

- **Image signing** — custom probe images must be cosign-signed. The admission enforcement policy verifies signatures before the Job pod is admitted. Unsigned custom probe images are rejected at admission.
- **Digest pinning** — custom probe images are referenced by digest, not tag. The `values.schema.json` enforces this.
- **ServiceAccount isolation** — each custom probe type requires its own dedicated ServiceAccount, pre-provisioned by the operator. The controller's admission enforcement policy validates that the Job references only approved ServiceAccounts (built-in or registered custom).
- **HMAC integrity** — custom probe results are HMAC-signed and verified identically to built-in probes.
- **Pod security** — custom probe Jobs run with the same Restricted pod security profile: non-root, read-only root filesystem, all capabilities dropped, seccomp RuntimeDefault.
- **Resource limits** — custom probe Jobs are subject to the same `ResourceQuota` as built-in probes.

Custom probe ServiceAccounts must be registered in the Helm values (`customProbes.registeredServiceAccounts`) so the admission enforcement policy can validate them. Unregistered ServiceAccounts are rejected.

### What Custom Probes Cannot Do

- Custom probes cannot use the `detection` outcome set (`Detected`/`Undetected`/`Blocked`) — those outcomes require the controller-driven verification window and AO authorization. Custom probes that need detection validation should request it be added as a built-in detection catalog entry.
- Custom probes cannot bypass the HMAC integrity chain.
- Custom probes cannot run with elevated privileges beyond what their registered ServiceAccount provides.
- Custom probes cannot opt out of image signature verification.

---

## Blast Radius Controls

Blast radius containment is a first-class design constraint, not an afterthought. Controls are layered in depth:

**Namespace Scoping** — every `SiderealProbe` must declare either a `targetNamespace` (explicit, single namespace) or a `targetNamespaceSelector` (label-based, multiple namespaces). The two fields are mutually exclusive — specifying both is rejected at admission.

When `targetNamespaceSelector` is used, the controller resolves matching namespaces at scheduling time and creates one probe Job per matching namespace. New namespaces that acquire a matching label are automatically included in subsequent scheduling cycles; namespaces that lose the label are automatically excluded. This eliminates the combinatorial overhead of managing hundreds of per-namespace probe definitions — a single `SiderealProbe` with `targetNamespaceSelector: { matchLabels: { compliance-tier: "high" } }` covers all namespaces in that tier.

The probe runner Job is created in `sidereal-system` and its ServiceAccount RoleBinding is scoped to the resolved target namespace only. Cross-namespace access is never implicit. For `targetNamespaceSelector` probes, ephemeral RoleBindings are created per-Job and cleaned up with the Job's TTL. Each resolved namespace produces its own `SiderealProbeResult` — there is no aggregated multi-namespace result.

**Execution Modes** — a first-class spec field on every probe (`executionMode: dryRun | observe | enforce`), overridable at the global level via Helm values. The three modes provide a graduated adoption path:

| Mode | Behavior | Incidents Created | Webhooks Fired | Use Case |
|---|---|---|---|---|
| `dryRun` | Probe constructs the action it would take and records it without executing | No | No | Initial install, configuration validation |
| `observe` | Probe executes live; results are recorded and exported to SIEM | No | No | Evaluation period — ISSO reviews results, tunes probes, builds confidence |
| `enforce` | Probe executes live; results are recorded; `SiderealIncident` resources are created on failure; IR webhooks fire | Yes | Yes | Full operational mode with incident pipeline |

`dryRun` is the default on initial install. Transitioning to `observe` requires the `sidereal-live-executor` role (same gate as before — live execution is still explicitly opted into). Transitioning from `observe` to `enforce` requires the same role. The graduated path allows an ISSO to enable live probing, review weeks of results, and only then activate the incident pipeline — reducing the risk of alert fatigue from untuned probes flooding the IR system.

Per-probe `executionMode` overrides the global setting. A probe can be in `enforce` while the global default is `observe`, allowing incremental promotion of individual probe surfaces.

**Resource Quotas** — a `ResourceQuota` is applied to `sidereal-system` at install time, capping concurrent probe Jobs and total CPU/memory consumption. This prevents a misconfigured schedule or runaway reconciliation loop from flooding the cluster.

**Probe Fingerprinting** — every probe Job pod carries the label `sidereal.cloud/probe-id: <uuid>` and all API calls carry a `sidereal.io` user-agent. For detection probes, the pod label serves as the correlation key for alert matching (see Detection Probe Verification). This label is the fingerprint — it does not suppress detection, it identifies the source after the fact. A probe action without a valid fingerprint does not execute.

**Execution Rate Limiting** — the Schedule Controller enforces a minimum interval between probe executions per target namespace, regardless of reconciliation loop frequency. This guards against clock skew, controller restarts, or scheduling bugs causing duplicate execution.

**Execution Jitter** — probe scheduling is randomized within ±10% of the configured interval. This prevents an attacker from timing attacks around a predictable probe execution window (SI-4).

**Immutable Probe Images** — probe container images are pinned by digest (not tag) in the Helm chart. Immutability means content-addressed (digest-pinned) plus a registry-level write-once policy (object lock or equivalent) on the probe image repository — not just digest-pinning. Probe images are minimal (distroless or scratch-based) with no shell, no package manager, and no capabilities beyond what the specific probe requires.

**Controller Job Constraints** — the controller's ServiceAccount may only create Jobs carrying specific label selectors, enforced by an admission enforcement policy shipped with the Helm chart (rendered for the configured admission controller per the deployment profile). Created Jobs must reference only the pre-approved probe ServiceAccounts — any Job referencing an unauthorized ServiceAccount is rejected at admission. A `NetworkPolicy` isolates `sidereal-system`, preventing probe Jobs from making arbitrary egress calls.

### Special Case: Detection Probes

Detection probes require the strictest containment, as they deliberately emit behavior that resembles an attack:

- Executed inside a heavily sandboxed container — custom Localhost seccomp profile applied (tighter than RuntimeDefault), all capabilities dropped, no network access, no volume mounts
- Synthetic syscall patterns only — constrained to the AO-approved catalog; no pattern may be included that could cause harm if the detection layer fails to catch it
- Probe container image contains no credentials, sensitive mounts, or exploitable tooling
- Detection verification (did Falco/Tetragon alert?) is performed by the controller polling the detection backend independently within a 60s verification window — the probe itself does not assert its own detection

The probe fires the signal. The controller independently verifies the signal was received. These are two separate actions by two separate identities.

---

## Key Management

Probe image signing keys and any cryptographic keys used within Sidereal are governed per NIST 800-53 SC-12.

- **Generation**: Keys generated in an HSM or cloud KMS (AWS KMS, GCP Cloud HSM, Azure Key Vault). Never generated on developer workstations or CI runners.
- **Storage**: Private keys remain in the HSM/KMS. They are never exported in plaintext. SC-28 (Protection of Information at Rest) requires encryption of keys at rest — HSM/KMS satisfies this.
- **Distribution**: Public verification key shipped with the Sidereal Helm chart. For air-gapped environments, key custody transfer follows a documented procedure included in the Helm chart deployment guide.
- **Rotation**: Annual rotation minimum, or immediately on suspected compromise. Rotation procedure: generate new keypair, re-sign all current probe images, update Helm chart with new public key, deploy updated chart, retire old key.
- **Revocation**: Revocation list maintained and referenced by the admission controller's image verification policy. Revoked keys cause all Jobs referencing images signed with the revoked key to be rejected at admission.
- **Destruction**: Keys retired per the documented schedule are destroyed in the HSM/KMS with destruction recorded as an auditable event.
- **Air-gapped re-signing**: Operators mirroring images to internal registries for IL4/IL5 deployments are responsible for re-signing with a registry-specific key. The admission controller's image verification policy must be updated with the new trusted public key. The re-signing key must itself be managed per these SC-12 requirements.

---

## Probe Image Supply Chain

Probe runner images have elevated execution context and perform adversarial behavior. A tampered probe image is a high-value attack vector. Supply chain integrity is enforced at the admission layer — not inside the controller — so that a compromised controller cannot circumvent image verification.

### Build and Signing

Probe images are built and signed by the CI/CD pipeline on every merge to main. No hand-built images are used. Signatures are generated using **Sigstore/cosign** with keys managed per the Key Management section above. Signatures are stored in the image registry alongside the image as OCI referrer artifacts.

Each image receives the following attestations at build time:

- **CycloneDX SBOM** — generated by `syft` (Go components) and `cargo cyclonedx` (Rust components); cosign-attested to the image digest via `cosign attest --type cyclonedx`; queryable via `cosign verify-attestation --type cyclonedx`
- **SLSA Level 2 provenance** — records source repository, commit SHA, build system identity, and build timestamp; cosign-attested to the image digest via `cosign attest --type slsaprovenance`; links each image to its exact source commit and CI build run
- **Sigstore Rekor transparency log** — every cosign signing event (signatures and attestations) is published to the Rekor append-only transparency log; Rekor is external to Sidereal infrastructure, publicly queryable, and provides independently verifiable non-repudiation of all build and signing events

### Admission Enforcement

An admission enforcement policy shipped with the Helm chart (rendered for the configured admission controller) verifies the cosign signature of every probe runner image before the Job pod is admitted. Any Job referencing an image without a valid Sidereal signature is rejected at admission — it never runs. This gate is independent of the controller: even a compromised controller cannot create a Job with an unsigned or tampered image.

This policy is co-located with the Job constraint policy (controller may only create Jobs referencing pre-approved ServiceAccounts) — both are enforced at the same admission layer, shipped and versioned together in the Helm chart.

### Image References

All probe images are pinned by digest in the Helm chart. Tag-based references are not used. The Helm chart supports image repository overrides (`global.imageRegistry`) for air-gapped environments and IL4/IL5 deployments where images must be mirrored to an approved internal registry.

---

## Bootstrap and Admission Controller Dependency

Sidereal's blast radius controls depend on the configured admission controller being present and active at install time. If no admission controller is installed, the policy that constrains the controller's Job creation permissions does not exist, silently removing a core blast radius control. This is enforced at three layers:

**Helm pre-install hook** — a lightweight Job runs before chart installation and checks for the admission controller CRDs specified in the deployment profile. If not detected, the install fails with a clear error message. This is the primary gate and is enabled by default.

**Helm values escape hatch** — operators can set `global.requireAdmissionController: false` to bypass the pre-install check. This setting requires the `sidereal-security-override` RBAC role to modify. When changed, the Helm pre-upgrade hook generates an audit record capturing the Kubernetes principal who made the change, timestamp, and stated justification. This record is exported to the SIEM. The reduced blast radius control is deliberate, traceable, and auditable — not silent. Per CM-6, this deviation must be documented as a configuration baseline exception in the SSP with documented approval.

**Controller startup check and acknowledgment gate** — on every startup and after every reconciliation cycle (continuous drift detection), the controller executes a bootstrap verification checklist:

1. Admission controller CRDs exist and all 4 Sidereal admission policies are present and enforcing (policy resource type depends on deployment profile)
2. All 7 built-in ServiceAccounts exist with expected RBAC bindings (plus any registered custom probe ServiceAccounts)
3. Default-deny NetworkPolicy is in place in `sidereal-system`
4. HMAC root Secret is accessible
5. Detection backend(s) are reachable (if configured)
6. SIEM export endpoint(s) are reachable (if configured)

If any check fails, the controller:

1. Halts probe execution immediately
2. Creates a `SiderealSystemAlert` resource with `reason: AdmissionPolicyMissing`
3. Surfaces a `DegradedMode` condition on its own status
4. Emits a Prometheus metric (`sidereal_bootstrap_verification_status`) for alerting

`SiderealSystemAlert` resources are used throughout Sidereal to surface degraded states. Each alert includes `spec.reason` (enum), `spec.message`, `spec.acknowledged` (bool), `spec.acknowledgedBy` (Kubernetes username), `spec.acknowledgedAt`, and `spec.remediationAction`. The full set of alert reasons is:

| Reason | Trigger |
|---|---|
| `AdmissionPolicyMissing` | Admission enforcement policies not found at startup or during drift check |
| `SIEMExportDegraded` | Consecutive SIEM export failures exceeded threshold |
| `AuditWriteFailure` | Failed to write SiderealProbeResult to etcd |
| `BaselineConfigurationDrift` | Deployed state differs from committed Helm values baseline |
| `TamperedResult` | HMAC verification failed on a probe result ConfigMap |
| `AOAuthorizationExpired` | Active SiderealAOAuthorization has passed its `expiresAt` time |
| `BackendUnreachable` | Detection or CNI backend not reachable during verification window |
| `UnexpectedNetworkFlow` | Hubble correlation detected unfingerpinted flow crossing a deny boundary |

Probe execution does not resume until an authorized operator explicitly acknowledges the `SiderealSystemAlert`. The acknowledging principal must be an individual Kubernetes RBAC identity (not a shared service account) — shared service account acknowledgments are rejected at admission. The acknowledgment record captures: Kubernetes username from request context, timestamp, and stated remediation action. This satisfies AU-10 non-repudiation requirements and serves as a POA&M evidence record under NIST 800-53 CA-7 and SI-7.

---

## Result Storage and Audit Log

Sidereal is designed for Federal systems operating under continuous monitoring requirements (FedRAMP, FISMA, NIST 800-53). Result storage uses a two-tier model that separates operational visibility from the authoritative audit record.

### Tier 1 — Operational View

Probe results are written to a status subresource on `SiderealProbe`. This holds the latest result, the last N executions (default 10, configurable), and a `consecutiveFailures` counter used for alerting. This tier is mutable and intended for day-to-day operator visibility via `kubectl`. It is not the audit record.

### Tier 2 — Append-Only Audit Log

Every probe execution creates a `SiderealProbeResult` resource. These resources are:
- Namespace-scoped to `sidereal-system`. RBAC restricts result visibility to operators of the corresponding target namespace. Cluster-wide aggregation requires explicit cluster-admin access.
- Never modified after creation — enforced by an admission enforcement policy that explicitly denies UPDATE and DELETE operations on `SiderealProbeResult` for all principals. Only CREATE is permitted.

Each record includes the following fields:

| Field | Type | Description |
|---|---|---|
| `spec.probe.id` | string (UUID) | Unique per-execution identifier; correlation key across all audit systems |
| `spec.probe.type` | enum | `rbac`, `netpol`, `admission`, `secret`, `detection` |
| `spec.probe.targetNamespace` | string | Namespace under test |
| `spec.probe.aoAuthorizationRef` | string | Reference to SiderealAOAuthorization (detection probes only) |
| `spec.result.outcome` | enum | `Pass`, `Fail`, `Detected`, `Undetected`, `Blocked`, `Rejected`, `Accepted`, `NotApplicable`, `BackendUnreachable`, `NotEnforced`, `Indeterminate`, `TamperedResult` |
| `spec.result.controlEffectiveness` | enum | Derived from `outcome` — see Control Effectiveness Normalization below |
| `spec.result.nistControls` | []string | NIST 800-53 controls validated by this execution (see control mapping below) |
| `spec.result.controlMappings` | map[string][]string | Multi-framework control mappings — see Multi-Framework Control Mapping below |
| `spec.result.mitreAttackId` | string | MITRE ATT&CK for Containers technique ID |
| `spec.result.integrityStatus` | enum | `Verified` or `TamperedResult` |
| `spec.result.detail` | string | Human-readable description of the outcome |
| `spec.execution.timestamp` | string | RFC 3339 UTC with nanosecond precision |
| `spec.execution.durationMs` | int64 | Probe execution duration in milliseconds |
| `spec.execution.jobName` | string | Name of the Kubernetes Job that executed the probe |
| `spec.audit.exportStatus` | enum | `Pending`, `Exported`, `Failed` |
| `spec.audit.exportedAt` | string | RFC 3339 UTC timestamp of successful export |

**Minimum TTL: 365 days** (FedRAMP High baseline, AU-11). The TTL floor is enforced by the controller — values below 365 days are rejected. In-cluster records are maintained for the full retention period as a resilient backup independent of SIEM availability.

### SIEM Export

Every `SiderealProbeResult` is pushed to a configurable external export target. Export is a first-class v1 feature — for federal systems, the SIEM is the preferred long-term authoritative record and the primary evidence source for ATO packages. The SIEM must retain records for a minimum of **3 years** (FedRAMP High baseline).

All SIEM export connections require TLS 1.2+ with FIPS-approved cipher suites and certificate validation. Payloads are signed with the Sidereal signing key before transmission so the SIEM can verify records were not altered in transit. S3 export requires SSE-KMS encryption and object lock in COMPLIANCE mode for AU-11 retention enforcement.

Export is pluggable via an `AuditExportBackend` interface, consistent with the `DetectionBackend` and `NetworkPolicyBackend` patterns.

### Export Formats

The export record format is configurable via `audit.exportFormat` in Helm values. Each format transforms the same underlying `SiderealProbeResult` data into the target format before transmission.

| Format | Identifier | Target SIEMs | Description |
|---|---|---|---|
| **JSON** | `json` | Splunk HEC, Elasticsearch, S3, generic webhook | Structured JSON — Sidereal's native format. All fields preserved with full fidelity. Default. |
| **CEF** | `cef` | ArcSight, QRadar (via CEF), legacy SIEMs | Common Event Format (ArcSight standard). Maps `controlEffectiveness` to CEF severity, probe metadata to CEF extension fields. |
| **LEEF** | `leef` | IBM QRadar | Log Event Extended Format. Native QRadar format with Sidereal-specific custom keys. |
| **Syslog** | `syslog` | Any RFC 5424-compliant receiver | Structured syslog with SD-ELEMENT containing probe result fields. Universal fallback for SIEMs that accept syslog input. Transmitted via TLS (RFC 5425). |
| **OCSF** | `ocsf` | AWS Security Lake, Amazon Security Hub, OCSF-native tools | Open Cybersecurity Schema Framework v1.1. Maps probe results to the OCSF `Security Finding` class (class_uid: 2001). Emerging standard with growing federal adoption. |

Multiple export targets can each use a different format — a single Sidereal deployment can export JSON to Splunk and OCSF to AWS Security Lake simultaneously.

### Export Reliability

Failed exports are retried with exponential backoff (5-second initial delay, 5-minute maximum, 24-hour retry window). Export failures surface as a distinct Prometheus metric (`sidereal_siem_export_failures_total`) and generate a `SiderealSystemAlert` with `reason: SIEMExportDegraded` after consecutive failures. In-cluster `SiderealProbeResult` records serve as the resilient backup if the SIEM is persistently unavailable.

**Fail-closed option**: When `audit.failClosedOnExportFailure: true` is set in the Helm values, the controller halts all probe scheduling when SIEM export is persistently failing. This ensures no probe executions occur without an audit trail being delivered to the SIEM. Recommended for NIST 800-53 High baseline systems.

### Audit Event Enumeration (AU-12)

The following events within Sidereal generate audit records exported to the SIEM:

- Controller startup and shutdown
- Probe execution mode changes (`executionMode` transitions: `dryRun` → `observe` → `enforce`)
- Every probe execution outcome
- AO authorization creation and expiration
- `SiderealSystemAlert` creation and acknowledgment (including acknowledging principal identity)
- Configuration changes to security-relevant Helm values
- HMAC verification failures (`TamperedResult`)
- SIEM export failures

### Audit Log Access Control (AU-9(4))

The `sidereal-audit-admin` role provides read-only access to `SiderealProbeResult`. This role is separate from cluster-admin. Per AU-9(4), the audit administrator and system administrator roles must be held by separate individuals — enforced administratively by the ISSO during account provisioning and verified through access review.

### NIST 800-53 Specific Control Mapping

Every probe result is tagged with specific NIST 800-53 controls. This makes the audit log directly referenceable in continuous monitoring reports and ATO packages without post-processing.

| Probe | NIST 800-53 Controls |
|---|---|
| RBAC | AC-2, AC-3, AC-6 |
| NetworkPolicy | SC-7, SC-8 |
| Admission Control | CM-6, CM-7 |
| Secret Access | AC-3, AC-4 |
| Detection Coverage | SI-3, SI-4, SI-7 |

### Multi-Framework Control Mapping

Federal agencies operate under diverse compliance regimes beyond NIST 800-53. A DoD contractor processing CUI needs CMMC mapping. A law enforcement system needs CJIS. A system handling tax data needs IRS 1075. An ISSO adopting Sidereal should not have to maintain manual crosswalk spreadsheets to satisfy their specific compliance requirements.

Every `SiderealProbeResult` carries a `controlMappings` field — a map from framework identifier to a list of control IDs within that framework. Active frameworks are defined as `SiderealFramework` cluster-scoped CRDs. The `FrameworkReconciler` loads each resource into the in-memory crosswalk resolver; the result reconciler populates mappings for all loaded frameworks on every result.

**Supported frameworks:**

| Framework ID | Framework | Example Control IDs |
|---|---|---|
| `nist-800-53` | NIST SP 800-53 Rev 5 | `AC-3`, `SC-7`, `AU-9` |
| `cmmc` | Cybersecurity Maturity Model Certification (v2) | `AC.L2-3.1.1`, `SC.L2-3.13.1` |
| `cjis` | Criminal Justice Information Services Security Policy | `5.4.1.1`, `5.10.1.2` |
| `irs-1075` | IRS Publication 1075 (Tax Information Security) | `9.3.1.3`, `9.3.16.7` |
| `hipaa` | HIPAA Security Rule (45 CFR 164) | `164.312(a)(1)`, `164.312(e)(1)` |
| `nist-800-171` | NIST SP 800-171 Rev 3 (CUI Protection) | `3.1.1`, `3.13.1` |
| `kubernetes-stig` | DISA Kubernetes STIG | `V-242435`, `V-242437` |

**Crosswalk data model**: Crosswalk tables are defined as `SiderealFramework` CRDs (cluster-scoped). Each resource maps `(probeType, nist_800_53_control) → [framework_control_ids]`. This makes crosswalks:
- **Auditable** — an assessor can `kubectl get siderealframeworks` to inspect exactly which mappings are active
- **Updateable** — agencies add, update, or remove frameworks with `kubectl apply`/`kubectl delete`; no controller restart required
- **Versionable** — each `SiderealFramework` carries a `spec.version` field recorded on every `SiderealProbeResult` in `spec.result.crosswalkVersion`

Custom framework mappings are supported by applying a `SiderealFramework` resource. Sidereal does not validate custom framework control IDs — the ISSO is responsible for correctness of custom mappings. The seven built-in frameworks ship as default `SiderealFramework` resources in the Helm chart (`crosswalk.installDefaults: true`); agencies managing frameworks externally set this to `false`.

**Example `controlMappings` on a probe result:**
```json
{
  "nist-800-53": ["AC-3", "AC-6"],
  "cmmc": ["AC.L2-3.1.1", "AC.L2-3.1.5"],
  "nist-800-171": ["3.1.1", "3.1.5"]
}
```

The `spec.result.nistControls` field is retained for backward compatibility and populated identically to `controlMappings["nist-800-53"]`. New integrations should use `controlMappings`.

### Control Effectiveness Normalization

The 12 raw outcome values are technically precise but operationally complex — each probe type uses a different subset, and an ISSO reviewing results across surfaces must mentally normalize them to answer a single question: *is this control working?*

Every `SiderealProbeResult` carries a derived `controlEffectiveness` field that normalizes the raw outcome into a four-value enum:

| Effectiveness | Meaning | Raw Outcomes Mapped |
|---|---|---|
| `Effective` | The control is operating as intended | `Pass`, `Detected`, `Blocked`, `Rejected` |
| `Ineffective` | The control is not operating — a gap exists | `Fail`, `Undetected`, `Accepted`, `NotEnforced` |
| `Degraded` | The control cannot be fully validated — infrastructure issue, not a control gap | `BackendUnreachable`, `Indeterminate`, `NotApplicable` |
| `Compromised` | Result integrity is violated — trust in the probe pipeline itself is broken | `TamperedResult` |

The `controlEffectiveness` field is:
- **Derived, not configurable** — the mapping is deterministic and not operator-modifiable, ensuring consistent interpretation across deployments
- **The primary field for dashboards, reports, and alerting** — operators and ISSOs interact with `controlEffectiveness`; the raw `outcome` field remains for detailed forensic analysis
- **Exposed as a Prometheus label** — `sidereal_probe_executions_total{control_effectiveness="Effective"}` enables simple Grafana dashboards and Alertmanager rules without outcome-by-outcome enumeration

The `sidereal report` CLI (see Report Generation) and `SiderealIncident` creation logic both key off `controlEffectiveness`, not raw outcomes. Incidents are created only when `controlEffectiveness` is `Ineffective` or `Compromised` (in `enforce` execution mode).

---

## Incident Response Integration

Control failure outcomes represent active security control gaps on a live federal system. These are incidents, not merely metrics. When a probe returns a failure outcome (`Forwarded`, `Undetected`, `Accepted`), Sidereal:

1. Creates a `SiderealIncident` resource capturing the failure details
2. Exports the incident to a configurable IR webhook (ServiceNow, JIRA, or generic webhook endpoint)
3. Increments the `consecutiveFailures` counter on the `SiderealProbe` status, triggering Alertmanager rules

The `SiderealIncident` resource is append-only and exported to the SIEM. Each incident includes:

| Field | Type | Description |
|---|---|---|
| `spec.probeResultRef` | string | Name of the SiderealProbeResult that triggered the incident |
| `spec.controlId` | string | NIST 800-53 control identifier (e.g., `AC-3`) |
| `spec.mitreId` | string | MITRE ATT&CK technique identifier (e.g., `T1078`) |
| `spec.description` | string | Human-readable description of the control gap |
| `spec.severity` | enum | `Critical`, `High`, `Medium`, `Low` — mapped from probe outcome type |
| `spec.targetNamespace` | string | Namespace where the control failure was detected |
| `spec.remediationStatus` | enum | `Open`, `InProgress`, `Remediated`, `Accepted` |
| `spec.webhookDeliveryStatus` | enum | `Pending`, `Delivered`, `Failed` |

Per NIST 800-53 IR-6 and FISMA, mandatory reporting to US-CERT/CISA within defined timeframes is triggered by `SiderealIncident` events. The mandatory reporting window (e.g., 1 hour for critical, 24 hours for high) is configurable in Helm values and documented in the system's incident response plan. Sidereal generates the incident; the agency's IR procedures govern the reporting workflow.

---

## Report Generation

Probe results and SIEM export provide the raw data. But an ISSO's deliverables are **formatted reports** — continuous monitoring summaries for AO briefings, POA&M entries for control gaps, and assessment evidence packages for assessors. Sidereal bridges this gap with a built-in report generation capability.

### Report Types

| Report | Output Formats | Description | NIST Reference |
|---|---|---|---|
| **Continuous Monitoring Summary** | OSCAL `assessment-results` JSON, PDF, Markdown | Control-by-control effectiveness summary for a time period. Shows pass/fail rates, trend data, and identified gaps per probe surface. Grouped by compliance framework when multiple frameworks are active. | CA-7, PM-31 |
| **POA&M Generator** | OSCAL `plan-of-action-and-milestones` JSON, CSV | Automatically generates POA&M entries from `SiderealIncident` resources with `Ineffective` or `Compromised` control effectiveness. Includes control ID, weakness description, scheduled remediation date (based on CVE SLA equivalents), and milestone tracking. | CA-5 |
| **Control Coverage Matrix** | PDF, Markdown, CSV | Maps every active `SiderealProbe` to its compliance framework controls, showing which controls have continuous validation coverage and which are not covered by any probe. Critical for gap analysis during ATO preparation. | CA-2 |
| **Assessment Evidence Package** | OSCAL `assessment-results` JSON, ZIP archive | Bundles probe results, discovery recommendations, system alerts, and incident records for a defined time window into a single exportable package suitable for submission to an assessor. Includes cryptographic integrity verification (HMAC chain) of all included records. | CA-2, CA-4 |
| **Executive Summary** | PDF, Markdown | High-level posture dashboard formatted for AO/ISSO consumption. Uses `controlEffectiveness` exclusively (no raw outcomes). Shows posture trend over time, active incidents, and discovery coverage ratio. | PM-9 |

### CLI Interface

```bash
sidereal report continuous-monitoring \
  --from 2026-03-01 --to 2026-03-31 \
  --frameworks nist-800-53,cmmc \
  --format oscal-json \
  --output march-2026-conmon.json

sidereal report poam \
  --open-incidents-only \
  --format csv \
  --output poam-q1-2026.csv

sidereal report coverage-matrix \
  --frameworks nist-800-53 \
  --format pdf \
  --output coverage-matrix.pdf

sidereal report evidence-package \
  --from 2026-01-01 --to 2026-03-31 \
  --include-results --include-incidents --include-alerts \
  --format zip \
  --output q1-2026-evidence.zip

sidereal report executive-summary \
  --period monthly \
  --format pdf \
  --output march-2026-executive.pdf
```

### In-Cluster Report Generation (Optional)

For agencies that require automated report delivery, a `SiderealReport` CRD can be configured to generate reports on a schedule:

```yaml
apiVersion: sidereal.cloud/v1alpha1
kind: SiderealReport
metadata:
  name: monthly-conmon
spec:
  type: continuous-monitoring
  schedule: "0 6 1 * *"        # First of every month at 06:00 UTC
  frameworks: ["nist-800-53"]
  format: oscal-json
  outputSecret: monthly-conmon-reports   # Results stored in a Kubernetes Secret
  retention: 12                          # Keep last 12 reports
```

`SiderealReport` is an operational convenience CRD — it does not carry the same audit integrity requirements as `SiderealProbeResult`. The report content is derived entirely from the authoritative audit log; the report itself is not the audit record.

### Report Data Sources

Reports consume data exclusively from the in-cluster `SiderealProbeResult`, `SiderealIncident`, and `SiderealSystemAlert` resources. They do not query the SIEM — the in-cluster data is the source of truth for report generation. This means reports are available even if SIEM export is degraded, and report generation does not create a dependency on external infrastructure.

---

## Privacy Controls

Probe results contain namespace names, workload identities, ServiceAccount names, timestamps, and behavioral telemetry. Depending on the workloads in monitored namespaces, this data may constitute Personally Identifiable Information (PII) under federal definitions.

Sidereal provides the following configuration options for environments where this data constitutes PII:
- `privacy.redactNamespaceNames: true` — replaces namespace names with opaque identifiers in audit records
- `privacy.redactWorkloadIdentities: true` — replaces workload and ServiceAccount names with opaque identifiers

PII assessment, System of Records Notice (SORN) requirements, and privacy impact assessment (PIA) are the deploying agency's responsibility under the NIST 800-53 PT control family and applicable privacy law. These Sidereal configuration options provide the technical mechanism; the agency determines applicability.

---

## Personnel Security

Positions with access to Sidereal are security-sensitive: Sidereal holds ATO evidence, can enable adversarial probing of federal infrastructure, and has connections to detection backends. The following personnel security requirements apply per NIST 800-53 PS controls:

- **PS-2**: Positions with `sidereal-operator`, `sidereal-live-executor`, or `sidereal-approver` roles require formal risk designation
- **PS-6**: All individuals with Sidereal access must execute a formal access agreement prior to provisioning
- **PS-7**: Contractor access to Sidereal is subject to PS-7 requirements; contractor personnel security must be documented in the SSP

These are agency-level obligations documented in the SSP and enforced through the agency's access management procedures, not Sidereal implementation requirements.

---

## Contingency Planning

Sidereal is a security control — its unavailability halts ATO evidence generation. Per NIST 800-53 CP controls:

- **RTO recommendation**: 4 hours. Monitoring continuity beyond 4 hours constitutes a gap in continuous monitoring evidence.
- **RPO**: Last successful backup of `SiderealProbe` CRD instances and Helm values.
- **Backup procedure**: `SiderealProbe` configurations backed up via Velero or equivalent on the agency's defined schedule. Helm values stored in version control constitutes the configuration backup.
- **Recovery procedure**: Redeploy Helm chart from version-controlled values, restore `SiderealProbe` resources from backup. Probe execution resumes automatically after controller startup checks pass.
- **Monitoring gap documentation**: Any Sidereal outage exceeding the RTO must be documented as a monitoring gap in the continuous monitoring report, with the duration and affected probe surfaces noted.

---

## Vulnerability Management

Sidereal is itself subject to vulnerability management requirements per NIST 800-53 RA-5 and SI-2:

- Go and Rust dependencies scanned by Dependabot (or equivalent) in CI on every commit
- Grype and Trivy scan all probe images in the CI pipeline before signing
- Critical CVEs patched and images re-signed within **30 days** (FedRAMP requirement)
- High CVEs patched within **60 days**
- Medium CVEs patched within **90 days**
- Probe images rebuilt and re-signed on any dependency update that resolves a CVE
- Vulnerability scan results published with each release as part of the SBOM

The deploying agency is responsible for scanning the running Sidereal deployment per their RA-5 continuous scanning requirements.

---

## Development Security Lifecycle

Sidereal is a security tool that validates supply chain integrity — its own development process must meet at least the standard it imposes on the systems it monitors. This section defines the security controls governing how Sidereal is built, reviewed, signed, and released. These controls satisfy NIST 800-218 (SSDF) and SLSA Level 2 requirements.

### Source Control and Commit Integrity

**Repository**: GitHub (github.com/primaris-tech/sidereal).

**Commit signing**: All commits must be cryptographically signed using SSH keys backed by a YubiKey hardware security device (YubiKey 5 series, FIPS 140-2 Level 2 certified). The signing key is generated on-device and never leaves the YubiKey — signing requires physical touch of the device. This ensures every commit is attributable to a specific individual with physical possession of their hardware token, satisfying AU-10 non-repudiation for the development process itself.

- Key type: `ed25519-sk` (SSH resident key on YubiKey)
- Git configuration: `gpg.format = ssh`, signing key set to the YubiKey-backed SSH public key
- GitHub verification: SSH signing keys registered with GitHub; commits display "Verified" badge
- Backup: Two YubiKeys per developer — one primary, one backup stored in a physically secure location

**Branch protection on `main`**:
- Require pull request before merging — no direct pushes
- Require at least 1 approving review (2 for security-critical paths — see CODEOWNERS)
- Require signed commits — unsigned commits are rejected
- Require all status checks to pass (build, test, lint, security scan)
- Require branches be up to date before merging
- No force pushes, no branch deletion
- Require review from CODEOWNERS for designated paths

**CODEOWNERS** — the following paths require review from the security reviewers team (2 approvals, not 1):

| Path | Reason |
|---|---|
| `internal/hmac/` | Cryptographic integrity — any change affects result trustworthiness |
| `internal/backend/` | External system connections — any change affects boundary security |
| `detection-probe/` | Adversarial syscall execution — highest-risk component |
| `deploy/helm/*/admission-policies/` | Admission enforcement policies — blast radius controls |
| `build/` | Dockerfiles — any change affects image composition and FIPS compliance |
| `.github/workflows/` | CI/CD pipeline — any change affects build integrity and signing |
| `api/v1alpha1/` | CRD type definitions — any change affects the data model |

### CI/CD Pipeline Hardening

**Platform**: GitHub Actions with GitHub-hosted runners (ephemeral, isolated).

**Action pinning**: All GitHub Actions are pinned by SHA, not tag. Tags are mutable — a compromised Action maintainer could push malicious code to an existing tag. SHA pins are immutable:

```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
```

Dependabot monitors Action SHAs and proposes updates when new versions are released.

**Workflow permissions**: The default `GITHUB_TOKEN` is read-only. Each job explicitly declares only the permissions it needs:

```yaml
permissions:
  contents: read       # default for all jobs
  packages: write      # only release jobs (push to GHCR)
  id-token: write      # only release jobs (OIDC for keyless signing)
```

**Separation of CI and release workflows**:

| Workflow | Trigger | Has Access To | Purpose |
|---|---|---|---|
| `ci.yaml` | PR, push to any branch | Nothing sensitive — read-only | Build, test, lint, security scan |
| `release.yaml` | Tag push to `main` only | OIDC token (keyless signing), GHCR push | Build images, sign, attest, publish |
| `security-scan.yaml` | Daily schedule | Read-only | Trivy scan, govulncheck against latest deps |

The CI workflow has no access to signing infrastructure or registry credentials. A malicious PR cannot trigger the release workflow or access signing capabilities.

**Environment protection rules**: The release workflow requires a GitHub Environment approval gate (`production` environment). A designated maintainer must manually approve the release before signing infrastructure becomes accessible. This prevents automated tag creation from triggering an unreviewed release.

**No self-hosted runners for untrusted code**: PRs from forks run only on GitHub-hosted runners. If self-hosted runners are ever introduced, they must be isolated from fork PRs.

**OpenSSF Scorecard**: The OpenSSF Scorecard GitHub Action runs on every push to `main` and produces a publicly visible supply chain security score. This catches misconfigurations (unpinned Actions, missing branch protection, etc.) automatically.

### Image Signing and Attestation

**Primary method: Keyless signing via Sigstore OIDC (Fulcio + Rekor)**

The release workflow authenticates to Sigstore's Fulcio CA via GitHub's OIDC token. Fulcio issues a short-lived signing certificate bound to the workflow identity:

```
Subject: https://github.com/primaris-tech/sidereal/.github/workflows/release.yaml@refs/tags/v1.0.0
Issuer: https://token.actions.githubusercontent.com
```

No long-lived signing key exists. The signing identity *is* the CI pipeline, verified by Fulcio. The signature and certificate are published to the Rekor transparency log. Verification checks that the image was signed by the Sidereal release workflow from a tag on `main`:

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/primaris-tech/sidereal/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  <image>@<digest>
```

**Alternative method: KMS-backed key (air-gapped / federal deployments)**

For environments that cannot reach the public Sigstore infrastructure, a cosign signing key stored in AWS KMS (or equivalent HSM) is used. The CI pipeline accesses the key via OIDC federation (GitHub → AWS STS → KMS). The private key never leaves the HSM.

Agencies mirroring images to internal registries may re-sign with an agency-managed KMS key. The admission enforcement policy must be updated with the agency's verification key. This procedure is documented in the deployment profile.

**Emergency manual signing (break-glass)**

If CI is unavailable and an emergency patch must be signed manually, a cosign key stored on the maintainer's YubiKey (PIV interface) can be used. This is a documented break-glass procedure, not a normal workflow. The manual signature is still published to Rekor for transparency.

### SLSA Provenance

The release workflow uses `slsa-framework/slsa-github-generator` to produce SLSA Level 2 provenance attestations. This Action runs in a hardened, isolated builder (separate from the main build job) and generates a signed provenance statement recording:

- Source repository and commit SHA
- Build system identity (GitHub Actions workflow)
- Build timestamp
- Build inputs (Go version, Rust toolchain version, base image digest)

The provenance attestation is cosign-attested to the image digest and published alongside the image in GHCR.

### Dependency Management

**Go modules**:
- `go.sum` provides cryptographic verification of all module downloads
- Dependencies are vendored (`go mod vendor`) — the repo is self-contained and immune to upstream module deletion or tampering
- `govulncheck` runs in CI on every PR and daily; blocks merge on known CVEs in called code paths
- Dependabot proposes dependency updates weekly

**Rust crates**:
- `Cargo.lock` pins exact versions
- `cargo audit` runs in CI on every PR; blocks merge on known advisories
- `cargo-deny` enforces license policies (deny copyleft in production dependencies) and bans specific crates if needed
- Dependabot proposes crate updates weekly

**Base images**:
- Pinned by digest in all Dockerfiles (never by tag)
- Dependabot monitors base image updates
- Base image updates go through the standard PR → review → merge flow

**GitHub Actions**:
- Pinned by SHA (covered above)
- Dependabot monitors Action updates

### Container Registry

**GitHub Container Registry (GHCR)** is the primary registry. Benefits:
- Integrated with GitHub — the `GITHUB_TOKEN` provides push access, no additional credentials needed
- OCI-compliant — supports cosign signatures and attestations as OCI referrer artifacts
- Publicly readable for the open-source project; private registries supported for agency mirrors
- No additional infrastructure to manage

### GitHub Account Security

All maintainers with write access to the Sidereal repository must use:
- **FIDO2/WebAuthn (YubiKey)** as their GitHub 2FA method — phishing-resistant (bound to github.com domain, cannot be replayed on a phishing page)
- **Not** TOTP or SMS, which are phishable

This is enforced via GitHub organization settings: "Require two-factor authentication" with FIDO2 as the required method.

### Vulnerability Disclosure

A `SECURITY.md` file in the repository defines the vulnerability disclosure process:
- GitHub's private vulnerability reporting is enabled — reporters submit through a form that creates a private advisory visible only to maintainers
- Maintainers triage, develop a fix, and coordinate disclosure timing with the reporter
- Fixes are released as a new signed image with a CVE identifier
- The advisory is published after the fix is available

### Development Security Summary

| Layer | Control | Mechanism |
|---|---|---|
| Developer identity | Hardware-backed commit signing | YubiKey SSH resident key (`ed25519-sk`) |
| Account security | Phishing-resistant 2FA | YubiKey FIDO2/WebAuthn |
| Code review | Mandatory review + elevated review for security paths | Branch protection + CODEOWNERS |
| CI integrity | Immutable Action pinning + minimal permissions | SHA-pinned Actions + read-only default token |
| Release gating | Human approval before signing | GitHub Environment protection rules |
| Image signing | Keyless signing (no long-lived key to compromise) | Sigstore OIDC via Fulcio + Rekor |
| Provenance | Build-to-source traceability | SLSA Level 2 via `slsa-github-generator` |
| Dependency integrity | Vendored deps + cryptographic verification | `go.sum` + `Cargo.lock` + `go mod vendor` |
| Vulnerability management | Continuous scanning + SLA enforcement | Trivy + govulncheck + cargo audit + Dependabot |
| Transparency | All signing events publicly auditable | Sigstore Rekor append-only log |

---

## Configuration Management

Sidereal configuration is a security-relevant artifact subject to NIST 800-53 CM controls.

**CM-2 (Configuration Baseline)**: The Helm values file is the configuration baseline. Security-relevant values are documented in the Helm chart's `values.schema.json` with default values and enforced ranges:

### Impact Level Cascade

The `global.impactLevel` setting is the primary configuration axis. It cascades defaults for scheduling, retention, and operational behavior so that operators select their baseline once and receive appropriate defaults. Individual parameters can be overridden tighter (but not looser without `sidereal-security-override` and an audit record).

| Parameter | High (default) | Moderate | Low | Constraint |
|---|---|---|---|---|
| `probe.intervalSeconds` | 21600 (6hr) | 86400 (24hr) | 259200 (72hr) | 300–86400 |
| `audit.retentionDays` | 365 | 365 | 180 | ≥ value for impact level |
| `audit.siemRetentionYears` | 3 | 3 | 1 | Documented minimum; enforced at SIEM |
| `audit.failClosedOnExportFailure` | `true` | `false` | `false` | Recommended `true` for High |
| `global.executionMode` | `dryRun` | `dryRun` | `dryRun` | `dryRun`, `observe`, `enforce` |

### Security-Relevant Parameters

| Parameter | Constraint | Default | Rationale |
|---|---|---|---|
| `global.impactLevel` | `high`, `moderate`, `low` | `high` | FIPS 199 impact level; cascades defaults above |
| `global.executionMode` | `dryRun`, `observe`, `enforce` | `dryRun` | See Execution Modes section |
| `tls.required` | Must be `true` | `true` | Disabling TLS is not a valid configuration |
| `global.fips` | bool | `true` on FIPS variant | FIPS cannot be disabled on FIPS images |
| `global.requireAdmissionController` | bool | `true` | Escape hatch requires `sidereal-security-override` role |
| `crosswalk.installDefaults` | bool | `true` | Install the seven built-in `SiderealFramework` resources |
| `audit.exportFormat` | `json`, `cef`, `leef`, `syslog`, `ocsf` | `json` | SIEM export record format |

Schema constraints are enforced at Helm install and upgrade time by the schema validation webhook, preventing drift from the approved security configuration.

**CM-3 (Configuration Change Control)**: Changes to security-relevant Helm values require the `sidereal-security-override` role and generate an audit record (see Bootstrap section). The Helm release history serves as the change log. Changes to probe definitions (`SiderealProbe` resources) that transition `executionMode` from `dryRun` to `observe` or `enforce` require the `sidereal-live-executor` role.

**CM-7 (Least Functionality)**: Sidereal components expose only the ports and APIs required for operation. No debug endpoints, admin APIs, or unnecessary services are enabled by default.

**CM-8 (Component Inventory)**: An SBOM is generated and published with each Sidereal release covering all Go and Rust dependencies, base images, and Helm chart dependencies. The SBOM is the CM-8 component inventory for Sidereal.

**Helm chart integrity**: The Sidereal Helm chart is signed with cosign and the signature verified before installation. Helm upgrade operations that modify security-relevant values require the `sidereal-security-override` role. The Helm chart itself is subject to the same supply chain controls as probe images.

---

## Key Design Constraints

- Sidereal itself must not be a privilege escalation vector; the controller and probe runner ServiceAccounts are strictly separated
- Detection probes require explicit AO authorization; unauthorized adversarial probing of federal infrastructure is not permitted
- Probe result integrity is cryptographically enforced end-to-end via HMAC; tampered results are detected and recorded
- `SiderealProbeResult` resources are immutable after creation, enforced at admission by the configured admission controller — not by convention
- `dryRun` execution mode is the default; graduated adoption via `observe` → `enforce` requires the `sidereal-live-executor` role
- All cryptographic operations use FIPS 140-2 validated modules (BoringCrypto for Go, aws-lc-rs for Rust)
- Minimum audit record retention is impact-level-dependent (365 days at High/Moderate, 180 days at Low); SIEM retention is 3 years at High/Moderate, 1 year at Low
- Production-safe blast radius controls are enforced at the infrastructure layer, not just by convention
- Custom probes are subject to identical security controls as built-in probes — no escape hatch from image signing, HMAC, or pod security
- Control mappings are defined as `SiderealFramework` CRDs — agencies add or update frameworks with `kubectl apply`, no rebuild required
- Discovery is a core controller capability; the primary onboarding path is review-and-promote, not author-from-scratch

---

## Control Discovery and Probe Generation

Control discovery is Sidereal's **primary onboarding path**. An ISSO deploying Sidereal should not need to hand-author `SiderealProbe` YAML — they should install Sidereal, review the automatically generated recommendations, and promote the ones that match their security plan.

**This is not a compliance scanner.** Discovery does not tell you whether your controls are correct or sufficient — that is the domain of tools like Kubescape and kube-bench. Discovery tells you "here are the controls you have; here are the probes that would continuously verify they are working." It is onboarding automation for Sidereal's own configuration.

### SiderealProbeRecommendation CRD

Discovery produces `SiderealProbeRecommendation` resources — a dedicated CRD in Sidereal's API group that represents a suggested probe configuration awaiting operator review. Recommendations are not probes — they do not execute. They exist solely as a review surface.

| Field | Type | Description |
|---|---|---|
| `spec.sourceResource` | ObjectReference | The cluster resource that triggered this recommendation (e.g., a specific NetworkPolicy) |
| `spec.sourceResourceHash` | string | Hash of the source resource spec at discovery time — used for change detection |
| `spec.confidence` | enum | `high`, `medium`, `low` — how confident discovery is in the generated probe configuration |
| `spec.probeTemplate` | SiderealProbeSpec | The proposed probe configuration (always `executionMode: dryRun`) |
| `spec.rationale` | string | Human-readable explanation of why this probe was recommended |
| `spec.controlMappings` | map[string][]string | Compliance framework controls this probe would validate |
| `status.state` | enum | `pending`, `promoted`, `dismissed`, `superseded` |
| `status.promotedTo` | string | Name of the `SiderealProbe` resource if promoted |
| `status.dismissedBy` | string | Kubernetes username who dismissed, if dismissed |
| `status.dismissedReason` | string | Stated reason for dismissal |

**Lifecycle**: `pending` → `promoted` (operator creates a SiderealProbe from the template) or `dismissed` (operator explicitly rejects). If the source resource changes (detected via `sourceResourceHash`), a new recommendation is created and the old one transitions to `superseded`. Dismissed recommendations are not re-generated for the same source resource unless the source resource changes.

### Controller-Driven Discovery (Default)

Discovery is a **core controller capability**, not an optional CronJob. On startup and on a configurable schedule (default: every 6 hours, aligned with the High baseline probe cadence), the controller's discovery reconciler:

1. Scans the cluster for discoverable resources (see table below)
2. Generates `SiderealProbeRecommendation` CRs for any resource not already covered by an existing `SiderealProbe` or a non-dismissed recommendation
3. Detects changes to source resources backing existing probes and creates `superseded` recommendations with updated configurations

Discovery runs with the `sidereal-discovery` ServiceAccount, which has read-only permissions across the cluster. It never creates probes, never enables live execution, and never modifies existing resources.

The operator's first interaction after install is: `kubectl get siderealproberecommendations` — review, promote, or dismiss.

### Discoverable Resources

| Cluster Resource | Generated Probe Type | Derivation |
|---|---|---|
| `NetworkPolicy` | `netpol` | Deny and allow paths derived from `podSelector`, `namespaceSelector`, `ports`. Uses `targetNamespaceSelector` when multiple namespaces share the same policy shape. |
| `ValidatingWebhookConfiguration` / Kyverno `ClusterPolicy` / OPA `ConstraintTemplate` | `admission` | Known-bad spec derived from policy schema; skeleton generated for generic webhooks |
| `RoleBinding` / `ClusterRoleBinding` | `rbac` | Allow-path and cross-namespace deny-path tests derived from binding scope |
| `Secret` resources across namespaces | `secret` | Cross-namespace access denial probes; high-value Secrets prioritized by type (TLS, dockerconfigjson, opaque with size > threshold) |
| Falco rules / Tetragon `TracingPolicy` | `detection` | Rule syscall triggers mapped to MITRE technique IDs in the approved catalog |

### Output and Safety Model

All recommendations are generated with:
- `spec.probeTemplate.executionMode: dryRun` — always; discovery never enables live execution
- `spec.confidence` — explicitly communicated so the operator knows which recommendations need manual review versus which are high-confidence
- `spec.controlMappings` — pre-populated with all active framework mappings so the ISSO can see which compliance controls would be covered

Discovery is read-only. It never creates probes automatically. The `sidereal-live-executor` role is still required to enable live execution on any promoted probe.

### CLI Interface

The `sidereal discover` CLI provides the same discovery capability for offline use, GitOps workflows, or pre-install planning:

```bash
sidereal discover --output probes/                              # All probe types → YAML files
sidereal discover --type netpol --namespace production          # Scoped to a surface and namespace
sidereal discover --type detection --output probes/detection.yaml
sidereal discover --dry-run                                     # Preview only, no file output
sidereal discover --kubeconfig ~/.kube/staging                  # Target a different cluster
sidereal discover --promote recommendations/                    # Generate SiderealProbe YAML from exported recommendations
```

### Promotion Workflow

Promoting a recommendation to a live probe is a deliberate operator action:

```bash
# Review pending recommendations
kubectl get siderealproberecommendations --field-selector status.state=pending

# Inspect a specific recommendation
kubectl describe siderealproberecommendation netpol-deny-prod-to-staging-abc123

# Promote: creates a SiderealProbe from the recommendation template
kubectl sidereal promote netpol-deny-prod-to-staging-abc123

# Or promote via YAML export + manual edit + apply (GitOps-compatible)
kubectl get siderealproberecommendation netpol-deny-prod-to-staging-abc123 -o yaml \
  | sidereal extract-probe \
  | kubectl apply -f -

# Dismiss with reason
kubectl sidereal dismiss netpol-deny-prod-to-staging-abc123 --reason "Covered by existing probe set"
```

The `kubectl sidereal` plugin is shipped with the Sidereal CLI binary. The promote and dismiss commands are convenience wrappers — all operations are also achievable via standard `kubectl` against the CRD API.

### Discovery Metrics

Discovery activity is observable via Prometheus:
- `sidereal_discovery_recommendations_total` (counter; labels: probe_type, confidence) — total recommendations generated
- `sidereal_discovery_pending_recommendations` (gauge; labels: probe_type) — current pending recommendations awaiting review
- `sidereal_discovery_coverage_ratio` (gauge; labels: probe_type) — ratio of discoverable resources that have a corresponding active `SiderealProbe`

---

## Differentiation from Existing Tooling

| Tool | Continuous | Active Probing | Detection Validation | Multi-Framework Mapped | SIEM Audit Export | Report Generation | Custom Probes | OSS/CNCF-fit |
|---|---|---|---|---|---|---|---|---|
| Kubescape / kube-bench | No | No | No | Partial (800-53) | No | No | No | Yes |
| Stratus Red Team | No | Yes | No | No | No | No | Yes | Yes |
| Falco / Tetragon | Yes | No (reactive) | No | No | Partial | No | Yes (rules) | Yes |
| Cymulate / AttackIQ | Yes | Yes | Yes | Partial | Yes | Yes | Yes | No (commercial) |
| AccuKnox | Yes | No (reactive) | No | No | No | No | No | Partial |
| **Sidereal** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** |

---

## Summary

Federal systems need more than a passing scan — they need continuous, evidence-backed proof that security controls are operationally effective. Existing tools tell you your controls are configured correctly. Sidereal tells you they are **actually working** — right now, continuously, including the detection layer, with every result mapped to the compliance frameworks your agency requires and exported to your SIEM as ATO evidence.

Sidereal is designed to be adopted by any ISSO regardless of their agency's specific technology stack, compliance regime, or operational maturity:

- **Any compliance framework**: NIST 800-53, CMMC, CJIS, IRS 1075, HIPAA, or custom crosswalks — configured, not hardcoded
- **Any impact level**: High, Moderate, or Low baseline — with appropriate defaults cascaded automatically
- **Any Kubernetes platform**: EKS, AKS, GKE, RKE2, or bare-metal Cilium/Calico — with pre-built profiles and degraded-capability transparency
- **Any adoption pace**: `dryRun` → `observe` → `enforce` — graduated modes so the ISSO can validate before committing to incident pipelines
- **Any probe surface**: Five built-in surfaces plus a custom probe extension model for agency-specific controls
- **Any reporting need**: Automated continuous monitoring reports, POA&M generation, coverage matrices, and OSCAL-native evidence packages

There is no cloud-native, open-source equivalent in the CNCF landscape that satisfies all of these requirements simultaneously. Sidereal fills that gap.
