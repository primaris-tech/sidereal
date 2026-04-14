# Sidereal

### Continuous Security Control Validation for Kubernetes

*Sidereal measures true security posture, not the apparent position.*

Most security tools tell you your controls are **configured**. Sidereal tells you they are **actually working**, continuously, with every result mapped to the compliance frameworks your agency requires and packaged into the reports your ISSO needs.

---

## The Problem

Federal systems running on Kubernetes face a gap that no existing open-source tool closes in a single, continuous operator.

**Configuration is not enforcement.** A NetworkPolicy can be defined and not enforcing. An admission webhook can be configured and silently disabled. A Falco rule can be deployed and suppressed by a config change. Between the last scan and this moment, any of these controls could have drifted. That drift is exactly where real-world compromises happen and where ATO evidence goes stale.

**The swivel chair.** Today, an ISSO validating Kubernetes security controls pivots between a constellation of disconnected tools: run Kubescape for posture, check Falco dashboards for detection, query the SIEM for audit records, manually crosswalk findings to NIST 800-53 (or CMMC, or CJIS, or IRS 1075), hand-build continuous monitoring reports, generate POA&M entries from spreadsheets, and package evidence for assessors. Each tool covers one piece. None of them connect the pieces. The ISSO becomes the integration layer, and that doesn't scale.

**Point-in-time is not continuous monitoring.** NIST 800-137 requires ongoing validation of security controls. A scan that ran at 2 AM doesn't tell you whether your controls are working at 2 PM. The gap between scans is the gap in your evidence, and your assessor knows it.

---

## What Sidereal Does

Sidereal is a Kubernetes-native operator that **actively probes** your cluster's security controls on a continuous schedule, **verifies they are operationally effective**, and **produces the compliance evidence and reports** your ISSO needs from a single tool.

| Probe Surface | What It Validates |
|---|---|
| **RBAC** | ServiceAccount permission boundaries are enforced and actually denying unauthorized operations |
| **NetworkPolicy** | East-west traffic restrictions are actively blocking unauthorized paths, verified against the CNI enforcement layer's own verdict |
| **Admission Control** | Admission controller policies reject non-compliant workload specs, including privileged containers, hostPath mounts, and capability escalations |
| **Secret Access** | Workloads cannot enumerate or access secrets outside their authorized namespace |
| **Detection Coverage** | Known-bad behaviors trigger expected alerts in your detection pipeline (Falco/Tetragon). Validates the detection layer by firing a real probe and independently confirming the alert was raised |
| **Custom** | Operator-extensible probe surface for agency-specific controls (encryption at rest, certificate expiration, service mesh mTLS, logging pipeline integrity, etc.) |

### One Tool, Not Six

Sidereal eliminates the swivel chair by collapsing what previously required multiple disconnected tools and manual processes into a single continuous loop:

| Before Sidereal | With Sidereal |
|---|---|
| Run Kubescape/kube-bench for posture scanning | Sidereal continuously probes all control surfaces |
| Manually verify detection rules are working | Detection probes fire real syscalls and confirm alerts were raised |
| Query SIEM for evidence, hope the format is right | Structured audit records exported automatically in your SIEM's native format (JSON, CEF, LEEF, Syslog, OCSF) |
| Crosswalk findings to NIST/CMMC/CJIS manually | Every result tagged with all active compliance framework controls automatically |
| Hand-build monthly continuous monitoring reports | `sidereal report continuous-monitoring --format pdf` |
| Generate POA&M entries from spreadsheets | `sidereal report poam --open-incidents-only --format csv` |
| Package evidence for assessors manually | `sidereal report evidence-package --format zip` |
| Repeat across every namespace, every month | One `SiderealProbe` with a label selector covers all matching namespaces continuously |

---

## Key Capabilities

### Continuous Active Validation
Probes run on configurable schedules (default: every 6 hours for High-impact systems) with execution jitter to prevent predictable blind spots. Probes fire real actions against real enforcement layers and read real verdicts, not cached configuration state.

### Detection Layer Validation
Sidereal fires a known-bad syscall pattern from a sandboxed container, then the controller independently queries the detection backend (Falco or Tetragon) to verify an alert was raised. Two separate identities, two separate actions. If the detection pipeline missed it, Sidereal surfaces the gap.

### Multi-Framework Compliance Mapping
Probe results are tagged with controls from every active compliance framework: NIST 800-53, CMMC, CJIS, IRS 1075, HIPAA, NIST 800-171, and the Kubernetes STIG. Frameworks are managed as `SiderealFramework` CRDs — agencies add or customize frameworks with a `kubectl apply`, no rebuild required.

### Report Generation
Sidereal generates continuous monitoring summaries, POA&M entries, control coverage matrices, executive summaries, and OSCAL-native assessment evidence packages directly from probe results, with zero manual assembly.

### Graduated Adoption
Three execution modes provide a safe adoption path:
- **`dryRun`**: validates configuration without executing probes (default on install)
- **`observe`**: probes execute live, results are recorded, but no incidents are generated (evaluation period)
- **`enforce`**: full operation with incident creation and IR webhook delivery

### Configurable Impact Level
Set `global.impactLevel: high | moderate | low` once, and Sidereal cascades appropriate defaults for probe cadence, audit retention, and fail-closed behavior. No manual tuning of 15 parameters to match your baseline.

### Namespace Label Selectors
One probe definition with `targetNamespaceSelector` covers all matching namespaces. No more managing hundreds of per-namespace probe definitions for large clusters.

### Discovery as Primary Onboarding
Sidereal scans your cluster for existing security controls and generates `SiderealProbeRecommendation` resources. The ISSO's first interaction is reviewing and promoting recommendations rather than authoring YAML from scratch.

### Custom Probe Extensibility
A standardized input/output contract lets agencies build probes for controls Sidereal doesn't cover natively. Custom probes are subject to the same security controls as built-in probes: image signing, HMAC integrity, pod security, admission verification.

### Normalized Outcomes
Every probe result carries a `controlEffectiveness` field (`Effective`, `Ineffective`, `Degraded`, or `Compromised`) derived from the raw outcome. Dashboards, reports, and alerting consume this normalized field without needing to understand 12 probe-specific outcome values.

---

## Architecture at a Glance

Sidereal is deployed as a Kubernetes operator via Helm into the `sidereal-system` namespace.

```
Controller Manager (Go / BoringCrypto FIPS)
  ├── Probe Scheduler: schedules probe Jobs with per-execution HMAC keys
  ├── Result Reconciler: verifies HMAC signatures, writes audit records
  ├── Discovery Reconciler: scans cluster, generates probe recommendations
  ├── Report Generator: produces formatted compliance reports
  └── Audit Export Pipeline: exports to SIEM in configurable format

Probe Runner Jobs (ephemeral, one per execution)
  ├── RBAC, NetworkPolicy, Admission, Secret Access: Go, non-root, read-only FS
  └── Detection: Rust/FIPS, no network, no mounts, custom seccomp

Per-Probe ServiceAccounts (strict privilege isolation)
  └── 7 built-in + operator-registered custom probe SAs
```

**Key design property:** The controller cannot perform probe operations. Probe runners cannot write their own results. HMAC verification ensures a compromised component cannot produce falsified evidence. See the [engineering specification](sidereal-engineering-summary.md) for the full architecture.

---

## Deployment Profiles

Sidereal references abstract capabilities rather than specific tools. Select a deployment profile that matches your cluster's stack, and Sidereal renders the correct admission policies, backend connections, and compliance documentation.

| Profile | Admission | Detection | CNI Observability | Target Platform |
|---|---|---|---|---|
| `kyverno-cilium-falco` | Kyverno | Falco | Hubble (cni-verdict) | Cilium-based clusters |
| `opa-calico-tetragon` | OPA/Gatekeeper | Tetragon | Calico (cni-verdict) | Calico-based clusters |
| `kyverno-eks` | Kyverno | Falco | tcp-inference | Amazon EKS |
| `opa-aks` | OPA/Gatekeeper | Falco | tcp-inference | Azure AKS |
| `kyverno-gke` | Kyverno | Falco | tcp-inference | Google GKE |
| `opa-rke2` | OPA/Gatekeeper | Tetragon | tcp-inference | RKE2/k3s on-premises |

Custom profiles are supported for any combination of supported implementations.

---

## Project Status

Sidereal **v0.1.0** is feature-complete. The operator is fully implemented and ready for initial deployment and testing.

**What's included:**
- All 9 CRDs and 7 controller reconcilers
- 5 built-in probe runners (RBAC, NetworkPolicy, Admission, Secret, Detection) plus custom probe extensibility
- Rust detection probe with MITRE ATT&CK technique catalog
- HMAC result integrity with per-execution HKDF-SHA256 key derivation
- Multi-framework compliance mapping (7 frameworks)
- SIEM export pipeline (5 formats, 3 backends)
- Incident controller with IR webhook delivery
- Discovery reconciler with probe recommendation lifecycle
- Report generation (5 report types)
- Helm chart with 6 deployment profiles
- FIPS 140-2 build configuration (BoringCrypto for Go, aws-lc-rs for Rust)
- CI/CD pipeline (GitHub Actions with image signing, SBOM, Trivy scanning)
- 260 Go unit tests + 8 Rust tests + 46 E2E integration tests

**Documentation:**
- **[Engineering Specification](sidereal-engineering-summary.md)**: canonical design document covering architecture, probe design, blast radius controls, key management, and development security lifecycle
- **[Compliance Package](compliance/)**: complete ATO documentation package with 40 OSCAL controls, SSP/SAP templates, CRM, 6 deployment profile binding documents, and architecture diagrams

---

## Documentation

| Document | Description |
|---|---|
| [Getting Started Guide](docs/getting-started.md) | Step-by-step deployment on a kind cluster with your first probe |
| [Example Manifests](examples/) | Sample SiderealProbe, AO Authorization, and namespace selector configurations |
| [Engineering Specification](sidereal-engineering-summary.md) | Canonical design document covering architecture, probe design, security model, and all design decisions |
| [Compliance README](compliance/README.md) | Guide to the ATO documentation package |
| [Customer Responsibility Matrix](compliance/crm/customer-responsibility-matrix.md) | Control-by-control responsibility split between Sidereal and the deploying agency |
| [SSP Template](compliance/ssp/system-security-plan-template.md) | Pre-filled System Security Plan for agency customization |
| [SAP Template](compliance/sap/security-assessment-plan-template.md) | Security Assessment Plan with 33 test procedures |

---

## Differentiation

| Capability | Kubescape / kube-bench | Stratus Red Team | Falco / Tetragon | Commercial BAS | **Sidereal** |
|---|---|---|---|---|---|
| Continuous | No | No | Yes (reactive) | Yes | **Yes (active)** |
| Active probing | No | Yes (manual) | No | Yes | **Yes (automated)** |
| Detection validation | No | Yes (manual) | No | Yes | **Yes (automated)** |
| Multi-framework mapping | Partial | No | No | Partial | **Yes (7 frameworks)** |
| Report generation | No | No | No | Yes | **Yes (5 report types)** |
| Custom probes | No | Yes | Yes (rules) | Yes | **Yes** |
| SIEM export (multi-format) | No | No | Partial | Yes | **Yes (5 formats)** |
| OSCAL-native evidence | No | No | No | No | **Yes** |
| OSS / CNCF-fit | Yes | Yes | Yes | No | **Yes** |

---

## Quick Start

### Prerequisites

- Kubernetes cluster (1.28+)
- Helm 3.12+
- An admission controller (Kyverno or OPA/Gatekeeper)
- A detection backend (Falco or Tetragon) for detection probes

### Install

```bash
# Add the Sidereal Helm repository
helm install sidereal oci://ghcr.io/primaris-tech/charts/sidereal \
  --namespace sidereal-system \
  --create-namespace \
  --set profile.name=kyverno-cilium-falco \
  --set global.impactLevel=moderate \
  --set global.executionMode=dryRun
```

### Discover existing controls

```bash
# Let Sidereal scan your cluster and generate probe recommendations
kubectl get siderealproberecommendations -n sidereal-system

# Or use the CLI for an offline preview
sidereal discover --dry-run
```

### Promote a recommendation to an active probe

```bash
# Review a recommendation
kubectl describe sprec <recommendation-name> -n sidereal-system

# Promote it (creates a SiderealProbe in dryRun mode)
kubectl patch sprec <recommendation-name> -n sidereal-system \
  --type merge --subresource status \
  -p '{"status":{"state":"promoted","promotedTo":"<probe-name>"}}'
```

### Graduate to live execution

```bash
# Move from dryRun to observe (probes execute, no incidents)
kubectl patch siderealprobe <probe-name> -n sidereal-system \
  --type merge -p '{"spec":{"executionMode":"observe"}}'

# After validation, move to enforce (full incident pipeline)
kubectl patch siderealprobe <probe-name> -n sidereal-system \
  --type merge -p '{"spec":{"executionMode":"enforce"}}'
```

### Generate reports

```bash
# Continuous monitoring summary
sidereal report continuous-monitoring --format markdown

# POA&M with open incidents
sidereal report poam --open-incidents-only --format csv

# Evidence package for assessors
sidereal report evidence-package --format zip
```

### View results

```bash
# Check probe results
kubectl get siderealproberesults -n sidereal-system

# Check incidents (enforce mode only)
kubectl get siderealincidents -n sidereal-system

# Check system alerts
kubectl get siderealsystemalerts -n sidereal-system
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and pull request requirements.

---

## License

Sidereal is licensed under the [Apache License 2.0](LICENSE).

---

## Known Issues

| CVE | Severity | Component | Impact | Status |
|---|---|---|---|---|
| CVE-2026-0861 | HIGH | glibc 2.36 (base-debian12) | Integer overflow in memalign. Exploitation requires attacker control of size and alignment arguments near PTRDIFF_MAX, which is not reachable in Sidereal's single-purpose containers. | No fix available in Debian bookworm. Debian classified as minor (`<no-dsa>`). Will remediate when bookworm backport is released or when migrating to Debian 13 base images. |

The detection probe image (`scratch` base) is not affected.

---

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting. We use GitHub's private vulnerability reporting feature. Please do not open public issues for security vulnerabilities.
