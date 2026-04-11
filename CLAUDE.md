# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

Sidereal is in the **pre-implementation phase**. The repository contains:
- Engineering specification (`sidereal-engineering-summary.md`) — the canonical design document
- Complete ATO documentation package under `compliance/`
- No implementation code yet — the implementation plan is at `.claude/plans/keen-bouncing-unicorn.md`

**Repo**: `primaris-tech/sidereal` on GitHub (private). Branch protection not yet configured (requires GitHub Team plan or public repo).

**Before writing implementation code**: YubiKey SSH signing must be set up, branch protection must be configured, and CODEOWNERS must be in place. See "Development Security" section below and the engineering spec's "Development Security Lifecycle" section.

## What Sidereal Is

A Kubernetes-native security operator for **continuous security control validation** on federal systems (FISMA, FedRAMP, NIST 800-53, CMMC, CJIS, and other frameworks). It runs targeted, low-impact probes against a live cluster to verify that security controls are *operationally effective* — not merely configured. Differentiated from existing tools (Kubescape, Stratus Red Team, Falco) by being the only OSS/CNCF-fit tool that is simultaneously continuous, actively probing, validates the detection layer, supports multi-framework compliance mapping, and generates ISSO-ready reports.

Probe surfaces: RBAC, NetworkPolicy, Admission Control, Secret Access, Detection Coverage (Falco/Tetragon), and Custom (operator-extensible).

## Architecture

**Deployment**: Kubernetes Operator pattern deployed via Helm into `sidereal-system` namespace.

**Implementation stack**:
- Controller Manager: Go with kubebuilder/controller-runtime, BoringCrypto FIPS (CMVP #3678)
- Go probe runners: RBAC, NetworkPolicy, Admission Control, Secret Access
- Rust detection probe: aws-lc-rs FIPS (CMVP #4816), scratch base, no network/no mounts

**Core CRDs** (8 total, API group `sidereal.cloud/v1alpha1`):
- `SiderealProbe` — probe configuration; maps to MITRE ATT&CK technique + multi-framework controls; includes `targetNamespace` or `targetNamespaceSelector`, `executionMode` (`dryRun`/`observe`/`enforce`), `intervalSeconds`; supports built-in and `custom` probe types
- `SiderealProbeResult` — append-only audit record; HMAC-verified; TTL per impact level (365d High/Moderate, 180d Low); unified outcome enum + derived `controlEffectiveness` (Effective/Ineffective/Degraded/Compromised); `controlMappings` for multi-framework tagging
- `SiderealIncident` — control failure record; created only in `enforce` execution mode when `controlEffectiveness` is `Ineffective` or `Compromised`; delivers to IR webhook
- `SiderealSystemAlert` — degraded state indicator; requires individual principal acknowledgment before probes resume
- `SiderealAOAuthorization` — AO authorization for detection probes; time-bounded, technique-scoped, namespace-scoped
- `SiderealProbeRecommendation` — discovery-generated probe suggestion; `pending`/`promoted`/`dismissed`/`superseded` lifecycle; primary onboarding surface
- `SiderealReport` — (optional) scheduled report generation; continuous monitoring summaries, POA&M, coverage matrices, evidence packages
- (Custom probe ServiceAccount registrations are configured via Helm values, not a CRD)

**Component separation** (strict privilege isolation):
- **Controller Manager** — orchestrates scheduling; holds only Job-creation + CRD read/write permissions; never holds probe-class permissions directly
- **Probe Runner Jobs** — short-lived, immutable Kubernetes Jobs; one Job per probe execution; TTL-based cleanup; non-root, read-only root filesystem, caps DROP ALL
- **Per-Probe ServiceAccounts** — 7 built-in (`sidereal-controller`, `sidereal-probe-rbac`, `sidereal-probe-netpol`, `sidereal-probe-admission`, `sidereal-probe-secret`, `sidereal-probe-detection`, `sidereal-discovery`) plus operator-registered custom probe ServiceAccounts, each with minimum required RBAC and nothing else

**Detection probe flow**: The probe fires a synthetic syscall pattern and exits; the *controller* independently queries the detection backend (Falco/Tetragon) every 5s for 60s to verify the alert was raised. Two separate identities, two separate actions. Requires active `SiderealAOAuthorization`.

**HMAC result integrity**: Per-execution key derived via HKDF-SHA256 from a KMS-encrypted root Secret. Probe signs result, controller verifies. Invalid signature → `TamperedResult` outcome + `SiderealSystemAlert` + probe surface suspended.

**Pluggable backend interfaces**:
- `DetectionBackend` — Falco gRPC (:50051), Tetragon gRPC (:54321)
- `NetworkPolicyBackend` — Hubble gRPC (:4245), Calico REST (:5443)
- `AuditExportBackend` — Splunk HEC, Elasticsearch, S3 (SSE-KMS + Object Lock COMPLIANCE); configurable export formats: JSON, CEF, LEEF, Syslog (RFC 5424), OCSF

## Key Design Constraints

- `executionMode: dryRun` is the **default** on fresh install; graduated adoption via `observe` → `enforce` requires `sidereal-live-executor` role
- FIPS 199 impact level (`global.impactLevel: high | moderate | low`) cascades defaults for cadence, retention, and fail-closed behavior
- Every probe action carries a mandatory fingerprint label (`sidereal.cloud/probe-id`) — unfingerpinted actions do not execute
- Controller's ServiceAccount may only create Jobs referencing pre-approved probe ServiceAccounts (enforced via admission enforcement policy — Kyverno or OPA per deployment profile)
- A `ResourceQuota` on `sidereal-system` caps concurrent probe Jobs
- Detection probe containers: custom seccomp profile, all capabilities dropped, no network, no volume mounts, no credentials
- Probe images pinned by digest (never by tag); distroless or scratch base; cosign-signed with admission-layer verification at every Pod admission
- FIPS 140-2 validated cryptography exclusively (BoringCrypto for Go, aws-lc-rs for Rust)
- All audit records append-only (admission enforcement policy denies UPDATE/DELETE on SiderealProbeResult)
- `values.schema.json` enforces: `intervalSeconds` 300–86400, retention per impact level, `tls.required` must be true
- Custom probes subject to identical security controls as built-in probes — no escape hatch
- Control mappings are data-driven crosswalk files — agencies can extend frameworks without rebuilding
- Discovery is a core controller capability — primary onboarding is review-and-promote, not author-from-scratch

## Repository Structure

```
sidereal/
├── sidereal-engineering-summary.md     # Canonical engineering specification
├── compliance/
│   ├── trestle-workspace/              # 40 OSCAL control files (Trestle markdown → OSCAL JSON)
│   ├── plans/                          # CMP, IRP, CP, PIA template, Rules of Behavior
│   ├── diagrams/                       # Authorization boundary, system architecture, data flows, network topology
│   ├── ssp/                            # System Security Plan template
│   ├── sap/                            # Security Assessment Plan template
│   ├── crm/                            # Customer Responsibility Matrix
│   └── profiles/                       # Deployment profile binding documents
└── (implementation code — not yet created)
```

## Compliance Toolchain

- **Trestle** (IBM/OSCAL Compass) for OSCAL authoring — human-readable markdown compiles to OSCAL JSON
- **Compile**: `trestle assemble component-definition -n sidereal`
- **Validate**: `oscal-cli component-definition validate -f trestle-workspace/component-definitions/sidereal/component-definition.json`
- **Lula** (Defense Unicorns) — deferred; do not include yet

## Key Decisions

- NIST 800-53 **High** baseline as default, but **impact level is configurable** (`high`/`moderate`/`low`) — cascades cadence, retention, and operational defaults
- Self-hosted per-agency deployment model (FedRAMP managed service deferred)
- **Multi-framework compliance mapping**: NIST 800-53, CMMC, CJIS, IRS 1075, HIPAA, NIST 800-171 — configurable via Helm, extensible via custom crosswalk files
- **Graduated execution modes**: `dryRun` → `observe` → `enforce` — ISSOs can validate before activating incident pipelines
- **Deployment profile abstraction**: Sidereal references abstract capabilities, not specific tools. Six pre-built profiles ship: `kyverno-cilium-falco`, `opa-calico-tetragon`, `kyverno-eks`, `opa-aks`, `kyverno-gke`, `opa-rke2`. Custom profiles supported.
- **Namespace label selectors**: `targetNamespaceSelector` in addition to explicit `targetNamespace` — one probe definition covers all matching namespaces
- **NetworkPolicy three verification modes**: `cni-verdict` (Hubble/Calico), `tcp-inference` (any CNI), `responder` (Sidereal-deployed pod)
- **Custom probe extensibility**: Standardized input/output contract for agency-specific probe surfaces
- **Discovery as primary onboarding**: `SiderealProbeRecommendation` CRD with controller-driven discovery — ISSOs review and promote, not author from scratch
- **Report generation**: CLI and optional CRD for continuous monitoring summaries, POA&M, coverage matrices, OSCAL evidence packages
- **SIEM export formats**: JSON (default), CEF, LEEF, Syslog RFC 5424, OCSF — configurable per export target
- **Normalized outcomes**: `controlEffectiveness` (Effective/Ineffective/Degraded/Compromised) derived from raw outcomes — ISSO-facing abstraction
- CVE SLAs: Critical 30 days, High 60 days, Medium 90 days
- Supply chain: cosign signatures + CycloneDX SBOM + SLSA Level 2 provenance + Sigstore Rekor transparency log
- Helm primary delivery, `helm template` static manifests generated in CI

## Development Security

- **Commit signing**: YubiKey-backed SSH resident keys (`ed25519-sk`); all commits must be signed
- **Branch protection**: PRs required, signed commits required, status checks required, no force push
- **CODEOWNERS**: Security-critical paths (`internal/hmac/`, `detection-probe/`, `build/`, `.github/workflows/`, admission policies) require 2 reviewers
- **CI hardening**: All GitHub Actions pinned by SHA (not tag); `GITHUB_TOKEN` read-only by default; CI has no access to signing infrastructure
- **Image signing**: Keyless via Sigstore OIDC (Fulcio + Rekor); KMS-backed key as alternative for air-gapped
- **Release gating**: GitHub Environment approval gate — human must approve before signing keys are accessible
- **Dependencies**: Go deps vendored (`go mod vendor`); `govulncheck` + `cargo audit` in CI; Dependabot for updates
- **Registry**: GHCR (GitHub Container Registry)
- **Account security**: FIDO2/WebAuthn (YubiKey) required for all maintainers — no TOTP/SMS
