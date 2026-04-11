# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

Gauntlet is in the **pre-implementation phase**. The repository contains:
- Engineering specification (`gauntlet-engineering-summary.md`) — the canonical design document
- Complete Phase 1 ATO documentation package under `compliance/`
- No implementation code yet — the implementation plan is at `.claude/plans/keen-bouncing-unicorn.md`

## What Gauntlet Is

A Kubernetes-native security operator for **continuous security control validation** on federal systems (FISMA, FedRAMP, NIST 800-53). It runs targeted, low-impact probes against a live cluster to verify that security controls are *operationally effective* — not merely configured. Differentiated from existing tools (Kubescape, Stratus Red Team, Falco) by being the only OSS/CNCF-fit tool that is simultaneously continuous, actively probing, and validates the detection layer.

Probe surfaces: RBAC, NetworkPolicy, Admission Control, Secret Access, and Detection Coverage (Falco/Tetragon).

## Architecture

**Deployment**: Kubernetes Operator pattern deployed via Helm into `gauntlet-system` namespace.

**Implementation stack**:
- Controller Manager: Go with kubebuilder/controller-runtime, BoringCrypto FIPS (CMVP #3678)
- Go probe runners: RBAC, NetworkPolicy, Admission Control, Secret Access
- Rust detection probe: aws-lc-rs FIPS (CMVP #4816), scratch base, no network/no mounts

**Core CRDs** (5 total, API group `gauntlet.io/v1alpha1`):
- `GauntletProbe` — probe configuration; maps to MITRE ATT&CK technique + NIST controls; includes `targetNamespace`, `dryRun`, `intervalSeconds`
- `GauntletProbeResult` — append-only audit record; HMAC-verified; 365-day minimum TTL; unified outcome enum (Pass/Fail/Detected/Undetected/Blocked/Rejected/Accepted/NotApplicable/BackendUnreachable/NotEnforced/Indeterminate/TamperedResult)
- `GauntletIncident` — control failure record; created on probe Fail; delivers to IR webhook
- `GauntletSystemAlert` — degraded state indicator; requires individual principal acknowledgment before probes resume
- `GauntletAOAuthorization` — AO authorization for detection probes; time-bounded, technique-scoped, namespace-scoped

**Component separation** (strict privilege isolation):
- **Controller Manager** — orchestrates scheduling; holds only Job-creation + CRD read/write permissions; never holds probe-class permissions directly
- **Probe Runner Jobs** — short-lived, immutable Kubernetes Jobs; one Job per probe execution; TTL-based cleanup; non-root, read-only root filesystem, caps DROP ALL
- **Per-Probe ServiceAccounts** — 6 total (`gauntlet-controller`, `gauntlet-probe-rbac`, `gauntlet-probe-netpol`, `gauntlet-probe-admission`, `gauntlet-probe-secret`, `gauntlet-probe-detection`), each with minimum required RBAC and nothing else

**Detection probe flow**: The probe fires a synthetic syscall pattern and exits; the *controller* independently queries the detection backend (Falco/Tetragon) every 5s for 60s to verify the alert was raised. Two separate identities, two separate actions. Requires active `GauntletAOAuthorization`.

**HMAC result integrity**: Per-execution key derived via HKDF-SHA256 from a KMS-encrypted root Secret. Probe signs result, controller verifies. Invalid signature → `TamperedResult` outcome + `GauntletSystemAlert` + probe surface suspended.

**Pluggable backend interfaces**:
- `DetectionBackend` — Falco gRPC (:50051), Tetragon gRPC (:54321)
- `NetworkPolicyBackend` — Hubble gRPC (:4245), Calico REST (:5443)
- `AuditExportBackend` — Splunk HEC, Elasticsearch, S3 (SSE-KMS + Object Lock COMPLIANCE)

## Key Design Constraints

- `dryRun: true` is the **default** on fresh install; live execution requires explicit opt-in via `gauntlet-live-executor` role
- Every probe action carries a mandatory fingerprint label (`gauntlet.io/probe-id`) — unfingerpinted actions do not execute
- Controller's ServiceAccount may only create Jobs referencing pre-approved probe ServiceAccounts (enforced via admission enforcement policy — Kyverno or OPA per deployment profile)
- A `ResourceQuota` on `gauntlet-system` caps concurrent probe Jobs
- Detection probe containers: custom seccomp profile, all capabilities dropped, no network, no volume mounts, no credentials
- Probe images pinned by digest (never by tag); distroless or scratch base; cosign-signed with admission-layer verification at every Pod admission
- FIPS 140-2 validated cryptography exclusively (BoringCrypto for Go, aws-lc-rs for Rust)
- All audit records append-only (admission enforcement policy denies UPDATE/DELETE on GauntletProbeResult)
- `values.schema.json` enforces: `intervalSeconds` 300–86400, `retentionDays` ≥ 365, `tls.required` must be true

## Repository Structure

```
gauntlet/
├── gauntlet-engineering-summary.md     # Canonical engineering specification
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
- **Compile**: `trestle assemble component-definition -n gauntlet`
- **Validate**: `oscal-cli component-definition validate -f trestle-workspace/component-definitions/gauntlet/component-definition.json`
- **Lula** (Defense Unicorns) — deferred; do not include yet

## Key Decisions

- NIST 800-53 **High** baseline (not Moderate)
- Self-hosted per-agency deployment model (FedRAMP managed service deferred)
- **Deployment profile abstraction**: Gauntlet references abstract capabilities, not specific tools. Two pre-built profiles ship: `kyverno-cilium-falco` and `opa-calico-tetragon`. Custom profiles supported.
- **NetworkPolicy three verification modes**: `cni-verdict` (Hubble/Calico), `tcp-inference` (any CNI), `responder` (Gauntlet-deployed pod)
- CVE SLAs: Critical 30 days, High 60 days, Medium 90 days
- Supply chain: cosign signatures + CycloneDX SBOM + SLSA Level 2 provenance + Sigstore Rekor transparency log
- `gauntlet discover` CLI for control discovery and probe generation (ships with v1, not deferred)
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
