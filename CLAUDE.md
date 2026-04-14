# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

Sidereal **v0.1.0** is feature-complete. All 22 implementation phases are done. The repository contains:
- Engineering specification (`sidereal-engineering-summary.md`) — the canonical design document
- Complete ATO documentation package under `compliance/`
- Implementation plan at `~/.claude/plans/keen-bouncing-unicorn.md` (completed)
- Full operator implementation: 9 CRDs, 7 controller reconcilers, 5 built-in probe runners + custom extensibility, Rust detection probe (9 MITRE ATT&CK techniques), HMAC integrity, multi-framework crosswalk (7 built-in frameworks via SiderealFramework CRD, agency-extensible), SIEM export (5 formats, 3 backends), incident/alert/authorization lifecycle, discovery engine with CLI, report generation (5 types), Helm chart (6 profiles), FIPS 140-2 builds, CI/CD pipeline. 260 Go tests + 15 Rust tests + 46 E2E tests.

**Repo**: `primaris-tech/sidereal` on GitHub (private).

**Status**: Tagged v0.1.0. Post-v0.1.0 work includes: community feedback, E2E test hardening on real clusters, additional crosswalk refinement, and eventual public release.

## What Sidereal Is

A Kubernetes-native security operator for **continuous security control validation** on federal systems (FISMA, FedRAMP, NIST 800-53, CMMC, CJIS, and other frameworks). It runs targeted, low-impact probes against a live cluster to verify that security controls are *operationally effective* — not merely configured. Differentiated from existing tools by being the only operator purpose-built to combine all of: continuous scheduled execution, active probing (not config analysis), detection layer validation, multi-framework federal compliance mapping, and ISSO-ready report generation. Tools like Stratus Red Team validate detections; tools like Kubescape check compliance configuration; Sidereal is the first to make those concerns a single, operator-native, scheduled workflow with ATO-ready output.

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
├── api/v1alpha1/                       # CRD type definitions (9 CRDs)
├── cmd/
│   ├── controller/                     # Controller Manager entrypoint
│   ├── probe-rbac/                     # RBAC probe runner
│   ├── probe-secret/                   # Secret Access probe runner
│   ├── probe-admission/                # Admission Control probe runner
│   ├── probe-netpol/                   # NetworkPolicy probe runner
│   ├── probe-bootstrap/                # Bootstrap verification (Helm pre-install hook)
│   └── sidereal/                       # CLI binary
├── probes/
│   ├── rbac/                           # RBAC probe logic
│   ├── secret/                         # Secret Access probe logic
│   ├── admission/                      # Admission Control probe logic
│   └── netpol/                         # NetworkPolicy probe logic
├── internal/
│   ├── controller/                     # Reconcilers (scheduler, result, incident, alert, authorization, discovery, bootstrap)
│   ├── discovery/                      # Cluster discovery engine (5 discoverers)
│   ├── hmac/                           # HMAC key derivation and verification
│   ├── probe/                          # Shared probe runner framework
│   ├── crosswalk/                      # Multi-framework control mapping (7 frameworks)
│   ├── report/                         # Report generation engine (5 report types)
│   ├── webhook/                        # IR webhook client
│   ├── metrics/                        # Prometheus metrics
│   └── backend/
│       ├── detection/                  # Falco + Tetragon gRPC backends
│       ├── networkpolicy/              # Hubble + Calico + TCP inference backends
│       └── export/                     # Splunk + Elasticsearch + S3 + 5 format serializers
├── detection-probe/                    # Rust detection probe (9 MITRE ATT&CK techniques)
├── deploy/helm/sidereal/              # Helm chart with profile-aware templates
├── build/                              # Dockerfiles (FIPS builds)
├── test/e2e/                           # E2E integration tests (envtest)
├── hack/                               # Utility scripts (FIPS verification)
└── compliance/                         # ATO documentation package
```

## Compliance Toolchain

- **Trestle** (IBM/OSCAL Compass) for OSCAL authoring — human-readable markdown compiles to OSCAL JSON
- **Compile**: `trestle assemble component-definition -n sidereal`
- **Validate**: `oscal-cli component-definition validate -f trestle-workspace/component-definitions/sidereal/component-definition.json`
- **Lula** (Defense Unicorns) — deferred; do not include yet

## Key Decisions

- NIST 800-53 **High** baseline as default, but **impact level is configurable** (`high`/`moderate`/`low`) — cascades cadence, retention, and operational defaults
- Self-hosted per-agency deployment model (FedRAMP managed service deferred)
- **Multi-framework compliance mapping**: NIST 800-53, CMMC, CJIS, IRS 1075, HIPAA, NIST 800-171, Kubernetes STIG — configurable via Helm, extensible via custom crosswalk files
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

## Git Workflow

**Branching strategy**: Feature branches merged to `main` via PR. `main` is always releasable.
- Branch naming by type: `feat/description`, `fix/description`, `chore/description`, `docs/description`
- Each PR is a coherent, deployable unit — not a week's worth of work, not a one-liner bundled with a feature
- Short-lived branches only — merge promptly
- No long-lived develop/release branches

**Release cadence**: Semantic versioning driven by what changed, not by time.
- Patch (`0.1.x`): bug fixes, security patches, dependency updates — no API surface change
- Minor (`0.x.0`): new features, new probe types, new framework crosswalks — backward-compatible
- Major (`x.0.0`): breaking CRD changes, controller API changes, anything requiring migration
- Security fixes (govulncheck, cargo audit, Trivy) should be patched and released promptly per CVE SLAs

**Deferred until multi-contributor or public release**:
- Branch protection (requires GitHub Pro/Team or public repo)
- CODEOWNERS enforcement — paths already identified: `internal/hmac/`, `detection-probe/`, `build/`, `.github/workflows/`, admission policies
- Required reviewers (1 general, 2 for CODEOWNERS-gated paths)
- Populate `release` environment approvers in GitHub

## Development Security

- **Commit signing** (active): YubiKey-backed SSH resident keys (`ed25519-sk`); all commits signed and verified on GitHub
- **Branch protection** (deferred): PRs required, signed commits required, status checks required, no force push. Blocked on GitHub plan — will enable when repo goes public or plan is upgraded.
- **CODEOWNERS** (deferred): Security-critical paths (`internal/hmac/`, `detection-probe/`, `build/`, `.github/workflows/`, admission policies) require 2 reviewers. Depends on branch protection.
- **CI hardening**: All GitHub Actions pinned by SHA (not tag); `GITHUB_TOKEN` read-only by default; CI has no access to signing infrastructure
- **Image signing**: Keyless via Sigstore OIDC (Fulcio + Rekor); KMS-backed key as alternative for air-gapped
- **Release gating**: GitHub Environment approval gate — human must approve before signing keys are accessible
- **Dependencies**: Go module proxy (no vendoring); `govulncheck` + `cargo audit` in CI; Dependabot for updates
- **Registry**: GHCR (GitHub Container Registry)
- **Account security**: FIDO2/WebAuthn (YubiKey) required for all maintainers — no TOTP/SMS
