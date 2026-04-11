---
x-trestle-comp-def-rules:
  sidereal:
    - name: helm-values-as-versioned-baseline-configuration
      description: Sidereal's Helm chart values file constitutes the versioned baseline configuration; the controller enforces that the running state matches the declared values
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: cm-02
status: implemented
---

# CM-2 — Baseline Configuration

## Control Statement

Develop, document, and maintain under configuration control a current baseline
configuration of the system that captures system components, their versions,
interconnections, and configuration settings. Review and update the baseline
configuration as part of system changes and at defined frequencies.

## Sidereal Implementation

Sidereal's baseline configuration is a first-class artifact managed by the
Helm chart release process. Every configurable aspect of the system is
declared in a single, version-controlled document: the `values.yaml` file.

### The Helm Chart as Baseline Configuration Document

The Sidereal Helm chart `values.yaml` is the authoritative baseline
configuration document. It captures every configurable parameter in the system:

- Probe schedules and FIPS 199 impact level declaration
- SIEM endpoint URLs, transport configuration, and credential references
- RBAC scope grants for per-probe ServiceAccounts
- ResourceQuota limits for the `sidereal-system` namespace
- Container image references (pinned by SHA-256 digest — never by tag)
- FIPS mode flags for Go and Rust components
- Audit record retention TTLs
- Alertmanager webhook endpoints
- SiderealAOAuthorization references for detection probes

Each Sidereal release is tagged with a semantic version (e.g., `v1.2.0`) and
a corresponding Helm chart version. The chart is published as an OCI artifact
to the Sidereal container registry, providing a durable, immutable reference
to the approved baseline at each release point.

### Image Digest Pinning

All container image references in the Helm chart are pinned by SHA-256 digest
rather than mutable tag. A tag reference like `v1.2.0` can be overwritten in
the registry; a digest reference like
`sha256:a3f2...` is immutable and unambiguously identifies the exact binary
deployed. This ensures the baseline configuration unambiguously captures the
software component inventory — a mutable tag cannot satisfy CM-2 requirements.

The CI pipeline updates digest pins automatically when new versions pass
vulnerability scanning (Grype/Trivy clean) and supply chain verification
(cosign signature present). Digest updates are reviewed as part of the release
process.

### Baseline Drift Detection

The controller performs a startup reconciliation check comparing the
currently-running configuration against the Helm-rendered expected state.
Resources in the `sidereal-system` namespace that were not created by the
Helm release (e.g., ConfigMaps modified outside of Helm) are flagged as
configuration drift.

Configuration drift produces a `SiderealSystemAlert` with
`reason: BaselineConfigurationDrift`. This alert:
- Prevents probe execution on affected surfaces until acknowledged
- Is exported to the SIEM with the drifted resource's name and diff
- Requires individual principal acknowledgment by an authorized operator

This ensures that out-of-band configuration changes — whether accidental or
adversarial — are detected, recorded, and cannot silently persist.

### Enhancement: CM-2(2) — Automation Support for Accuracy and Currency

Baseline configuration accuracy is maintained automatically. The Helm release
process generates the canonical desired-state manifest. The controller
continuously reconciles against this desired state. Digest pins are updated
by automated CI pipeline processes. Dependabot monitors dependency versions.
No manual inventory update process is required to keep the baseline current.

### Enhancement: CM-2(3) — Retention of Previous Configurations

Helm stores each release as a Kubernetes Secret in the `sidereal-system`
namespace, maintaining a complete history of all previous deployed
configurations. Any prior configuration can be retrieved via
`helm history sidereal` and rolled back via `helm rollback`. The Kubernetes
audit log records every Helm upgrade with the initiating principal's identity,
providing a change history that links each baseline state to its author.

## Evidence Produced

- Versioned Helm chart OCI artifacts (one per release) representing the
  approved baseline at each release
- `values.yaml` in version-controlled source repository (git history = change
  history for the baseline)
- `SiderealSystemAlert` CRs for any detected configuration drift from the
  Helm baseline, exported to SIEM
- Helm release history Secrets in `sidereal-system` (previous configuration
  retention)
- Kubernetes audit log entries for all Helm upgrade operations

## Customer Responsibility

The deploying agency must:
1. Store the site-specific `values.yaml` override file in their configuration
   management system (e.g., a GitOps repository) under the same change control
   as other system configuration artifacts
2. Ensure changes to the override file go through the agency's formal change
   control process with security impact analysis
3. Maintain a Velero or equivalent backup of all Sidereal CRDs as documented
   in the contingency plan, to support restoration to a known baseline state
4. Document Sidereal's version and configuration baseline in their SSP CM-2
   statement, referencing the Helm chart version and the site-specific
   `values.yaml` override file location
