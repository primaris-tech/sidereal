---
x-trestle-comp-def-rules:
  gauntlet:
    - name: helm-values-schema-controller-enforcement
      description: Gauntlet's Helm chart includes a JSON schema for values validation, and the controller rejects runtime configurations that deviate from the approved settings at admission
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: cm-06
status: implemented
---

# CM-6 — Configuration Settings

## Control Statement

Establish and document configuration settings for information technology
products that reflect the most restrictive mode consistent with operational
requirements. Document deviations from established configuration settings,
and monitor and control changes to configuration settings.

## Gauntlet Implementation

Gauntlet enforces secure configuration settings at two layers: pre-deploy
(Helm schema validation blocks invalid configurations from reaching the
cluster) and runtime (the controller's admission webhook rejects CRD
configurations that violate security constraints). Defaults are set to the
most restrictive mode consistent with operation.

### Helm Values Schema Enforcement

The Gauntlet Helm chart ships with a `values.schema.json` that enforces
required fields, allowed value ranges, and type constraints on all
configurable parameters. `helm install` and `helm upgrade` fail schema
validation if provided values violate a constraint. Example enforced
constraints:

| Parameter | Constraint | Security Rationale |
|---|---|---|
| `probe.intervalSeconds` (High) | Maximum 21600 (6 hours) | Enforces FIPS 199 High monitoring cadence |
| `audit.retentionDays` | Minimum 365 | Enforces AU-11 retention floor |
| `siem.tlsCABundle` | Required when `siem.enabled: true` | Prevents plaintext SIEM export |
| `fips.enabled` | Boolean, documented in SSP | FIPS mode is an auditable setting |
| `global.executionMode` | Default `dryRun` on fresh install | Graduated adoption (`dryRun` → `observe` → `enforce`); explicit opt-in required via `gauntlet-live-executor` role |
| `global.impactLevel` | `high`, `moderate`, `low` (default: `high`) | FIPS 199 impact level; cascades cadence, retention, and fail-closed defaults |

These constraints cannot be overridden via `helm upgrade --set` without first
modifying the schema, which requires a code change that flows through CI and
code review.

### Controller CRD Admission Validation

The controller implements a validating admission webhook that enforces
OpenAPI v3 schema constraints on `GauntletProbe` and related CRDs at
creation and update time. Configurations rejected at admission include:

- A `GauntletProbe` with `intervalSeconds` exceeding the High-baseline
  maximum without a documented AO-approved deviation
- A `GauntletProbe` targeting `kube-system` without a justification
  annotation
- A detection probe without a `GauntletAOAuthorization` reference
- A SIEM export configuration without a TLS CA bundle reference

Invalid configurations are rejected with a structured error response
referencing the specific violated constraint, providing actionable feedback
rather than a generic rejection.

### FIPS Mode as a Controlled Configuration Setting

FIPS mode is a top-level boolean in the Helm values (`fips.enabled`). When
enabled, it sets `GOEXPERIMENT=boringcrypto` for Go components and activates
the `aws-lc-rs` FIPS feature flag for Rust probe runners at build time. This
configuration is baked into the released container images — it cannot be
toggled by modifying a ConfigMap post-deployment.

Changing the FIPS mode setting requires a full `helm upgrade` with a new
set of FIPS-specific image digests. This ensures cryptographic posture
changes are controlled, auditable events rather than live configuration
flips.

### Most Restrictive Defaults

Gauntlet's default configuration settings represent the most restrictive
mode consistent with operation:

- `global.executionMode: dryRun` — no live probes without explicit opt-in via `gauntlet-live-executor` role; graduated path through `observe` then `enforce`
- `probe.fingerprinting.enabled: true` — all probe actions fingerprinted
- `resourceQuota.maxConcurrentJobs: 3` — bounded concurrent probe footprint
- `audit.exportOnFailure: true` — failures always exported, not configurable
  off
- `controller.leaderElection.enabled: true` — HA posture is the default

Agencies that require deviations from these defaults must document each
deviation in their SSP and obtain AO approval.

### Enhancement: CM-6(1) — Automated Management, Application, and Verification

Configuration management is automated end-to-end. Helm schema validation
runs in CI before any artifact is produced. The controller's admission
webhook enforces settings at every resource creation and update. The
controller startup reconciliation detects drift from the approved baseline
(see CM-2). No manual configuration review process is required to maintain
compliance with CM-6 settings.

### Enhancement: CM-6(2) — Respond to Unauthorized Changes

Unauthorized changes to configuration settings are detected by the
controller's baseline drift mechanism (CM-2) and by the admission enforcement policy
enforcing the approved change pathway (CM-3). Detected unauthorized changes
produce `GauntletSystemAlert` CRs that suspend probe execution until
acknowledged, ensuring that a configuration-level attack does not silently
affect the integrity of monitoring evidence.

## Evidence Produced

- Helm values schema validation output in CI/CD pipeline logs for each
  deployment (records what was validated and passed)
- Controller admission webhook rejection events in the Kubernetes audit log
  for out-of-compliance configuration attempts
- `GauntletSystemAlert` CRs for detected configuration drift, exported to
  SIEM
- `values.schema.json` in the Helm chart source (the definitive list of
  enforced settings and their constraints)

## Customer Responsibility

The deploying agency must:
1. Document any site-specific deviations from Gauntlet's default
   configuration settings in their System Security Plan, including the
   security justification for each deviation
2. Obtain AO approval for each deviation from the enforced defaults,
   particularly for probe schedule intervals and SIEM export modes
3. Treat the Gauntlet `values.schema.json` as an authoritative reference
   for the approved configuration parameter space when conducting control
   assessments
4. Not disable the controller's validating admission webhook without AO
   authorization and documentation of compensating controls
