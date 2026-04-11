---
x-trestle-comp-def-rules:
  sidereal:
    - name: security-override-role-required-for-config-changes
      description: Modifications to security-relevant Sidereal configuration require the sidereal-security-override role; all such changes are recorded in the Kubernetes audit log and SIEM
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 HIGH Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: cm-03
status: implemented
---

# CM-3 — Configuration Change Control

## Control Statement

Establish and document configuration change control processes that include
types of changes requiring approval, a change control authority, security
and privacy impact analysis, testing before implementation, documentation
of approved changes, and retention of configuration change records.

## Sidereal Implementation

Sidereal enforces configuration change control through layered technical
controls: RBAC gates who can make changes, the admission controller gates how changes arrive,
and the Kubernetes audit log records what changed and who changed it.

### Role-Based Change Authorization

Security-relevant Sidereal resources are protected by the
`sidereal-security-override` ClusterRole. This role is required to modify:

- `SiderealProbe` resources (probe schedules, targets, FIPS 199 level)
- The Sidereal controller ConfigMap (SIEM endpoints, retention TTLs)
- Per-probe ServiceAccount RBAC bindings
- `SiderealAOAuthorization` resources for detection probe authorization
- The `sidereal-image-signature-required` admission enforcement policy

Any attempt to modify these resources by a principal not holding
`sidereal-security-override` is denied by Kubernetes RBAC and produces an
audit log entry with the requesting principal's identity. These denied
attempts are forwarded to the SIEM as unauthorized change events.

The `sidereal-security-override` role is not granted to the Sidereal
controller's own ServiceAccount. The controller cannot modify its own
security configuration — changes must come from an authorized external
principal.

### GitOps-Only Change Pathway (Admission Enforcement)

An admission enforcement policy enforces that changes to security-critical Sidereal
resources arrive exclusively through the designated change pathway. Permitted
mutation sources are:

- The Helm release ServiceAccount (for `helm upgrade` operations)
- A designated GitOps ServiceAccount (e.g., ArgoCD, Flux) that has been
  granted `sidereal-security-override` by the agency

Ad-hoc `kubectl edit` or `kubectl patch` mutations by unlabeled principals
are blocked at admission, even if the principal holds the
`sidereal-security-override` ClusterRole. This enforces that all changes
flow through the documented pathway and are traceable to a specific
deployment pipeline run.

Policy violations generate `SiderealIncident` CRs with
`reason: UnauthorizedConfigurationChange` and are exported to the SIEM.

### Auditable Change History

Every approved configuration change deployed via Helm upgrade produces:
1. A versioned Helm release Secret in `sidereal-system` (Helm's native
   release history, capturing before/after configuration state)
2. Kubernetes audit log entries for all resource mutations, including the
   initiating principal's identity and the diff
3. SIEM export records timestamped and linked to the deploying principal

This creates an unbroken, auditable change history that maps each
configuration state to a specific chart version, the principal who performed
the upgrade, and the time of the change.

### Enhancement: CM-3(1) — Automated Documentation, Notification, and Prohibition

Change documentation and prohibition are automated:
- Documentation: Helm release Secrets and Kubernetes audit log are written
  automatically on every change
- Prohibition: The admission controller and RBAC deny unauthorized change attempts without
  human intervention
- Notification: `SiderealIncident` CRs for blocked change attempts trigger
  the agency's IR webhook automatically

### Enhancement: CM-3(2) — Test, Validate, and Document Changes

Sidereal's CI pipeline requires all proposed configuration changes to pass:
- Helm values schema validation (`helm lint` + `values.schema.json`)
- OSCAL compliance validation (NIST oscal-cli against the component
  definition)
- Container image integrity checks (cosign verification + Grype/Trivy clean)

Changes that fail CI validation cannot produce a deployable artifact. This
enforces pre-deployment testing as a structural constraint, not a procedural
recommendation.

### Enhancement: CM-3(6) — Cryptographic Management

Changes to cryptographic configuration (FIPS mode flags, HMAC key rotation
schedules, signing key references) require `sidereal-security-override` and
are subject to the same admission-enforced change pathway as other
security-critical settings. See SC-12 for key management procedures.

## Evidence Produced

- Kubernetes audit log entries for all mutations to `sidereal-system`
  resources, exported to SIEM (who changed what and when)
- Helm release history Secrets in `sidereal-system` (before/after
  configuration state for each change)
- `SiderealIncident` CRs for change attempts blocked by the admission controller or RBAC
- CI pipeline run records for each approved change (test results, scan
  outputs, cosign verification)

## Customer Responsibility

The deploying agency must:
1. Define a formal change control process that includes security and privacy
   impact analysis for Sidereal configuration changes before approval
2. Restrict binding of the `sidereal-security-override` ClusterRole to
   authorized change management personnel and designated GitOps service
   accounts only
3. Operate the GitOps deployment pathway (ArgoCD, Flux, or equivalent) as
   the exclusive mechanism for applying approved Sidereal configuration
   changes
4. Designate a change control authority (change control board or ISSO
   equivalent) to approve Sidereal configuration changes before deployment
