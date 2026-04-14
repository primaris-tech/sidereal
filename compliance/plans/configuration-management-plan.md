# Sidereal Configuration Management Plan

**Document Type**: Supporting Plan — NIST 800-53 CM Family  
**Baseline**: NIST SP 800-53 Rev 5 High  
**Status**: Draft — Agency Customization Required  

---

## 1. Purpose and Scope

This Configuration Management Plan (CMP) defines the configuration management
policies, procedures, and technical controls that govern the Sidereal
continuous monitoring operator. It covers the Sidereal software components,
their runtime configuration, and the processes by which configuration changes
are authorized, implemented, and audited.

This plan satisfies NIST 800-53 CM-1 through CM-14 requirements for the
Sidereal component. The deploying agency must integrate this plan into their
organization-wide CM program and supplement it with agency-specific
procedures for their infrastructure and personnel.

---

## 2. Baseline Configuration (CM-2)

### 2.1 Configuration Baseline Document

The authoritative Sidereal baseline configuration document is the Helm chart
`values.yaml` file, stored in version control alongside the Sidereal Helm
chart at the versioned release tag. The baseline captures:

- Global execution mode (`global.executionMode`: `observe` or `enforce`)
- Global impact level declaration (`global.impactLevel`: `low`, `moderate`, or `high`)
- Compliance framework definitions (`SiderealFramework` resources) and audit export format (`audit.exportFormat`)
- Probe schedules (cadence defaults cascade from `global.impactLevel`)
- SIEM endpoint URLs and transport configuration
- Container image references (SHA-256 digest-pinned)
- FIPS mode flags (`fips.enabled`)
- Audit record retention TTLs (minimum 365 days; default cascades from `global.impactLevel`)
- ResourceQuota limits for `sidereal-system`
- RBAC role bindings for per-probe ServiceAccounts
- Deployment profile selection (six pre-built profiles available)

The site-specific configuration is maintained in a separate `values-override.yaml`
file stored in the deploying agency's GitOps repository.

### 2.2 Image Digest Pinning

All container image references in the Helm chart are pinned by SHA-256 digest.
Mutable tag references are not used. This ensures the baseline configuration
unambiguously identifies the exact binary deployed at each release.

### 2.3 Baseline Versions

| Component | Reference | Notes |
|---|---|---|
| Sidereal Helm chart | `sidereal:<chart-version>` | Semantic version; tagged in git |
| Site values override | `<agency-gitops-repo>/sidereal/values-override.yaml` | Agency-maintained |
| Trestle workspace | `compliance/trestle-workspace/` | In Sidereal source repo |

*[Agency: Insert specific chart version, image digests, and GitOps repository path here.]*

### 2.4 Drift Detection

The controller performs a startup reconciliation check and continuously
compares running configuration against the Helm-rendered expected state.
Configuration drift produces a `SiderealSystemAlert` with
`reason: BaselineConfigurationDrift`, exported to the SIEM.

---

## 3. Configuration Change Control (CM-3)

### 3.1 Change Types Requiring Authorization

| Change Type | Authorization Required | Mechanism |
|---|---|---|
| Probe schedule modification | `sidereal-operator` role | `kubectl edit SiderealProbe` via GitOps |
| Transition execution mode | `sidereal-live-executor` role | `executionMode: observe` or `executionMode: enforce` in SiderealProbe spec |
| Modify SIEM endpoints | `sidereal-security-override` role | Helm upgrade |
| Change retention TTLs | `sidereal-security-override` role | Helm upgrade |
| Modify FIPS mode setting | `sidereal-security-override` role | Helm upgrade (requires new images) |
| Enable detection probes | `sidereal-approver` + `SiderealAOAuthorization` | AO-signed authorization CR |
| Change impact level | `sidereal-security-override` role | Helm upgrade (`global.impactLevel`); cascades cadence, retention, fail-closed defaults |
| Add/modify compliance frameworks | `sidereal-security-override` role | `kubectl apply SiderealFramework` via GitOps |
| Change audit export format | `sidereal-security-override` role | Helm upgrade (`audit.exportFormat`) |
| Register custom probes | `sidereal-operator` + ISSO approval | Custom `SiderealProbe` with non-default probe type |
| Modify framework crosswalk | `sidereal-security-override` role | Security-relevant change; requires ISSO review |
| Disable admission controller check | `sidereal-security-override` + AO approval | `global.requireAdmissionController: false` |

### 3.2 Change Control Process

1. **Request**: Change initiator submits a pull request to the GitOps
   repository modifying `values-override.yaml` or a `SiderealProbe` manifest
2. **Review**: Designated reviewer (ISSO or delegate) reviews the security
   impact of the proposed change
3. **Approval**: Change control authority approves or rejects
4. **Testing**: Approved changes are deployed to a non-production environment
   if a staging cluster is available; otherwise, dry-run verification is performed
5. **Deployment**: Change is applied via `helm upgrade` or `kubectl apply`
   through the GitOps pipeline using the designated service account
6. **Recording**: Helm release history Secret and Kubernetes audit log
   record the change with the initiating principal's identity
7. **Verification**: Post-deployment probe execution confirms the change
   did not degrade security control effectiveness

### 3.3 Rollback Procedure

Every Helm upgrade creates a versioned release record. Rollback is performed
via `helm rollback sidereal <revision>`. The Kubernetes audit log records
the rollback event.

### 3.4 Emergency Changes

Emergency changes (e.g., responding to an active security event) follow the
same process with expedited review. The `sidereal-security-override` role
requirement is not waivable. Changes made outside the GitOps pipeline must
be reconciled by a subsequent GitOps deployment within 24 hours.

*[Agency: Define emergency change authority and notification procedures here.]*

---

## 4. Configuration Settings (CM-6)

### 4.1 Approved Configuration Parameter Ranges

The `values.schema.json` in the Helm chart enforces the following constraints:

| Parameter | Constraint | Rationale |
|---|---|---|
| `global.executionMode` | Default `observe` | Blast radius default; `enforce` requires `sidereal-live-executor` role |
| `global.impactLevel` | `low`, `moderate`, or `high` | Cascades defaults for cadence, retention, and fail-closed behavior |
| `crosswalk.installDefaults` | `true` or `false` | Whether Helm installs the seven built-in `SiderealFramework` resources |
| `probe.intervalSeconds` (High impact) | Maximum 21,600 (6 hours) | NIST 800-137 High monitoring cadence |
| `audit.retentionDays` | Minimum 365 | FedRAMP AU-11 retention floor |
| `audit.exportFormat` | Supported format identifier | Determines SIEM export serialization |
| `siem.tlsCABundle` | Required when SIEM enabled | Prevents unauthenticated export |
| `fips.enabled` | Must be `true` for federal deployments | FIPS 140-2 compliance |
| `tlsInsecureSkipVerify` | Must remain `false` | IA-3/IA-8 device authentication |

### 4.2 Approved Deviations

Any deviation from default configuration settings requires:
1. Security impact analysis documented by the ISSO
2. AO approval recorded in the risk acceptance register
3. SSP CM-6 statement updated to reflect the deviation and its justification

*[Agency: Document approved deviations and their justifications here.]*

---

## 5. Least Functionality (CM-7)

Sidereal components expose only essential capabilities:
- No shell in probe runner images (distroless/scratch base)
- No debug endpoints in production builds (`/debug/pprof` disabled)
- NetworkPolicy restricts `sidereal-system` egress to explicitly listed endpoints
- Pod security context enforces: non-root, read-only filesystem, all capabilities dropped

The agency must not add sidecars, init containers, or additional network
policies that introduce capabilities not present in the baseline deployment.

---

## 6. Component Inventory (CM-8)

### 6.1 SBOM as Component Inventory

A CycloneDX SBOM is generated and cosign-attested for every Sidereal release.
The SBOM serves as the CM-8 component inventory for Sidereal. It is queryable via:

```
cosign verify-attestation --type cyclonedx <image@sha256:digest>
```

The agency must integrate the Sidereal SBOM into their organization's software
asset management system and document Sidereal's component inventory in the SSP.

### 6.2 Inventory Update Procedure

The inventory is updated automatically on each Helm upgrade — a new SBOM is
generated for any changed component images as part of the release pipeline.
No manual inventory update is required.

---

## 7. Signed Components (CM-14)

All Sidereal container images are cosign-signed at build time. The admission
enforcement policy `sidereal-image-signature-required` enforces signature verification
at every Pod admission. The agency must:

1. Ensure the admission controller (e.g., Kyverno or OPA/Gatekeeper) is deployed before Sidereal installation
2. Not disable or create exceptions to the image signature policy
3. For air-gapped deployments: re-sign mirrored images per the documented
   procedure and update the admission enforcement policy with the agency's signing key

---

## 8. Roles and Responsibilities

| Role | CM Responsibility |
|---|---|
| ISSO | Approve security-relevant configuration changes; maintain deviation register |
| Authorizing Official | Approve deviations from default security configuration; authorize detection probe campaigns |
| System Administrator | Execute approved changes via GitOps pipeline |
| Change Control Board | Review and approve changes to security-relevant Sidereal configuration |

*[Agency: Map these responsibilities to named individuals or positions here.]*

---

## 9. Related Controls and Plans

- **CM-2** baseline → SSP Section [X], site `values-override.yaml`
- **CM-3** change control → this plan, Section 3
- **CM-6** configuration settings → `values.schema.json`; deviations in SSP
- **CM-7** least functionality → OSCAL Component Definition cm-7.md
- **CM-8** inventory → Sidereal SBOM OCI artifact
- **CM-14** signed components → OSCAL Component Definition cm-14.md
- **SC-12** key management → Key Management Plan (if separate)
- **SI-2** flaw remediation → Sidereal release channel; 30-day critical CVE SLA
