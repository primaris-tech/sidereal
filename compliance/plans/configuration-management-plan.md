# Gauntlet Configuration Management Plan

**Document Type**: Supporting Plan — NIST 800-53 CM Family  
**Baseline**: NIST SP 800-53 Rev 5 High  
**Status**: Draft — Agency Customization Required  

---

## 1. Purpose and Scope

This Configuration Management Plan (CMP) defines the configuration management
policies, procedures, and technical controls that govern the Gauntlet
continuous monitoring operator. It covers the Gauntlet software components,
their runtime configuration, and the processes by which configuration changes
are authorized, implemented, and audited.

This plan satisfies NIST 800-53 CM-1 through CM-14 requirements for the
Gauntlet component. The deploying agency must integrate this plan into their
organization-wide CM program and supplement it with agency-specific
procedures for their infrastructure and personnel.

---

## 2. Baseline Configuration (CM-2)

### 2.1 Configuration Baseline Document

The authoritative Gauntlet baseline configuration document is the Helm chart
`values.yaml` file, stored in version control alongside the Gauntlet Helm
chart at the versioned release tag. The baseline captures:

- Probe schedules and FIPS 199 impact level declaration
- SIEM endpoint URLs and transport configuration
- Container image references (SHA-256 digest-pinned)
- FIPS mode flags (`fips.enabled`)
- Audit record retention TTLs (minimum 365 days)
- ResourceQuota limits for `gauntlet-system`
- RBAC role bindings for per-probe ServiceAccounts

The site-specific configuration is maintained in a separate `values-override.yaml`
file stored in the deploying agency's GitOps repository.

### 2.2 Image Digest Pinning

All container image references in the Helm chart are pinned by SHA-256 digest.
Mutable tag references are not used. This ensures the baseline configuration
unambiguously identifies the exact binary deployed at each release.

### 2.3 Baseline Versions

| Component | Reference | Notes |
|---|---|---|
| Gauntlet Helm chart | `gauntlet:<chart-version>` | Semantic version; tagged in git |
| Site values override | `<agency-gitops-repo>/gauntlet/values-override.yaml` | Agency-maintained |
| Trestle workspace | `compliance/trestle-workspace/` | In Gauntlet source repo |

*[Agency: Insert specific chart version, image digests, and GitOps repository path here.]*

### 2.4 Drift Detection

The controller performs a startup reconciliation check and continuously
compares running configuration against the Helm-rendered expected state.
Configuration drift produces a `GauntletSystemAlert` with
`reason: BaselineConfigurationDrift`, exported to the SIEM.

---

## 3. Configuration Change Control (CM-3)

### 3.1 Change Types Requiring Authorization

| Change Type | Authorization Required | Mechanism |
|---|---|---|
| Probe schedule modification | `gauntlet-operator` role | `kubectl edit GauntletProbe` via GitOps |
| Enable live probe execution | `gauntlet-live-executor` role | `dryRun: false` in GauntletProbe spec |
| Modify SIEM endpoints | `gauntlet-security-override` role | Helm upgrade |
| Change retention TTLs | `gauntlet-security-override` role | Helm upgrade |
| Modify FIPS mode setting | `gauntlet-security-override` role | Helm upgrade (requires new images) |
| Enable detection probes | `gauntlet-approver` + `GauntletAOAuthorization` | AO-signed authorization CR |
| Disable admission controller check | `gauntlet-security-override` + AO approval | `global.requireAdmissionController: false` |

### 3.2 Change Control Process

1. **Request**: Change initiator submits a pull request to the GitOps
   repository modifying `values-override.yaml` or a `GauntletProbe` manifest
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
via `helm rollback gauntlet <revision>`. The Kubernetes audit log records
the rollback event.

### 3.4 Emergency Changes

Emergency changes (e.g., responding to an active security event) follow the
same process with expedited review. The `gauntlet-security-override` role
requirement is not waivable. Changes made outside the GitOps pipeline must
be reconciled by a subsequent GitOps deployment within 24 hours.

*[Agency: Define emergency change authority and notification procedures here.]*

---

## 4. Configuration Settings (CM-6)

### 4.1 Approved Configuration Parameter Ranges

The `values.schema.json` in the Helm chart enforces the following constraints:

| Parameter | Constraint | Rationale |
|---|---|---|
| `probe.intervalSeconds` (High impact) | Maximum 21,600 (6 hours) | NIST 800-137 High monitoring cadence |
| `audit.retentionDays` | Minimum 365 | FedRAMP AU-11 retention floor |
| `siem.tlsCABundle` | Required when SIEM enabled | Prevents unauthenticated export |
| `fips.enabled` | Must be `true` for federal deployments | FIPS 140-2 compliance |
| `probe.dryRun` | Default `true` | Blast radius default |
| `tlsInsecureSkipVerify` | Must remain `false` | IA-3/IA-8 device authentication |

### 4.2 Approved Deviations

Any deviation from default configuration settings requires:
1. Security impact analysis documented by the ISSO
2. AO approval recorded in the risk acceptance register
3. SSP CM-6 statement updated to reflect the deviation and its justification

*[Agency: Document approved deviations and their justifications here.]*

---

## 5. Least Functionality (CM-7)

Gauntlet components expose only essential capabilities:
- No shell in probe runner images (distroless/scratch base)
- No debug endpoints in production builds (`/debug/pprof` disabled)
- NetworkPolicy restricts `gauntlet-system` egress to explicitly listed endpoints
- Pod security context enforces: non-root, read-only filesystem, all capabilities dropped

The agency must not add sidecars, init containers, or additional network
policies that introduce capabilities not present in the baseline deployment.

---

## 6. Component Inventory (CM-8)

### 6.1 SBOM as Component Inventory

A CycloneDX SBOM is generated and cosign-attested for every Gauntlet release.
The SBOM serves as the CM-8 component inventory for Gauntlet. It is queryable via:

```
cosign verify-attestation --type cyclonedx <image@sha256:digest>
```

The agency must integrate the Gauntlet SBOM into their organization's software
asset management system and document Gauntlet's component inventory in the SSP.

### 6.2 Inventory Update Procedure

The inventory is updated automatically on each Helm upgrade — a new SBOM is
generated for any changed component images as part of the release pipeline.
No manual inventory update is required.

---

## 7. Signed Components (CM-14)

All Gauntlet container images are cosign-signed at build time. The admission
enforcement policy `gauntlet-image-signature-required` enforces signature verification
at every Pod admission. The agency must:

1. Ensure the admission controller (e.g., Kyverno or OPA/Gatekeeper) is deployed before Gauntlet installation
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
| Change Control Board | Review and approve changes to security-relevant Gauntlet configuration |

*[Agency: Map these responsibilities to named individuals or positions here.]*

---

## 9. Related Controls and Plans

- **CM-2** baseline → SSP Section [X], site `values-override.yaml`
- **CM-3** change control → this plan, Section 3
- **CM-6** configuration settings → `values.schema.json`; deviations in SSP
- **CM-7** least functionality → OSCAL Component Definition cm-7.md
- **CM-8** inventory → Gauntlet SBOM OCI artifact
- **CM-14** signed components → OSCAL Component Definition cm-14.md
- **SC-12** key management → Key Management Plan (if separate)
- **SI-2** flaw remediation → Gauntlet release channel; 30-day critical CVE SLA
