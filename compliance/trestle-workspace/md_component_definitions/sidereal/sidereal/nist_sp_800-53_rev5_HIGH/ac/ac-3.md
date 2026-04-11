---
x-trestle-comp-def-rules:
  sidereal:
    - name: rbac-probe-validates-access-enforcement
      description: Sidereal RBAC probe continuously validates that Kubernetes RBAC policies deny unauthorized access as configured, and that authorized access is not inadvertently blocked
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: ac-03
status: implemented
---

# AC-3 — Access Enforcement

## Control Statement

Enforce approved authorizations for logical access to information and system
resources in accordance with applicable access control policies. Access
decisions must be enforced at every request and reflect the current access
control policy state, covering all subjects, objects, and operations in scope.

## Sidereal Implementation

Sidereal contributes to access enforcement through two complementary
mechanisms: continuous validation that the access control system is
enforcing its policy, and a strictly least-privileged internal architecture
that models correct access control posture.

### Active Access Enforcement Validation — RBAC Probe

The RBAC probe surface continuously verifies that Kubernetes RBAC is
enforcing access decisions as declared. The probe tests in both directions:

**Deny-path verification** (primary): The probe attempts API operations that
the target ServiceAccount is explicitly not authorized to perform. A `Pass`
result means the API server returned a 403 Forbidden — RBAC is enforcing
the deny. A `Fail` result means the API server returned success on a
should-be-denied operation: RBAC has drifted, a ClusterRoleBinding has
been incorrectly added, or the policy has been modified outside of change
control.

**Allow-path verification** (secondary): The probe attempts operations the
ServiceAccount is authorized to perform. A `Fail` here indicates the access
control policy has become overly restrictive — a legitimate operation is
being denied. Both failure modes are security-relevant and generate
`SiderealIncident` CRs.

This active probing detects the gap between declared policy (what the
RBAC manifests say) and enforced policy (what the API server is actually
doing) — a gap that static configuration scanning cannot find.

### Cross-Namespace Secret Access Validation

The Secret Access probe surface extends AC-3 validation to cross-namespace
credential access. The probe attempts to read Secrets from namespaces
outside its authorized scope. A `Fail` (success on a should-be-denied GET)
indicates that namespace-boundary RBAC enforcement has broken down —
ServiceAccounts in one namespace can read credentials belonging to another.

This is a direct test of the most critical RBAC enforcement boundary in a
multi-tenant cluster.

### Sidereal's Internal Access Enforcement

Sidereal enforces access control for its own resources through layered
Kubernetes RBAC:

**Controller ServiceAccount** — Can perform:
- Create/delete `Job` resources in `sidereal-system`
- Read/write `SiderealProbe`, `SiderealProbeResult`, `SiderealIncident`,
  `SiderealSystemAlert` CRDs
- Read Secrets in `sidereal-system` (HMAC root secret only)
- Cannot perform: any operation in non-sidereal namespaces; any operation
  the probe ServiceAccounts perform

**Per-probe ServiceAccounts** — Each scoped to only what its probe requires:
- `sidereal-probe-rbac`: reads ClusterRoles/RoleBindings (read-only, cluster-scoped)
- `sidereal-probe-netpol`: reads NetworkPolicy objects (read-only, target namespace)
- `sidereal-probe-admission`: creates/deletes test resource specs (specific
  resource types, specific namespaces)
- `sidereal-probe-secret`: attempts GET on Secrets (scoped to test targets only)
- `sidereal-probe-detection`: no Kubernetes API access (syscall-only operation)

**Admission enforcement**: An admission enforcement policy (e.g., Kyverno ClusterPolicy or OPA Constraint) enforces that the controller's
ServiceAccount may only create Jobs that reference pre-approved probe
ServiceAccounts. The controller cannot create a Job with a ServiceAccount
that has broader permissions than the pre-provisioned probe set.

### Enhancement: AC-3(7) — Role-Based Access Control

Sidereal's internal access model is entirely role-based. Every access
decision is made against a named ServiceAccount bound to a specific Role
or ClusterRole. There are no wildcard grants, no `system:masters` bindings,
and no cluster-admin assignments for any Sidereal component.

### Enhancement: AC-3(2) — Dual Authorization

Security-relevant Sidereal configuration changes require the
`sidereal-security-override` ClusterRole (a separate, named authorization)
enforced by the admission enforcement layer (e.g., Kyverno or OPA/Gatekeeper). This provides a second authorization layer for
changes to the access control configuration itself — the entity that makes
operational changes cannot also modify the access control policy for those
changes without holding a separately provisioned role.

## Evidence Produced

- `SiderealProbeResult` CRs capturing pass/fail for each RBAC and Secret
  Access check (append-only, HMAC-signed, continuous)
- `SiderealIncident` CRs for any detected RBAC misconfiguration or access
  policy violation, with specific API operation and target resource
- Kubernetes audit log entries for all API operations by Sidereal
  ServiceAccounts, exported to SIEM
- ServiceAccount and RoleBinding manifests in the versioned Helm chart
  (declared least-privilege posture, reviewable at any time)

## Customer Responsibility

The deploying agency must:
1. Define and maintain the ClusterRole and RoleBinding manifests that
   express their access control policy — Sidereal validates enforcement
   of those policies but does not author them
2. Review and approve the ServiceAccount RBAC grants shipped with Sidereal
   during the ATO process
3. Not grant additional cluster-wide roles to `sidereal-system`
   ServiceAccounts outside the defined Helm values
4. Configure `SiderealProbe` resources to cover the RBAC boundaries most
   critical to their system's access control policy
