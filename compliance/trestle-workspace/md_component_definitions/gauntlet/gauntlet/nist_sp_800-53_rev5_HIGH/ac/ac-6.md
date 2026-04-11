---
x-trestle-comp-def-rules:
  gauntlet:
    - name: per-probe-serviceaccount-least-privilege
      description: Each Gauntlet probe surface runs under a dedicated ServiceAccount with the minimum RBAC permissions required for that probe type only; the controller cannot perform probe-class operations and probe runners cannot perform controller operations
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: ac-06
status: implemented
---

# AC-6 — Least Privilege

## Control Statement

Employ the principle of least privilege, allowing only authorized accesses
necessary for assigned tasks. Privileged accounts and roles must be
explicitly authorized, their use audited, and periodically reviewed.

## Gauntlet Implementation

Least privilege is enforced as a structural property of Gauntlet's
architecture. The controller and probe runners are separate identities
with non-overlapping permissions. Neither can perform the other's
operations. No component holds more permission than required for its
specific function.

### Per-Probe ServiceAccount Model

Five built-in probe classes plus a discovery capability each run under dedicated ServiceAccounts provisioned at Helm install time. Custom probes use operator-registered ServiceAccounts subject to the same least-privilege constraints:

| ServiceAccount | Permitted Operations | Cannot Perform |
|---|---|---|
| `gauntlet-probe-rbac` | `get`, `list` ClusterRoles, RoleBindings; attempt denied operations as test subject | Write any resource; access Secrets; cross-namespace reads |
| `gauntlet-probe-netpol` | `get`, `list` NetworkPolicy in target namespace; initiate probe TCP connections | Modify NetworkPolicy; access other namespaces |
| `gauntlet-probe-admission` | Create/delete specific test resource types in designated test namespaces | Read or modify production workloads; access Secrets |
| `gauntlet-probe-secret` | Attempt `get` on specific Secret names in test namespaces (expects 403) | Write Secrets; access other namespaces; hold valid credential |
| `gauntlet-probe-detection` | None — no Kubernetes API access | Any Kubernetes API operation |

Each ServiceAccount is bound to a named Role or ClusterRole. There are no
wildcard resource grants (`*`), no wildcard verb grants (`*`), and no
bindings to `cluster-admin` or `system:masters` for any probe ServiceAccount.

### Controller ServiceAccount Constraints

The controller's ServiceAccount is scoped to its orchestration role:
- **Can create**: `Job` resources in `gauntlet-system`
- **Can read/write**: Gauntlet CRDs (`GauntletProbe`, `GauntletProbeResult`,
  `GauntletIncident`, `GauntletSystemAlert`)
- **Can read**: HMAC root Secret in `gauntlet-system` (specific Secret name)
- **Cannot**: Perform any of the operations the probe ServiceAccounts perform
- **Cannot**: Create Jobs referencing ServiceAccounts outside the
  pre-approved probe set (admission enforcement policy)

The admission enforcement policy (e.g., Kyverno ClusterPolicy or OPA
Constraint) that enforces the last constraint is the critical separation
control. It prevents a compromised controller from
escalating its effective privileges by creating a Job referencing a more
privileged ServiceAccount. The controller can only create Jobs using the
pre-provisioned probe ServiceAccounts — it cannot bootstrap new
ServiceAccounts or reference cluster-admin.

### OS-Layer Least Privilege

Probe runners enforce least privilege at the Linux process level:
- `runAsNonRoot: true` — no root execution
- `runAsUser: 65532` — non-zero, non-privileged UID
- `allowPrivilegeEscalation: false` — setuid/setgid transitions blocked
- `capabilities: drop: [ALL]` — no Linux capabilities
- `seccompProfile: RuntimeDefault` (or probe-specific allow-list for
  detection runners)
- `readOnlyRootFilesystem: true` — no runtime filesystem writes

No Gauntlet component holds `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`,
`CAP_SYS_PTRACE`, or any other capability that would allow bypass of
OS-level access controls.

### ResourceQuota Prevents Exhaustion Escalation

A `ResourceQuota` on `gauntlet-system` limits concurrent probe Jobs to
a configurable maximum (default: 3). This prevents privilege escalation
through resource exhaustion — a compromised or misconfigured controller
cannot spawn an unbounded number of probe Jobs, each consuming cluster
resources or namespace quotas that affect other workloads.

### Continuous Least Privilege Verification

The RBAC probe continuously tests the least privilege posture. On each
execution, the probe verifies:
1. The probe ServiceAccounts cannot access resources outside their declared
   scope
2. The should-be-403 operations return 403
3. Cross-namespace access boundaries are enforced

A change that silently widens a probe ServiceAccount's RBAC scope (e.g.,
an operator incorrectly adding a ClusterRoleBinding) is detected on the
next probe execution and produces a `GauntletIncident` CR.

### Enhancement: AC-6(1) — Authorize Access to Security Functions

Access to security-relevant Gauntlet resources (changing probe
configuration, modifying SIEM credentials, adjusting FIPS settings)
requires the `gauntlet-security-override` ClusterRole, which is separately
provisioned and not held by any automated Gauntlet component. Only
explicitly authorized human principals hold this role.

### Enhancement: AC-6(5) — Privileged Accounts

The `gauntlet-security-override` role is the only elevated role in the
Gauntlet access model. Holders of this role are explicitly listed in the
SSP and subject to the agency's privileged account review process.
The admission enforcement layer (e.g., Kyverno or OPA/Gatekeeper) enforces
that changes to security-relevant resources arrive through the designated
pathway (CM-3), providing a detective control for
unauthorized use of the privileged role.

### Enhancement: AC-6(9) — Log Use of Privileged Functions

All mutations to Gauntlet CRDs, including those performed by principals
holding `gauntlet-security-override`, are recorded in the Kubernetes
audit log at the `RequestResponse` level and forwarded to the SIEM. This
provides a complete record of privileged function use that is auditable
independent of the Gauntlet controller.

## Evidence Produced

- ServiceAccount and RoleBinding manifests in the versioned Helm chart
  (declared least-privilege posture, reviewable and diffable per release)
- Admission policy records confirming controller Job creation is restricted
  to pre-approved probe ServiceAccounts
- `GauntletProbeResult` CRs from the RBAC probe confirming that probe
  ServiceAccounts cannot access out-of-scope resources
- Kubernetes audit log for all API operations by Gauntlet ServiceAccounts,
  exported to SIEM

## Customer Responsibility

The deploying agency must:
1. Review and approve the ServiceAccount RBAC grants shipped with Gauntlet
   during the ATO process and document approval in the SSP
2. Not grant additional cluster-wide roles to `gauntlet-system`
   ServiceAccounts outside the defined Helm values
3. Restrict binding of the `gauntlet-security-override` ClusterRole to
   explicitly authorized personnel and subject those accounts to the
   agency's privileged account review process (AC-2)
4. Review the ServiceAccount RBAC grants in each Gauntlet release as part
   of the upgrade change management process
