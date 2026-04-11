# Gauntlet Rules of Behavior

**Document Type**: Rules of Behavior — NIST 800-53 PL-4  
**Baseline**: NIST SP 800-53 Rev 5 High  
**Status**: Template — Agency Customization Required  

---

## 1. Purpose

These Rules of Behavior (RoB) define the specific obligations, expected
behaviors, and prohibited actions for all personnel who are granted access
to the Gauntlet continuous security control validation operator. All
individuals granted any Gauntlet role must read, understand, and formally
acknowledge these Rules before access is provisioned.

These Rules supplement — they do not replace — the agency's organization-wide
Rules of Behavior (PL-4) and any additional use agreements required by the
agency's access management policy.

---

## 2. Applicability

These Rules apply to all individuals holding any of the following Gauntlet
RBAC roles:

| Role | Description |
|---|---|
| `gauntlet-reader` | View probe configuration and results |
| `gauntlet-operator` | Configure probes; cannot enable live execution |
| `gauntlet-live-executor` | Enable live probe execution (`executionMode: observe` or `enforce`) |
| `gauntlet-approver` | Create `GauntletAOAuthorization` resources |
| `gauntlet-audit-admin` | Read-only access to audit records |
| `gauntlet-security-override` | Modify security-relevant configuration |

Personnel with cluster-admin access to the cluster hosting Gauntlet are
also subject to these Rules with respect to their interactions with
`gauntlet-system` and Gauntlet resources.

---

## 3. General Obligations

All Gauntlet users must:

3.1 Use only individually assigned credentials to access Gauntlet. Shared
    service accounts, shared credentials, and proxy access through another
    individual's identity are prohibited.

3.2 Access Gauntlet resources only for authorized purposes related to their
    assigned role and job function.

3.3 Report any suspected security incidents, unauthorized access, or
    unexpected system behavior to the ISSO immediately upon discovery.

3.4 Not circumvent, disable, or attempt to bypass any Gauntlet security
    control, including admission enforcement policies (e.g., Kyverno or OPA/Gatekeeper), RBAC restrictions, audit logging,
    or SIEM export.

3.5 Complete required security awareness training before access is
    provisioned and on the agency's defined refresher schedule.

---

## 4. Role-Specific Rules of Behavior

### 4.1 All Roles — Audit Record Handling

**Required:**
- Treat `GauntletProbeResult` and `GauntletIncident` records as official
  federal audit records with legal and regulatory significance
- Access audit records only for purposes directly related to security
  operations, incident response, ATO evidence review, or authorized assessment

**Prohibited:**
- Attempting to modify, delete, or suppress any `GauntletProbeResult` or
  `GauntletIncident` record
- Using audit record data for purposes outside the stated security monitoring
  purpose (Section 3.2 of the Privacy Impact Assessment)
- Sharing audit records with personnel who do not have a need-to-know and
  do not hold the `gauntlet-audit-admin` or equivalent role

### 4.2 `gauntlet-operator` Role

**Required:**
- Create `GauntletProbe` resources only for namespaces within the authorized
  scope documented in the SSP
- Configure probe schedules consistent with the FIPS 199 impact level declared
  for the system (High: maximum 6-hour interval)
- Document any new `GauntletProbe` configuration in the change management
  system before deployment

**Prohibited:**
- Setting `executionMode: observe` or `executionMode: enforce` on any
  `GauntletProbe` resource (requires `gauntlet-live-executor` role)
- Creating `GauntletProbe` resources targeting `kube-system` or other
  infrastructure namespaces without explicit ISSO approval
- Registering custom probe types without ISSO approval
- Modifying probe schedules below the FIPS 199 minimum cadence without
  documented AO approval

### 4.3 `gauntlet-live-executor` Role

**Required:**
- Obtain ISSO approval before transitioning any probe to `executionMode: observe`
  or `executionMode: enforce`
- Verify that the target namespace is included in the ATO boundary before
  transitioning execution mode
- Review probe blast radius controls (namespace scoping, ResourceQuota,
  probe fingerprinting) before transitioning execution mode in a new namespace

**Prohibited:**
- Transitioning execution mode in namespaces not included in the ATO boundary
  without written AO approval and SSP update
- `gauntlet-live-executor` role assignment being held by the same individual
  who holds `gauntlet-operator` for the same namespace (separation of duty
  requirement — AC-5)

**Separation of Duty Note**: The `gauntlet-operator` role (configure probes)
and `gauntlet-live-executor` role (transition execution mode) must not be assigned
to the same individual for the same system scope. The ISSO must enforce this
separation during account provisioning and verify it through access reviews.

### 4.4 `gauntlet-approver` Role — AO Authorization for Detection Probes

**Required:**
- Create `GauntletAOAuthorization` resources only after receiving explicit
  written authorization from the Authorizing Official
- Scope the authorization to the minimum necessary set of techniques and
  namespaces
- Set an expiration date that reflects the authorized assessment window
  (not indefinite authorization)
- Document the AO's written authorization as supporting evidence for the
  `GauntletAOAuthorization` creation event

**Prohibited:**
- Creating `GauntletAOAuthorization` resources without AO written approval
- Extending or renewing an authorization without AO re-approval
- Creating authorizations with scope broader than documented in the AO's
  written approval (e.g., `techniques: ["*"]` is prohibited)
- Holding both the `gauntlet-approver` role and the `gauntlet-live-executor`
  role simultaneously (separation of duty)

**Critical**: Unauthorized adversarial probing of a federal system is a
potential violation of the Computer Fraud and Abuse Act (18 U.S.C. § 1030).
The AO authorization requirement is not procedural — it is a legal requirement.

### 4.5 `gauntlet-security-override` Role

**Required:**
- Use this role only for changes that require it (see Configuration
  Management Plan Section 3.1)
- Document the justification for each use in the change management system
  before executing the change
- Notify the ISSO of any use of this role within 24 hours

**Prohibited:**
- Using this role for routine operational changes that can be accomplished
  with less-privileged roles
- Modifying `global.requireAdmissionController: false` without AO approval
  and a documented compensating control
- Disabling FIPS mode (`fips.enabled: false`) on any federal deployment
- Modifying framework crosswalks (`global.controlFrameworks`) without
  ISSO review and documented security impact analysis

### 4.6 `gauntlet-audit-admin` Role

**Required:**
- Maintain independence from the System Administrator role — the audit
  administrator and system administrator must be separate individuals
  (AC-5, AU-9(4))
- Access audit records only for authorized purposes: ATO evidence review,
  incident investigation, compliance reporting

**Prohibited:**
- Holding both `gauntlet-audit-admin` and cluster-admin simultaneously
  (except under documented emergency access procedures)
- Using audit record access to review records outside the scope of a
  specific authorized investigation or review period

---

## 5. Incident and Anomaly Reporting Obligations

5.1 Any user who observes a `GauntletSystemAlert` with `reason: TamperedResult`
    must immediately notify the ISSO. This is a potential active integrity
    attack requiring immediate response.

5.2 Any user who discovers a `GauntletProbeResult` that appears to have been
    modified or deleted must immediately notify the ISSO and must not take
    further action until the ISSO has assessed the situation.

5.3 Any user who receives an admission controller denial for a Gauntlet image
    must notify the ISSO and treat the event as a potential supply chain
    security incident pending investigation.

5.4 Users must not attempt to "fix" anomalies they discover before notifying
    the ISSO. Remediation actions taken without ISSO coordination may destroy
    forensic evidence.

---

## 6. Acknowledgment Gate for GauntletSystemAlerts

When a `GauntletSystemAlert` requires acknowledgment before probe execution
resumes, only individuals with the appropriate authorization may acknowledge
the alert. Rules for acknowledgment:

6.1 Acknowledge only after investigating the root cause of the alert.
    Acknowledging without investigation is prohibited.

6.2 Document the root cause, remediation action, and verification that the
    issue is resolved in the acknowledgment annotation.

6.3 Do not acknowledge an alert if the root cause has not been resolved and
    a compensating control is not in place. In that case, leave the alert
    open and notify the ISSO to accept the risk.

6.4 Acknowledgment using a shared service account is prohibited. The
    Kubernetes admission webhook will reject shared account acknowledgments.
    Use your individual Kubernetes identity.

---

## 7. Prohibited Actions — All Users

The following actions are prohibited for all Gauntlet users regardless of role:

- Disabling or creating exceptions to the admission enforcement policy
  `gauntlet-image-signature-required`
- Disabling or creating exceptions to the admission enforcement policy
  `gauntlet-proberesult-immutable`
- Modifying the `gauntlet-system` NetworkPolicy to permit egress to
  unauthorized endpoints
- Deploying unsigned or unverified Gauntlet images into `gauntlet-system`
- Extracting or exfiltrating SIEM credentials, HMAC keys, or mTLS
  certificates from `gauntlet-system` Secrets
- Using Gauntlet probe infrastructure for any purpose other than authorized
  security control validation

---

## 8. Consequences of Non-Compliance

Violations of these Rules of Behavior may result in:

- Immediate revocation of Gauntlet access
- Disciplinary action per agency HR policy
- Referral for legal action if violations constitute criminal conduct (e.g.,
  unauthorized computer access under 18 U.S.C. § 1030)
- Documentation in the system's incident record and POA&M

---

## 9. Acknowledgment

*By signing below, I acknowledge that I have read, understand, and agree to
comply with the Gauntlet Rules of Behavior. I understand that my activities
within Gauntlet are logged and may be reviewed by authorized personnel.*

**Name (Print)**: ____________________________________  
**Title / Position**: ____________________________________  
**Gauntlet Role(s) Assigned**: ____________________________________  
**Date**: ____________________________________  
**Signature**: ____________________________________  

*Retain signed acknowledgments per the agency's access management records
retention policy. Acknowledgment must be renewed annually and upon any
significant change to these Rules.*

---

## 10. Related Controls and Documents

- **PL-4** Rules of Behavior — this document
- **AC-2** Account Management — role provisioning procedures
- **AC-5** Separation of Duties — operator/live-executor separation
- **AU-10** Non-Repudiation — individual identity requirement for acknowledgments
- **CA-8** Penetration Testing — AO authorization for detection probes
- **PS-6** Access Agreements — this document serves as the Gauntlet access agreement
- Configuration Management Plan — Section 3 (change control)
- Incident Response Integration Plan — Section 5 (response procedures)
