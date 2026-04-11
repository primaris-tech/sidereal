# Sidereal Incident Response Integration Plan

**Document Type**: Supporting Plan — NIST 800-53 IR Family  
**Baseline**: NIST SP 800-53 Rev 5 High  
**Status**: Draft — Agency Customization Required  

---

## 1. Purpose and Scope

This plan defines how Sidereal integrates with the deploying agency's incident
response (IR) program. Sidereal detects active security control failures and
generates structured incident records automatically. This plan documents what
Sidereal produces, how those records trigger the agency's IR workflow, and what
human response is expected at each escalation level.

This plan supplements — it does not replace — the agency's organization-wide
Incident Response Plan. The agency must incorporate Sidereal-generated incidents
into their IR program and document this integration in their SSP IR-1 statement.

---

## 2. Incident Classification

### 2.1 What Sidereal Treats as an Incident

A control failure detected by Sidereal is an active security control gap on a
live federal system. When operating in `enforce` execution mode, Sidereal creates
a `SiderealIncident` CR for every probe execution where `controlEffectiveness` is
`Ineffective` or `Compromised`. In `observe` mode, probe results are recorded and
exported to the SIEM but incidents are not generated — this allows an evaluation
period to tune probes before activating the incident pipeline. In `dryRun` mode,
probes do not execute. The following failure outcomes trigger incidents (in `enforce` mode):

| Probe Surface | Failure Outcome | Security Meaning |
|---|---|---|
| RBAC | `Fail` (should-be-403 succeeded) | Unauthorized access path exists |
| NetworkPolicy | `Forwarded` (should-be-dropped) | Unauthorized network flow path exists |
| Admission Control | `Accepted` (known-bad spec admitted) | Admission policy gap; spec-based escalation possible |
| Secret Access | `Fail` (cross-namespace GET succeeded) | Credential exposure path exists |
| Detection Coverage | `Undetected` (no alert within window) | Detection gap; known attack technique undetected |

**These are incidents, not warnings.** A `Fail` outcome means a real attacker
could exploit the same path. The `SiderealIncident` record triggers the agency's
IR workflow immediately.

### 2.2 Severity Classification

| Sidereal Outcome | Suggested IR Severity | Mandatory Reporting Trigger |
|---|---|---|
| `Forwarded` (NetworkPolicy) | High | Yes — active exfiltration path |
| `Fail` (RBAC/Secret Access) | High | Yes — unauthorized access possible |
| `Accepted` (Admission) | High | Yes — privilege escalation path |
| `Undetected` (Detection) | Medium | Evaluate based on technique |
| `BackendUnreachable` (sustained) | Medium | Monitoring gap |
| `TamperedResult` | Critical | Yes — active integrity attack |

*[Agency: Map these to your organization's incident severity taxonomy here.]*

### 2.3 System Alerts vs. Incidents

`SiderealSystemAlert` resources indicate a degraded monitoring state (not
a direct control failure). They require acknowledgment and investigation but
may not require external reporting. Types:

| Alert Reason | Meaning | Priority |
|---|---|---|
| `TamperedResult` | Probe result HMAC verification failed | Critical — potential active attack |
| `SecurityFunctionUnavailable` | Prerequisite security tool offline | High — monitoring gap |
| `SIEMExportDegraded` | Audit export pipeline failure | High — evidence gap |
| `BaselineConfigurationDrift` | Out-of-band config change detected | Medium — investigate root cause |
| `AdmissionPolicyMissing` | Admission enforcement policy absent | High — blast radius control absent |
| `ExternalAuthFailure` | mTLS authentication failed to external system | Medium |

---

## 3. Automated Incident Generation

### 3.1 SiderealIncident Resource

Every failure outcome creates a `SiderealIncident` CR in `sidereal-system`:

```yaml
apiVersion: sidereal.cloud/v1alpha1
kind: SiderealIncident
metadata:
  name: incident-<uuid>
  namespace: sidereal-system
spec:
  probeType: rbac
  outcome: Fail
  targetNamespace: production
  detectedAt: "2026-04-10T14:32:01Z"
  nistControls: ["AC-3", "AC-6"]
  mitreTechnique: "T1078"   # Valid Accounts
  expectedBehavior: "HTTP 403 Forbidden"
  observedBehavior: "HTTP 200 OK — read succeeded"
  remediationStatus: Open
```

`SiderealIncident` records are append-only and exported to the SIEM immediately
on creation.

### 3.2 IR Webhook

The controller delivers `SiderealIncident` data to the configured IR webhook
endpoint on every incident creation. Supported targets:
- Generic webhook (JSON payload, configurable schema)
- ServiceNow (structured incident creation via API)
- JIRA (issue creation via REST API)

Webhook configuration:
```yaml
# In values-override.yaml
irWebhook:
  enabled: true
  url: "https://servicenow.agency.gov/api/now/incident"
  credentialSecret: sidereal-ir-webhook-cred
  timeoutSeconds: 10
  retryAttempts: 3
```

*[Agency: Configure the IR webhook endpoint here.]*

### 3.3 Consecutive Failure Escalation

The `consecutiveFailures` counter on `SiderealProbe.status` increments on
each consecutive failure execution. Alertmanager rules fire when the counter
exceeds the configured threshold, escalating to on-call personnel.

Recommended Alertmanager rule thresholds:
- `consecutiveFailures >= 2`: page on-call security engineer
- `consecutiveFailures >= 5`: escalate to ISSO; consider emergency change

---

## 4. Mandatory Federal Reporting

### 4.1 US-CERT / CISA Reporting

Per FISMA and OMB M-20-04, federal incidents must be reported to CISA
within defined timeframes. Sidereal-detected incidents that meet the US-CERT
reporting threshold must be reported.

| Incident Type | Reporting Window |
|---|---|
| Critical (TamperedResult, active exfiltration path) | 1 hour |
| Major (RBAC/NetworkPolicy/Admission gap confirmed) | Within 1 hour if critical; 24 hours if significant |
| Standard | As required by agency IR policy |

*[Agency: Map SiderealIncident types to your US-CERT reporting categories
and document thresholds here.]*

### 4.2 Reporting Trigger Configuration

The mandatory reporting window is configurable in Helm values:

```yaml
incidentResponse:
  mandatoryReportingWindowHours:
    critical: 1
    high: 24
    medium: 72
```

When a `SiderealIncident` exceeds its configured reporting window without a
`remediationStatus` update, the controller creates a `SiderealSystemAlert`
with `reason: MandatoryReportingWindowExceeded`.

---

## 5. Response Procedures

### 5.1 RBAC / Secret Access Failure Response

1. **Immediate**: Identify the specific API operation that succeeded
   unexpectedly (captured in `SiderealIncident.spec.observedBehavior`)
2. **Within 1 hour**: Audit Kubernetes RBAC bindings for the affected
   namespace; identify any recently added ClusterRoleBindings or RoleBindings
3. **Remediation**: Remove unauthorized RBAC grants; re-run probe to confirm
   `Pass` outcome on next execution
4. **Documentation**: Update `SiderealIncident.spec.remediationStatus` to
   `Remediated` with remediation notes; document in POA&M if applicable

### 5.2 NetworkPolicy Failure Response

1. **Immediate**: Identify the source namespace, destination, and protocol
   of the unauthorized flow (in `SiderealIncident`)
2. **Within 1 hour**: Review NetworkPolicy objects in the affected namespace
   for recent changes; check CNI configuration for policy enforcement status
3. **Remediation**: Restore correct NetworkPolicy; verify with probe execution
4. **Documentation**: Update incident record; assess whether real traffic
   traversed the gap during the detection window

### 5.3 Admission Control Failure Response

1. **Immediate**: Identify which policy was bypassed and what spec was admitted
2. **Within 1 hour**: Check admission controller webhook status (e.g., Kyverno or OPA/Gatekeeper); review recent policy
   changes or webhook endpoint changes
3. **Remediation**: Restore or correct the admission policy; redeploy webhook
   if necessary; verify with probe execution
4. **Documentation**: Assess whether any unauthorized workloads were deployed
   during the gap window

### 5.4 Detection Coverage Gap Response

1. **Immediate**: Identify the MITRE technique that went undetected
2. **Within 24 hours**: Review detection backend rule configuration (e.g., Falco, Tetragon) for the
   affected technique; identify whether a rule update, exception, or backend
   restart caused the gap
3. **Remediation**: Update detection rules; verify with next probe execution
4. **Documentation**: If the gap is a known limitation, document as accepted
   risk with AO approval

### 5.5 TamperedResult Response

1. **Immediate**: Treat as a potential active attack; escalate to ISSO
2. **Within 1 hour**: Audit Kubernetes API server logs for unexpected mutations
   to the affected probe result ConfigMap; identify the principal responsible
3. **Parallel**: Report to US-CERT within 1 hour as a potential integrity attack
4. **Investigation**: Determine whether the tamper was an active attack or a
   misconfiguration (e.g., an operator accidentally modifying a ConfigMap)
5. **Recovery**: After investigation, acknowledge the `SiderealSystemAlert`
   with documented findings; probe execution resumes after acknowledgment

---

## 6. SiderealSystemAlert Acknowledgment Procedure

`SiderealSystemAlert` resources require individual principal acknowledgment
before probe execution resumes on the affected surface. Acknowledgment procedure:

1. Investigate the root cause of the alert
2. Document findings in the acknowledgment annotation:
   ```
   kubectl annotate SiderealSystemAlert <name> \
     sidereal.cloud/acknowledged-by="firstname.lastname@agency.gov" \
     sidereal.cloud/acknowledgment-notes="Root cause: admission controller pod restarted; policy re-applied; verified functioning"
   ```
3. Acknowledgment is recorded in the Kubernetes audit log and exported to SIEM
4. Probe execution resumes automatically after acknowledgment

Shared service account acknowledgments are rejected. The acknowledging
principal must be an individual identity traceable to a named person (AU-10).

---

## 7. Roles and Responsibilities

| Role | IR Responsibility |
|---|---|
| On-call Security Engineer | First responder for SiderealIncident webhook notifications; initial triage |
| ISSO | Incident classification; mandatory reporting decision; SiderealSystemAlert acknowledgment for critical alerts |
| Authorizing Official | Notified for Critical incidents and TamperedResult events; mandatory reporting approval |
| System Administrator | Execute remediation actions under ISSO direction |

*[Agency: Map these to named individuals or positions and provide contact information.]*

---

## 8. Evidence Retention

Per AU-11 requirements:
- `SiderealIncident` CRs: 365-day minimum in-cluster; 3-year SIEM retention
- `SiderealSystemAlert` CRs (including acknowledgment records): same retention
- IR webhook delivery logs: retained per agency IR evidence policy
- Acknowledgment records in Kubernetes audit log: exported to SIEM

---

## 9. Related Controls

- **IR-4** Incident Handling — agency IR plan integration
- **IR-5** Incident Monitoring — SiderealIncident as incident tracking mechanism
- **IR-6** Incident Reporting — US-CERT reporting thresholds
- **CA-7** Continuous Monitoring — SiderealIncident as monitoring output
- **SI-4** System Monitoring — detection of failures via probe surfaces
- **AU-6** Audit Review — SiderealIncident SIEM queries for IR investigation
