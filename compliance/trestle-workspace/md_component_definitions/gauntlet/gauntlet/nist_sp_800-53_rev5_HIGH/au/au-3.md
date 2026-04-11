---
x-trestle-comp-def-rules:
  gauntlet:
    - name: gauntlet-audit-record-content
      description: Gauntlet audit records contain all required content fields per AU-3
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: au-03
status: implemented
---

# AU-3 — Content of Audit Records

## Control Statement

Ensure that audit records contain information that establishes what type of event occurred,
when the event occurred, where the event occurred, the source of the event, the outcome of
the event, and the identity of any individuals, subjects, or objects associated with the event.

## Gauntlet Implementation

Every `GauntletProbeResult` record contains the following fields satisfying all AU-3
content requirements:

| AU-3 Requirement | Gauntlet Field | Description |
|---|---|---|
| What type of event | `probe.type` | Probe surface (RBAC, NetworkPolicy, Admission, SecretAccess, Detection) |
| When the event occurred | `execution.timestamp` | RFC 3339 timestamp of probe Job completion |
| Where the event occurred | `probe.targetNamespace` | Kubernetes namespace targeted by the probe |
| Source of the event | `probe.id` + `probe.jobName` | Unique probe execution UUID and corresponding Job name |
| Outcome of the event | `result.outcome` | Structured outcome (Detected, Undetected, Blocked, Dropped, Forwarded, Rejected, Accepted, TamperedResult, BackendUnreachable, NotApplicable, NotEnforced) |
| Identity of subjects | `execution.principal` | Kubernetes principal (username) that enabled or triggered the probe |
| NIST control mapping | `result.nistControls` | Specific NIST 800-53 control IDs implicated by this probe execution |
| HMAC verification | `result.integrityStatus` | Whether the result ConfigMap HMAC signature verified successfully |
| Export status | `audit.exportStatus` | Whether the record was successfully exported to the configured SIEM |

### Enhancement: AU-3(1) — Additional Audit Information

`GauntletProbeResult` records additionally include:
- `probe.aoAuthorizationRef` — for Detection probes, the GauntletAOAuthorization resource
  reference providing legal basis for the probe execution
- `probe.syscallCatalogVersion` — for Detection probes, the approved catalog version used
- `result.backendType` — the detection or CNI backend that provided the verdict

## Evidence Produced

- `GauntletProbeResult` CRD schema (published in Helm chart, defines all required fields)
- SIEM export records containing all fields above in structured JSON

## Customer Responsibility

No agency action required for this control. Agencies may add additional fields to SIEM
ingest pipelines if their AU-3 policy requires additional content beyond what Gauntlet
provides.
