---
x-trestle-comp-def-rules:
  gauntlet:
    - name: gauntlet-event-logging
      description: Gauntlet identifies and generates audit records for all security-relevant events within its operational boundary
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: au-02
status: implemented
---

# AU-2 — Event Logging

## Control Statement

Identify the types of events that the system is capable of logging in support of the audit
function; coordinate the event logging function with other organizations requiring
audit-related information; and review and update the event types on an organization-defined
frequency.

## Gauntlet Implementation

Gauntlet defines a comprehensive set of audit-generating events enumerated at design time
and enforced at runtime. Every event below produces a structured record exported to the
configured SIEM target.

### Audited Events

| Event | Trigger | Record Type |
|---|---|---|
| Probe execution — any outcome | Every probe Job completion | GauntletProbeResult |
| HMAC verification failure | Tampered result ConfigMap detected | GauntletProbeResult (outcome: TamperedResult) |
| Controller startup | Controller pod starts | Kubernetes audit log + SIEM export |
| Controller shutdown | Controller pod terminates | Kubernetes audit log + SIEM export |
| Probe enablement | dryRun set to false on a GauntletProbe | SIEM export via CM-3 change audit |
| Probe disablement | GauntletProbe paused or deleted | SIEM export via CM-3 change audit |
| AO authorization creation | GauntletAOAuthorization resource created | SIEM export |
| AO authorization expiration | GauntletAOAuthorization TTL reached | GauntletSystemAlert + SIEM export |
| GauntletSystemAlert creation | Control failure halts probe execution | GauntletSystemAlert + SIEM export |
| GauntletSystemAlert acknowledgment | Operator acknowledges degraded state | Audit record with principal identity, timestamp, remediation action |
| Security-relevant configuration change | gauntlet-security-override role action | SIEM export with principal identity |
| SIEM export failure | Export attempt fails | Prometheus metric + retry queue |
| GauntletIncident creation | Control failure outcome detected | GauntletIncident + IR webhook export |

### Event Review

The audited event set is reviewed with each Gauntlet release. Changes to the event
enumeration require an update to this control implementation statement and the
corresponding AU-12 implementation.

## Evidence Produced

- `GauntletProbeResult` resources (append-only, one per execution)
- SIEM export records for all events above
- Prometheus metrics for operational event monitoring
- Kubernetes audit log entries for all Kubernetes API interactions

## Customer Responsibility

The deploying agency must:
1. Review this event list and determine if additional events within their environment
   require logging (AU-2 coordination requirement)
2. Configure SIEM to ingest Gauntlet's exported audit records
3. Review the event list at least annually and after significant system changes
