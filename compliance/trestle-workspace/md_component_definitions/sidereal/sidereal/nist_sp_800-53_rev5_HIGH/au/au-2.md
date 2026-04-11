---
x-trestle-comp-def-rules:
  sidereal:
    - name: sidereal-event-logging
      description: Sidereal identifies and generates audit records for all security-relevant events within its operational boundary
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

## Sidereal Implementation

Sidereal defines a comprehensive set of audit-generating events enumerated at design time
and enforced at runtime. Every event below produces a structured record exported to the
configured SIEM target.

### Audited Events

| Event | Trigger | Record Type |
|---|---|---|
| Probe execution — any outcome | Every probe Job completion | SiderealProbeResult |
| HMAC verification failure | Tampered result ConfigMap detected | SiderealProbeResult (outcome: TamperedResult) |
| Controller startup | Controller pod starts | Kubernetes audit log + SIEM export |
| Controller shutdown | Controller pod terminates | Kubernetes audit log + SIEM export |
| Probe execution mode change | executionMode transitioned (dryRun → observe → enforce) on a SiderealProbe | SIEM export via CM-3 change audit |
| Probe disablement | SiderealProbe paused or deleted | SIEM export via CM-3 change audit |
| AO authorization creation | SiderealAOAuthorization resource created | SIEM export |
| AO authorization expiration | SiderealAOAuthorization TTL reached | SiderealSystemAlert + SIEM export |
| SiderealSystemAlert creation | Control failure halts probe execution | SiderealSystemAlert + SIEM export |
| SiderealSystemAlert acknowledgment | Operator acknowledges degraded state | Audit record with principal identity, timestamp, remediation action |
| Security-relevant configuration change | sidereal-security-override role action | SIEM export with principal identity |
| SIEM export failure | Export attempt fails | Prometheus metric + retry queue |
| SiderealIncident creation | Control failure outcome detected | SiderealIncident + IR webhook export |

### Event Review

The audited event set is reviewed with each Sidereal release. Changes to the event
enumeration require an update to this control implementation statement and the
corresponding AU-12 implementation.

## Evidence Produced

- `SiderealProbeResult` resources (append-only, one per execution)
- SIEM export records for all events above
- Prometheus metrics for operational event monitoring
- Kubernetes audit log entries for all Kubernetes API interactions

## Customer Responsibility

The deploying agency must:
1. Review this event list and determine if additional events within their environment
   require logging (AU-2 coordination requirement)
2. Configure SIEM to ingest Sidereal's exported audit records
3. Review the event list at least annually and after significant system changes
