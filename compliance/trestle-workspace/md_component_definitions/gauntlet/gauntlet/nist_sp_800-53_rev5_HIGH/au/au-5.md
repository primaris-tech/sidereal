---
x-trestle-comp-def-rules:
  gauntlet:
    - name: siem-export-failure-alert-and-retry
      description: Gauntlet detects SIEM export failures via consecutive failure thresholds, raises GauntletSystemAlert with reason SIEMExportDegraded, buffers undelivered records with exponential-backoff retry, and optionally halts probe scheduling when audit delivery cannot be guaranteed
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: au-05
status: implemented
---

# AU-5 — Response to Audit Processing Failures

## Control Statement

Alert designated personnel in the event of an audit processing failure and
take additional defined actions such as shutting down the system, overwriting
oldest records, or stopping record generation. Limit the impact of audit
failures on the ability to detect and respond to security events.

## Gauntlet Implementation

An audit processing failure in Gauntlet means one of two things: the SIEM
export pipeline cannot durably deliver records off-cluster, or the in-cluster
record creation fails. Gauntlet detects both conditions, alerts automatically,
retries delivery, and can halt probe scheduling when durable audit delivery
cannot be guaranteed — fail-closed rather than fail-open.

### Failure Detection

**SIEM export failures**: The controller tracks delivery status for every
`GauntletProbeResult` export attempt. After a configurable consecutive
failure threshold (default: 3), the export channel is marked degraded.

Prometheus metrics exposed for monitoring:
| Metric | Description |
|---|---|
| `gauntlet_siem_export_failures_total` | Cumulative count of export failures per channel |
| `gauntlet_siem_export_retry_queue_depth` | Records buffered pending retry |
| `gauntlet_siem_backend_reachability` | 0/1 gauge per configured SIEM endpoint |
| `gauntlet_audit_export_failures` | Rate of export failures (alert threshold metric) |

**In-cluster write failures**: If the controller cannot write a
`GauntletProbeResult` to the Kubernetes API (etcd unavailable, quota
exceeded), the failure is logged and surfaced as a `GauntletSystemAlert`.

### Alert Generation

When the consecutive export failure threshold is reached, the controller
creates a `GauntletSystemAlert` with `reason: SIEMExportDegraded`. This
alert:
- Appears in the cluster as a named resource queryable by operators
- Is exported to any still-functional SIEM channels (or logged locally
  if all channels are degraded)
- Triggers Alertmanager rules configured by the agency against the
  `gauntlet_siem_export_failures_total` metric
- Is visible in the controller's structured log output

The `GauntletSystemAlert` creation event is recorded in the Kubernetes
audit log, providing an independent notification record even if the SIEM
is fully unavailable.

### Retry and Buffering

Undelivered records are not silently dropped. The export pipeline implements
exponential backoff retry:
- Initial retry delay: 5 seconds
- Maximum retry delay: 5 minutes
- Retry window: configurable (default: 24 hours)
- Buffer depth: bounded by the `gauntlet-system` namespace ResourceQuota

Records pending delivery are buffered in the controller's in-memory export
queue. The queue depth is reported via `gauntlet_siem_export_retry_queue_depth`
and bounded by the ResourceQuota, preventing unbounded memory growth during
prolonged SIEM unavailability.

When the SIEM recovers, the retry queue is drained in order, ensuring no
records are permanently lost during transient unavailability. Delivered
records carry their original creation timestamp — the delivery delay does
not corrupt the audit timeline.

### Fail-Closed Posture Option

When `audit.failClosedOnExportFailure: true` is set in Helm values (default:
`false`; recommended for High-baseline deployments), the controller halts
new probe Job scheduling when the SIEM export pipeline has been degraded
for longer than the configurable threshold (default: 1 hour).

This satisfies the AU-5 requirement to "stop audit record generation" when
audit processing has failed — Gauntlet stops generating records it cannot
durably store rather than accumulating evidence that may never reach the
authoritative audit store.

Probe scheduling resumes automatically when the SIEM export pipeline
recovers and the retry queue is drained.

### Response Timeline

| Time | Event |
|---|---|
| T+0 | First SIEM export failure detected |
| T+0 | Record queued for retry; `gauntlet_siem_export_failures_total` incremented |
| T+(threshold failures) | `GauntletSystemAlert` created; `reason: SIEMExportDegraded` |
| T+(alert) | Alertmanager fires; designated personnel notified |
| T+(1 hour, fail-closed) | Probe scheduling halted |
| T+(recovery) | SIEM reachable; retry queue drained; scheduling resumes |
| T+(recovery) | `GauntletSystemAlert` resolved; resolved event exported to SIEM |

### Enhancement: AU-5(1) — Storage Capacity Warning

The `gauntlet_audit_record_count` metric provides advance warning of
approaching etcd storage capacity (see AU-4). Alertmanager rules fire
before capacity is exhausted, giving operators time to respond before
audit logging fails.

### Enhancement: AU-5(2) — Real-Time Alerts

`GauntletSystemAlert` creation triggers the Alertmanager rules configured
by the agency. With Alertmanager webhook integration (configured in Helm
values), notification of an export failure reaches designated personnel
within the time window between the failure threshold and the next
Alertmanager evaluation cycle — typically within minutes of the failure
onset.

## Evidence Produced

- `GauntletSystemAlert` CRs with `reason: SIEMExportDegraded`, including
  timestamps for alert onset and resolution, exported to SIEM when
  delivery recovers
- Prometheus metrics: `gauntlet_siem_export_failures_total`,
  `gauntlet_siem_export_retry_queue_depth`, `gauntlet_siem_backend_reachability`
- Controller structured logs recording export failure events, retry
  attempts, and recovery events
- Kubernetes audit log entries for `GauntletSystemAlert` creation and
  resolution (independent notification record)

## Customer Responsibility

The deploying agency must:
1. Configure Alertmanager rules against `gauntlet_siem_export_failures_total`
   and `GauntletSystemAlert` resources to notify designated operations staff
   of SIEM export failures within the agency's defined SLA
2. Set `audit.failClosedOnExportFailure: true` for High-baseline deployments
   to ensure fail-closed behavior when audit delivery cannot be guaranteed
3. Maintain SIEM endpoint availability and ensure SIEM credentials in
   `gauntlet-system` Secrets remain valid (expired credentials are the
   most common cause of export failure)
4. Define and document the agency's response procedure for
   `GauntletSystemAlert` with `reason: SIEMExportDegraded`, including
   the notification chain and the maximum acceptable SIEM outage duration
