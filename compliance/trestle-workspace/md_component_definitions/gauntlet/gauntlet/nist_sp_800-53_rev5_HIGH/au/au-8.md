---
x-trestle-comp-def-rules:
  gauntlet:
    - name: rfc3339-timestamps-all-probe-results
      description: All GauntletProbeResult, GauntletIncident, and GauntletSystemAlert records include RFC 3339 UTC timestamps with nanosecond precision, sourced from NTP-synchronized node clocks and preserved through SIEM export
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: au-08
status: implemented
---

# AU-8 — Time Stamps

## Control Statement

Use internal system clocks to generate timestamps for audit records and
map those timestamps to Coordinated Universal Time (UTC) or Greenwich Mean
Time (GMT). Provide timestamps with granularity sufficient for incident
investigation and sequence-of-events reconstruction.

## Gauntlet Implementation

Every Gauntlet audit record carries RFC 3339 UTC timestamps with nanosecond
precision. Timestamps are sourced from the node's NTP-synchronized clock,
use UTC exclusively, and are preserved verbatim through SIEM export — the
authoritative event time is always the time the event occurred, not the
time it was delivered.

### Timestamp Format and Precision

All timestamps in Gauntlet audit records use RFC 3339 format with full
nanosecond precision:

```
2026-04-10T14:32:01.123456789Z
```

The `Z` suffix indicates UTC — no timezone offset ambiguity. Nanosecond
precision enables sub-millisecond event ordering, which is necessary for
reconstructing the sequence of events within a single probe execution
(e.g., ordering probe start, individual check events, result write, and
SIEM export delivery within a 60-second execution window).

### Timestamp Sources

**Go controller**: Timestamps are generated using `time.Now().UTC()` from
the Go standard library. When compiled with BoringCrypto (`GOEXPERIMENT=
boringcrypto`), the time package uses the same FIPS-validated runtime as
all other cryptographic operations. The controller reads the system clock
(CLOCK_REALTIME) from the Linux kernel on the node.

**Rust probe runners**: Timestamps are generated using the `chrono` crate's
`Utc::now()`, which also reads CLOCK_REALTIME from the Linux kernel.
Both the controller and probe runners read from the same underlying clock
source on the same node — timestamps from the same node are directly
comparable without conversion.

### Timestamps on Every Record Type

| Record Type | Timestamp Fields |
|---|---|
| `GauntletProbeResult` | `probeStartTime`, `probeEndTime`, `resultWriteTime`, `siemExportTime` |
| `GauntletIncident` | `detectedAt`, `reportedAt`, `webhookDeliveredAt` |
| `GauntletSystemAlert` | `raisedAt`, `acknowledgedAt`, `resolvedAt` |
| `GauntletAOAuthorization` | `authorizedAt`, `expiresAt` |

The distinction between `probeStartTime` and `resultWriteTime` allows
assessors to identify probe execution duration and to detect anomalous
delays between execution and result recording — a potential indicator of
result manipulation.

### Timestamp Preservation Through Export

SIEM export records preserve the original RFC 3339 timestamps from the
CRD fields verbatim. The SIEM event timestamp field is set to the
`probeStartTime` of the originating `GauntletProbeResult` — not the
delivery time.

This is critical for forensic accuracy: a record that experienced a SIEM
export delay (due to AU-5 retry) appears in the SIEM with its original
event time, not the delayed delivery time. Assessors querying the SIEM by
time window receive an accurate picture of when events occurred, not when
they were delivered.

The `siemExportTime` field in the `GauntletProbeResult` records the actual
delivery time, allowing the difference between event time and export time
to be computed and monitored for export pipeline health.

### NTP Dependency

The accuracy of all Gauntlet timestamps depends on the node clock being
synchronized to an authoritative NTP source. Clock drift on a node
introduces systematic timestamp errors across all records generated on
that node.

The controller monitors clock health indirectly: if the Kubernetes node's
system time drifts significantly, the JWT expiry validation for projected
ServiceAccount tokens will begin failing, causing probe runner Jobs to
fail authentication. This provides an indirect signal of severe clock
drift before it affects audit record accuracy.

For federal deployments, nodes must be synchronized to a DISA-approved
time source (see AU-8(1) below).

### Enhancement: AU-8(1) — Synchronization with Authoritative Time Source

The Kubernetes nodes running Gauntlet must synchronize to an authoritative
NTP time source. Gauntlet's audit records are only as accurate as the node
clock. For federal deployments at IL4/IL5, the authoritative time source
is a DISA NTP server or equivalent DoD-approved time service. The NTP
configuration is a node-level requirement documented in the cluster's
system security plan as a platform control.

### Enhancement: AU-8(2) — Secondary Authoritative Time Source

For High-baseline deployments, Kubernetes node NTP configuration should
reference at least two authoritative time sources (primary and secondary)
to provide continuity if the primary source becomes unavailable. A
single-source NTP configuration is a single point of failure for timestamp
accuracy across the entire audit record corpus.

## Evidence Produced

- `GauntletProbeResult` CRs with RFC 3339 UTC `probeStartTime`,
  `probeEndTime`, `resultWriteTime`, and `siemExportTime` fields
- `GauntletIncident` CRs with `detectedAt` and `reportedAt` timestamps
- `GauntletSystemAlert` CRs with `raisedAt`, `acknowledgedAt`, and
  `resolvedAt` timestamps
- SIEM event records preserving original probe timestamps for forensic
  sequencing; `siemExportTime` delta available for export latency analysis
- Controller startup logs confirming timestamp format configuration

## Customer Responsibility

The deploying agency must:
1. Configure all Kubernetes nodes to synchronize with a DISA-approved or
   equivalent authoritative NTP time source, with at least two NTP server
   references for High-baseline deployments
2. Monitor node clock drift via the cluster's infrastructure monitoring
   stack and alert on drift exceeding the acceptable tolerance for audit
   record accuracy (typically ±1 second for federal systems)
3. Document the NTP configuration for Gauntlet's hosting nodes in the SSP
   as a platform-level implementation of AU-8(1)
4. Not adjust node system clocks manually or through non-NTP mechanisms
   while Gauntlet is generating audit records, as this would corrupt the
   timestamp sequence for records spanning the clock adjustment
