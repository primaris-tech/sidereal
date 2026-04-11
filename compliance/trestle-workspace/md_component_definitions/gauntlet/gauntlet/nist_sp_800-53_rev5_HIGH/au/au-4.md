---
x-trestle-comp-def-rules:
  gauntlet:
    - name: probe-result-impact-level-ttl-siem-export
      description: GauntletProbeResult records are retained for an impact-level-dependent minimum (365 days at High/Moderate, 180 days at Low) by controller TTL enforcement, with continuous SIEM export in configurable format (JSON/CEF/LEEF/Syslog/OCSF) providing durable off-cluster storage independent of etcd capacity
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: au-04
status: implemented
---

# AU-4 — Audit Log Storage Capacity

## Control Statement

Allocate audit log storage capacity to reduce the likelihood of capacity
being exceeded and implement controls to ensure audit logging does not
fail due to storage limitations. Protect audit records from unauthorized
modification and ensure availability for the required retention period.

## Gauntlet Implementation

Gauntlet implements a two-tier audit record storage architecture. The
in-cluster tier (Kubernetes etcd) provides fast, queryable, access-controlled
storage for the active retention window. The off-cluster tier (SIEM) provides
durable long-term storage that survives cluster loss and operates
independently of etcd capacity constraints.

### Tier 1: In-Cluster Storage — etcd

`GauntletProbeResult` CRs are stored in the Kubernetes API server (etcd).
Capacity is managed through several mechanisms:

**Minimum retention floor**: The controller enforces an impact-level-dependent minimum TTL
on all `GauntletProbeResult` CRs at admission time (365 days for High/Moderate, 180 days
for Low). A TTL annotation below the floor for the configured `global.impactLevel` is rejected
by the controller's validating admission webhook. This is a floor, not a ceiling — the agency
may configure a longer in-cluster retention period.

**Append-only protection**: The admission enforcement policy (e.g., Kyverno ClusterPolicy or OPA Constraint) denying UPDATE and
DELETE operations on `GauntletProbeResult` resources (SR-9) ensures that
records cannot be deleted to free capacity before their TTL expires. Capacity
management cannot be used as a mechanism to purge inconvenient evidence.

**Capacity monitoring**: The `gauntlet_audit_record_count` Prometheus metric
tracks the current number of `GauntletProbeResult` records in the cluster.
Alertmanager rules (configured by the agency) fire when this count approaches
the etcd quota threshold, providing advance warning before capacity is reached.

**ResourceQuota bounding**: The `gauntlet-system` namespace ResourceQuota
caps the total storage objects can consume in etcd, preventing unbounded
growth from starving other namespace quotas.

### Tier 2: Off-Cluster Storage — SIEM

Every `GauntletProbeResult` and `GauntletIncident` record is exported to
the configured SIEM immediately upon creation. The SIEM export is not
optional for audit records — export failures are tracked, retried, and
escalated (see AU-5).

SIEM export provides:
- **Cluster-independent retention**: records survive etcd loss, cluster
  rebuild, and node failures
- **Long-term retention beyond 365 days**: agency-defined retention policy
  applied in the SIEM (NIST 800-53 does not specify a universal upper limit;
  many High-baseline systems require 3+ years)
- **Tamper-resistant at-rest storage**: S3 export uses object lock in
  COMPLIANCE mode — records cannot be modified or deleted during the
  retention period, even by the bucket owner

The SIEM is the authoritative long-term audit record store. The in-cluster
CRDs serve the operational use case (live querying, probe scheduling context);
the SIEM serves the compliance and forensic use case.

### Capacity Failure Prevention

Gauntlet is designed to never silently fail to record an audit event due
to capacity pressure:
- **Pre-failure alerting**: `gauntlet_audit_record_count` and the namespace
  ResourceQuota utilization metric alert before capacity is exhausted
- **Export as pressure relief**: once records are durably exported to the
  SIEM, etcd is not the sole copy; agencies can choose to configure shorter
  in-cluster TTLs (above the 365-day floor) if etcd capacity is constrained,
  knowing the SIEM holds the long-term copy
- **Fail-closed on export failure**: if the SIEM export pipeline is degraded,
  probe scheduling halts rather than accumulating records that cannot be
  durably stored (configurable via `audit.failClosedOnExportFailure`)

### Enhancement: AU-4(1) — Transfer to Alternate Storage

The SIEM export is Gauntlet's implementation of transfer to alternate
storage. Records are transferred to the SIEM immediately on creation, before
any risk of in-cluster capacity pressure. S3 export with object lock provides
WORM (Write Once Read Many) alternate storage that is independent of cluster
infrastructure.

## Evidence Produced

- `GauntletProbeResult` CRs in etcd with controller-enforced 365-day
  minimum TTL annotations
- SIEM export delivery confirmations (Splunk HEC acknowledgment tokens,
  Elasticsearch `_id` records, S3 object ETags)
- `gauntlet_audit_record_count` Prometheus metric time series
- `gauntlet_audit_export_failures` Prometheus metric (capacity pressure
  early warning)
- Controller startup log confirming retention TTL floor configuration

## Customer Responsibility

The deploying agency must:
1. Provision sufficient SIEM storage capacity for their full retention
   requirement (typically 3 years for High-baseline federal systems)
2. Configure S3 Object Lock in COMPLIANCE mode (not just GOVERNANCE mode)
   for the Gauntlet S3 export bucket if using S3 as the SIEM target
3. Configure Alertmanager rules for `gauntlet_audit_record_count` and
   `gauntlet_audit_export_failures` to alert before capacity thresholds
   are breached
4. Ensure SIEM credentials stored in `gauntlet-system` Secrets are rotated
   on the agency's defined credential rotation schedule
