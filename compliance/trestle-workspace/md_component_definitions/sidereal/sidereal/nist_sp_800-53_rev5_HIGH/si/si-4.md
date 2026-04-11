---
x-trestle-comp-def-rules:
  sidereal:
    - name: sidereal-system-monitoring
      description: Sidereal implements continuous active system monitoring through security probes with jitter-randomized scheduling and NIST-mapped result generation
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: si-04
status: implemented
---

# SI-4 — System Monitoring

## Control Statement

Monitor the system to detect attacks and indicators of potential attacks; identify
unauthorized use of the system; invoke greater degree of internal monitoring for
specific events; and report unusual or unauthorized activities.

## Sidereal Implementation

Sidereal implements active system monitoring across five control surfaces continuously.
Unlike passive monitoring tools that observe events, Sidereal actively probes to verify
controls are functioning — detecting control drift before it becomes an attack vector.

### Active Monitoring Surfaces

**RBAC Monitoring** — Sidereal probes whether ServiceAccounts can perform operations
outside their authorized scope. Failed enforcement (a probe that should receive a 403
but does not) is an active indicator of RBAC drift — a misconfiguration that an attacker
could exploit. Detected immediately on the next probe execution.

**NetworkPolicy Monitoring** — Sidereal sends TCP SYN probes to test whether east-west
traffic restrictions are enforced. A `Forwarded` outcome on a should-be-blocked path
indicates an active network policy gap. The CNI flow verdict is read directly from
CNI observability backends (e.g., Hubble, Calico) — the authoritative enforcement source.

**Admission Control Monitoring** — Sidereal submits known-bad specs and verifies
rejection. An `Accepted` outcome indicates the admission webhook is misconfigured,
disabled, or bypassed — a direct control failure requiring immediate response.

**Secret Access Monitoring** — Sidereal attempts cross-namespace secret reads and
verifies 403 rejection. A pass on a should-be-denied operation indicates RBAC
boundaries have drifted, exposing credential data.

**Detection Coverage Monitoring** — Sidereal emits known-bad syscall patterns and
queries the detection backend (e.g., Falco, Tetragon) to verify an alert was generated. An `Undetected` outcome
means the detection layer has a gap — real attacks using that pattern would go
undetected.

### Timing Attack Mitigation (SI-4 Enhancement)

Probe scheduling is randomized with ±10% jitter around the configured interval.
This prevents an attacker who observes probe timing from predicting monitoring
windows and timing attacks to occur between probe executions.

### Internal Monitoring Escalation

When consecutive failures are detected on a probe surface, the `consecutiveFailures`
counter increments and Alertmanager rules (configured by the agency) escalate
monitoring intensity. SiderealIncident resources are created for every failure
outcome, triggering the agency's IR webhook.

### Unauthorized Use Detection

RBAC and Secret Access probes continuously verify that ServiceAccounts cannot
access resources outside their authorized scope. Any probe returning a non-failure
outcome on a should-be-denied operation is a direct indicator of potential
unauthorized access.

## Evidence Produced

- `SiderealProbeResult` records for all probe executions (continuous)
- `sidereal_consecutive_failures` Prometheus metric
- `SiderealIncident` resources for all failure outcomes
- SIEM export records with probe outcomes and NIST control mappings

## Customer Responsibility

The deploying agency must:
1. Configure Alertmanager rules to escalate on `sidereal_consecutive_failures`
2. Review SiderealIncident records as part of their ongoing monitoring procedures
3. Operate complementary passive monitoring tools (detection backends such as Falco or Tetragon, SIEM correlation)
   alongside Sidereal's active monitoring
