---
x-trestle-comp-def-rules:
  gauntlet:
    - name: probes-verify-security-functions-are-operating
      description: Gauntlet's five probe surfaces continuously verify that the security functions they depend on (RBAC enforcement, NetworkPolicy CNI, admission control, secret store access controls, detection coverage) are operating as intended
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: si-06
status: implemented
---

# SI-6 — Security and Privacy Function Verification

## Control Statement

Verify the correct operation of security and privacy functions. Notify
designated personnel of failed security verification tests. Provide the
capability to notify personnel, shut down the system, or restart the system
when anomalies are discovered.

## Gauntlet Implementation

SI-6 is the control that most directly captures Gauntlet's mission. Every
probe execution is a security function verification test. The distinction
between Gauntlet and other monitoring tools is precisely the SI-6 property:
not just detecting events, but actively verifying that security functions
are producing the expected behavior.

### Security Function Verification by Probe Surface

Each probe surface tests a specific security function:

| Probe Surface | Security Function Verified | Failure Indicator |
|---|---|---|
| RBAC | Kubernetes RBAC enforcement is denying unauthorized operations | A should-be-403 operation returns success |
| NetworkPolicy | CNI is enforcing declared boundary policy (SC-7) | A should-be-dropped flow is forwarded |
| Admission Control | Admission controller policies are active and rejecting non-compliant specs | A known-bad spec is admitted |
| Secret Access | Secret store RBAC boundaries are enforced across namespaces | A should-be-403 cross-namespace GET succeeds |
| Detection Coverage | Detection backend rules (e.g., Falco, Tetragon) are triggering on known-bad syscall patterns | A probe-generated alert is not observed within the verification window |

A `Fail` outcome on any probe surface is not just a monitoring alert — it
is a direct verification that a specific security function has stopped
working. The difference between a misconfigured network policy (a
configuration finding) and an unenforced network policy (a SI-6 security
function failure) is what Gauntlet measures.

### Bootstrap Verification — Before Continuous Assessment Begins

Before scheduling any probe execution, the controller performs startup
verification of all security functions that probes depend on:

1. Admission controller webhook is reachable and responding to admission requests
2. CNI observability API (e.g., Hubble, Calico) is reachable
3. Detection backend (e.g., Falco, Tetragon) is reachable via gRPC
4. HMAC root Secret is present and readable in `gauntlet-system`
5. SIEM export endpoint is reachable with valid TLS

If any prerequisite is absent or non-responsive, the controller raises a
`GauntletSystemAlert` with `reason: SecurityFunctionUnavailable` and does
**not** proceed to probe scheduling. This prevents Gauntlet from producing
misleading evidence during a window when it cannot meaningfully verify
security functions.

The bootstrap check runs on every controller startup — including restarts
after crashes, node migrations, and upgrades. Security function availability
is re-verified before every new monitoring cycle begins.

### Notification of Failed Verification Tests

Security function failures are reported through multiple channels:

**Immediate (automated)**:
- `GauntletIncident` CR created for every `Fail` outcome; includes the
  specific security function, expected behavior, and observed behavior
- IR webhook triggered (configured in Helm values) with the incident payload
- `GauntletIncident` exported to SIEM with NIST 800-53 control mapping

**Escalating (automated)**:
- `gauntlet_consecutive_failures` Prometheus metric increments on each
  consecutive failure on a probe surface
- Alertmanager rules (configured by the agency) fire when the counter
  exceeds the threshold, escalating to designated personnel

**Critical (automated)**:
- `GauntletSystemAlert` created for security function unavailability or
  `TamperedResult` detection
- Probe execution suspended until an authorized principal acknowledges the
  alert
- Alert exported to SIEM

The notification path is fully automated. No human needs to observe a
dashboard to trigger the initial notification — the IR webhook fires on
every `GauntletIncident` creation.

### Shutdown and Restart Capability

Gauntlet provides graduated response capabilities aligned with SI-6's
shutdown/restart requirement:

**Probe surface suspension**: When a `GauntletSystemAlert` is raised (for
`TamperedResult`, `SecurityFunctionUnavailable`, or `BackendUnreachable`),
probe execution on the affected surface is automatically suspended. The
controller stops scheduling new Jobs for that surface. This is equivalent
to "shutting down" the affected monitoring function pending investigation.

**Acknowledgment-gated restart**: Probe execution resumes only after an
authorized operator acknowledges the `GauntletSystemAlert` via a status
patch. The acknowledgment is recorded in the Kubernetes audit log (who
acknowledged, when) and exported to the SIEM. This is the "restart after
remediation" path.

**Full system halt**: If the controller itself cannot reach the Kubernetes
API, it enters a non-operational state and does not attempt probe scheduling.
The absence of probe results in the SIEM is itself a monitoring signal
configured via Alertmanager rules.

### Enhancement: SI-6(1) — Notification of Failed Security Tests

`GauntletIncident` CRs are created automatically on every failed security
verification test. The IR webhook delivers notification to designated
personnel (configured endpoint in Helm values) within the time window of
the probe execution cycle — no polling or manual review is required to
receive the notification.

## Evidence Produced

- `GauntletProbeResult` CRs for each security function verification cycle
  across all five probe surfaces (continuous evidence of verification)
- `GauntletIncident` CRs for every `Fail` outcome, with specific security
  function, expected behavior, and observed behavior
- `GauntletSystemAlert` CRs with `reason: SecurityFunctionUnavailable` when
  a prerequisite security function is detected as non-operational
- Controller startup logs documenting bootstrap verification results
- `gauntlet_consecutive_failures` Prometheus metric time series
- IR webhook delivery records for all `GauntletIncident` notifications

## Customer Responsibility

The deploying agency must:
1. Ensure that prerequisite security functions (an admission controller such as Kyverno or OPA/Gatekeeper, a detection backend such as Falco or Tetragon,
   CNI with observability such as Hubble or Calico) are deployed and operational
   before installing Gauntlet
2. Configure the IR webhook endpoint in Gauntlet Helm values to ensure that
   `GauntletIncident` notifications reach designated security personnel
3. Configure Alertmanager rules for `gauntlet_consecutive_failures` to
   escalate to on-call personnel when a security function fails repeatedly
4. Define and document the acknowledgment procedure for `GauntletSystemAlert`
   resources in their incident response plan, including the criteria under
   which probe execution may be restarted
