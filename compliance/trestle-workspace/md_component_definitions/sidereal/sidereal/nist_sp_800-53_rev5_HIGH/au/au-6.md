---
x-trestle-comp-def-rules:
  sidereal:
    - name: detection-probe-validates-automated-audit-analysis
      description: Sidereal's detection probe validates that the automated audit analysis pipeline (Falco/Tetragon) generates alerts for known-bad syscall patterns, confirming the automated review mechanism required by AU-6(1) is operationally effective
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: au-06
status: implemented
---

# AU-6 — Audit Record Review, Analysis, and Reporting

## Control Statement

Review and analyze system audit records at an organization-defined frequency for
indications of inappropriate or unusual activity, identify and report findings to
organization-defined personnel or roles, and adjust the level of audit record review,
analysis, and reporting based on findings.

## Sidereal Implementation

Sidereal's contribution to AU-6 is specifically through the automated audit analysis
layer (AU-6(1)). The detection probe continuously validates that the automated audit
analysis pipeline — Falco or Tetragon — is operationally effective. The review and
reporting processes that complete AU-6 are the agency's responsibility and are described
under Customer Responsibility below.

### Enhancement: AU-6(1) — Automated Process Integration

Falco and Tetragon are automated audit analysis systems: they continuously process
kernel-level syscall events and generate structured alerts when patterns matching
detection rules are observed. This is the automated mechanism AU-6(1) requires.

The detection probe validates that this mechanism is functioning. On each execution:

1. The Rust detection probe fires a synthetic syscall pattern corresponding to the
   configured MITRE ATT&CK technique (e.g., T1611 container escape: `unshare(CLONE_NEWNS)`
   and `mount()` attempts). The syscalls are expected to fail in the sandboxed container;
   the detection layer should alert on the *attempt* regardless of whether the syscall
   succeeds.
2. The controller independently queries the detection backend via gRPC every 5 seconds
   for up to 60 seconds, filtering for alerts matching the probe's execution ID.
3. The outcome is recorded as `Detected` (alert confirmed), `Undetected` (no alert
   within the verification window — a detection gap), or `BackendUnreachable` (the
   analysis system is unreachable).

An `Undetected` result means the automated analysis system would not have generated an
alert for a real attack using that technique. The agency's audit review process (AU-6
base) would therefore never receive the finding to review. Continuous detection probe
execution catches this gap before a real event exploits it.

### What This Does Not Validate

The detection probe validates that automated analysis is generating alerts. It does not
validate:

- That generated alerts are being reviewed by the agency's security team
- That alert findings are being reported to the ISSO or other designated personnel
- That the review frequency meets the agency's defined schedule
- That the level of review is being adjusted based on findings

Those are procedural controls that the agency must implement through SIEM integration,
alert routing, and operational procedures.

### Detection Backend Configuration

The detection backend is configured at Helm install time via the deployment profile
(`global.profile`). Two backends are supported:

| Backend | Protocol | Default Port |
|---|---|---|
| Falco | gRPC | 50051 |
| Tetragon | gRPC | 54321 |

Both backends must be reachable from the controller's network egress path. The
`sidereal-system` NetworkPolicy permits egress to the configured detection backend port.

### AO Authorization Requirement

Detection probes require an active `SiderealAOAuthorization` resource scoped to the
technique ID and target namespace. When the authorization expires, the
`AuthorizationReconciler` creates a `SiderealSystemAlert` and detection probe scheduling
halts. This ensures detection coverage validation only occurs under explicit,
time-bounded AO approval — consistent with CA-8 (Penetration Testing) authorization
requirements for active technique simulation.

## Evidence Produced

- `SiderealProbeResult` CRs for each detection probe execution, recording the outcome
  (`Detected`, `Undetected`, `BackendUnreachable`), the MITRE ATT&CK technique ID, and
  the matching alert details from the backend when `Detected`
- `SiderealIncident` CRs for `Undetected` and `BackendUnreachable` outcomes in enforce
  mode, delivered to the IR webhook
- SIEM export records for all detection probe results, tagged with NIST and
  cross-framework control mappings for correlation
- `SiderealAOAuthorization` resources documenting the authorization record for each
  detection probe execution window

## Customer Responsibility

The deploying agency must:
1. Configure the detection backend (Falco or Tetragon) and verify it is reachable from
   the controller before enabling detection probes
2. Establish procedures for reviewing `SiderealProbeResult` records and `SiderealIncident`
   resources generated by detection probe outcomes — this is the AU-6 base review process
   that Sidereal's automation feeds into but does not perform
3. Configure SIEM alert routing to ensure `Undetected` and `BackendUnreachable` outcomes
   reach the ISSO and security operations team at the frequency required by AU-6
4. Issue and renew `SiderealAOAuthorization` resources with documented justification before
   each detection probe execution window
5. Adjust detection probe technique coverage and review frequency based on threat
   intelligence and findings, per the AU-6 requirement to adjust review based on findings
