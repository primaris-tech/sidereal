---
x-trestle-comp-def-rules:
  gauntlet:
    - name: continuous-probe-evidence-for-assessments
      description: Gauntlet produces continuous, timestamped GauntletProbeResult and GauntletIncident records across all five probe surfaces that serve as machine-readable assessment evidence importable into OSCAL Assessment Results
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: ca-02
status: implemented
---

# CA-2 — Control Assessments

## Control Statement

Assess the controls in the system and its environment to determine the
extent to which controls are implemented correctly, operating as intended,
and producing the desired outcome. Assessments must be conducted by
assessors with required independence and technical competence.

## Gauntlet Implementation

Gauntlet transforms control assessment from a periodic manual event into
a continuous automated process. Each probe execution is a control
assessment — it tests whether a specific security control is operationally
effective, not merely configured. The distinction is fundamental to
Gauntlet's value: existing tools verify configuration; Gauntlet verifies
effectiveness.

### Continuous Assessment vs. Point-in-Time Assessment

A traditional control assessment asks: "is this control configured
correctly?" at a specific moment. Between assessments, drift can occur
undetected. Gauntlet asks: "is this control enforcing its policy right
now?" continuously, at a cadence tied to the FIPS 199 impact level.

| Impact Level | Maximum Assessment Interval |
|---|---|
| High | Every 6 hours (21,600 seconds) |
| Moderate | Every 24 hours |
| Low | Every 72 hours |

At the High impact level, each security control surface is assessed up to
4 times per day. A control failure has a maximum detection latency of 6
hours — compared to months or years in a point-in-time assessment cycle.

### What Each Assessment Produces

Every probe execution produces a `GauntletProbeResult` CR with:

| Field | Content |
|---|---|
| `probe.type` | Which control surface was assessed |
| `result.outcome` | Pass / Fail / Indeterminate outcome |
| `execution.timestamp` | RFC3339 timestamp of assessment |
| `result.nistControls` | NIST 800-53 control IDs assessed |
| `result.integrityStatus` | HMAC verification result |
| `audit.exportStatus` | SIEM export confirmation |
| `probe.id` | Unique probe execution identity |

HMAC signing of the result payload ensures the assessment evidence is
integrity-protected from probe runner to controller to SIEM. A tampered
result is detected and flagged rather than accepted as valid evidence
(SI-7, SR-9).

### Control Coverage by Probe Surface

| Probe Surface | NIST Controls Assessed |
|---|---|
| RBAC | AC-2, AC-3, AC-6 |
| NetworkPolicy | AC-4, SC-7, SC-8 |
| Admission Control | CM-6, CM-7, SI-7 |
| Secret Access | AC-3, AC-4 |
| Detection Coverage | SI-3, SI-4, SI-7 |

Each `GauntletProbeResult` includes the specific control IDs being assessed
in the `result.nistControls` field, enabling SIEM queries filtered by
control family or individual control identifier.

### OSCAL Assessment Results Output

`GauntletProbeResult` data is formatted for export as OSCAL Assessment
Results, providing machine-readable evidence directly importable into
agency ATO tooling (eMASS, XACTA, Trestle). Each probe execution maps to
an OSCAL `finding` with:
- `finding.target` — the specific control being assessed
- `finding.implementation-status` — implemented / not-implemented
- `finding.observation` — timestamped, HMAC-verified result record
- `finding.risk` — populated for Fail outcomes with the specific gap

This allows the agency's ISSO to generate continuous monitoring reports
directly from Gauntlet's OSCAL output without manual correlation.

### Assessment Independence

Gauntlet's controller is architecturally independent from the controls
it assesses. The controller that verifies RBAC probe outcomes does not
hold the RBAC permissions it is testing. The controller that records
detection probe results does not operate the detection backend (e.g., Falco,
Tetragon). Assessment results reflect actual control state — the assessor
cannot produce a false positive by using its own privileged access.

The admission enforcement append-only policy (SR-9) further ensures that once an
assessment record is written, it cannot be modified by the controller or
any other principal — including one attempting to retroactively "pass"
a failed assessment.

### Enhancement: CA-2(1) — Independent Assessors

Gauntlet's probe execution is structurally independent of the control
implementations it tests. This independence satisfies CA-2(1)'s requirement
for assessor independence at the technical layer. The controller holds no
privileges that would allow it to produce a misleading assessment result
for the controls it evaluates.

For the organizational independence requirement (human assessors), Gauntlet's
OSCAL Assessment Results output enables external assessors to review
machine-generated evidence without requiring direct cluster access — reducing
the access footprint of the assessment engagement.

### Enhancement: CA-2(2) — Specialized Assessments

The Detection Coverage probe surface constitutes a specialized assessment
(adversarial simulation) for detection control effectiveness. See CA-8 for
the full penetration testing implementation.

### Enhancement: CA-2(3) — Leveraging External Assessment Results

`GauntletProbeResult` records exported to the SIEM are accessible to
third-party assessors without requiring direct cluster access. An assessor
can query the SIEM for all probe results in a given assessment window,
filter by control family, and export OSCAL Assessment Results — leveraging
Gauntlet's continuous assessment output to inform their independent review.

## Evidence Produced

- `GauntletProbeResult` CRs for all five probe surfaces (append-only,
  HMAC-signed, 365-day minimum TTL, SIEM-exported)
- `GauntletIncident` CRs for each detected control failure, mapped to
  specific NIST 800-53 control IDs
- OSCAL Assessment Results generated from `GauntletProbeResult` data,
  importable into agency ATO tooling
- Assessment frequency compliance warnings in controller logs when
  configured interval exceeds the FIPS 199 impact level threshold

## Customer Responsibility

The deploying agency must:
1. Review Gauntlet's probe scope and scheduling parameters as part of the
   ATO process to confirm that continuous assessment coverage meets their
   Security Assessment Plan requirements
2. Declare the system's FIPS 199 impact level in Gauntlet Helm values to
   enforce the correct assessment cadence
3. Designate personnel to triage `GauntletIncident` records within the
   agency's defined response SLA
4. Use Gauntlet's OSCAL Assessment Results output as primary evidence in
   their ongoing authorization process, supplemented by periodic independent
   assessments as required by their ISCM strategy
