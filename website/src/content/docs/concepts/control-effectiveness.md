---
title: Control Effectiveness
description: How Sidereal normalizes probe outcomes into compliance-ready assessments
---

Every SiderealProbeResult carries a `controlEffectiveness` field that normalizes the 12 possible probe outcomes into four values. This is the primary field for dashboards, reports, alerting, and incident creation.

## Effectiveness values

**Effective** -- The security control is working as intended. The probe verified that the enforcement layer is active and correctly denying or detecting the test action.

**Ineffective** -- The security control failed. The probe attempted an action that should have been blocked, denied, or detected, and the control did not respond. This represents a real gap in your security posture.

**Degraded** -- The probe could not fully evaluate the control. The enforcement layer may be partially working, the backend may be unreachable, or the result was inconclusive. Investigation is recommended.

**Compromised** -- The integrity of the probe result itself is in question. This occurs when HMAC verification fails, indicating the result may have been tampered with. A SystemAlert is created and the affected probe surface is suspended.

## Outcome mapping

| Probe Outcome | Control Effectiveness |
|---|---|
| Pass | Effective |
| Detected | Effective |
| Blocked | Effective |
| Rejected | Effective |
| Fail | Ineffective |
| Undetected | Ineffective |
| Accepted | Ineffective |
| NotEnforced | Ineffective |
| NotApplicable | Degraded |
| BackendUnreachable | Degraded |
| Indeterminate | Degraded |
| TamperedResult | Compromised |

## Usage

The `controlEffectiveness` field is:
- Set on every SiderealProbeResult by the result reconciler
- Available as a label (`sidereal.cloud/control-effectiveness`) for filtering
- Used by the incident reconciler to determine whether to create incidents (enforce mode)
- Used by the report generator for continuous monitoring summaries and POA&M entries
- Exposed as a Prometheus metric label for dashboards
