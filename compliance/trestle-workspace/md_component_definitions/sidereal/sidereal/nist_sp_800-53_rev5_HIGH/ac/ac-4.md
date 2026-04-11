---
x-trestle-comp-def-rules:
  sidereal:
    - name: networkpolicy-probe-validates-flow-enforcement
      description: Sidereal NetworkPolicy probe verifies that Kubernetes NetworkPolicy rules enforce approved information flow paths and block unapproved ones, reading CNI enforcement verdicts directly from the CNI observability layer
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: ac-04
status: implemented
---

# AC-4 — Information Flow Enforcement

## Control Statement

Enforce approved authorizations for controlling information flow within the
system and between connected systems based on applicable policy. Flow control
decisions must account for information characteristics and must be enforced
at system boundaries and between internal segments.

## Sidereal Implementation

Information flow enforcement in a Kubernetes environment is implemented
by the CNI's NetworkPolicy engine. The question AC-4 asks is: is the CNI
actually enforcing the declared flow policy? A NetworkPolicy YAML is an
intent document — Sidereal tests whether that intent is being honored at
the enforcement layer.

### Active Flow Enforcement Validation — NetworkPolicy Probe

The NetworkPolicy probe launches ephemeral Rust Jobs that test both
approved and denied flow paths. The probe does not attempt to establish
a complete TCP connection — it sends a bounded TCP SYN and queries the
CNI observability layer (e.g., Cilium Hubble or Calico flow logs) for the
flow verdict associated with that probe's fingerprinted connection attempt.

**Deny-path verification**: The probe tests should-be-blocked flows. The
expected verdict is `Dropped`. A `Forwarded` verdict means an unauthorized
information flow path exists — the CNI is not enforcing the declared policy
for that source/destination pair. This produces a `Fail` outcome, a
`SiderealIncident` CR, and SIEM export.

**Allow-path verification**: The probe also tests should-be-permitted flows.
An unexpectedly `Dropped` verdict on an authorized path indicates
over-restriction — a legitimate information flow is being blocked. Both
failure modes produce `SiderealIncident` CRs.

**Reading from the enforcement source**: The CNI observability API (e.g.,
Hubble, Calico) is the authoritative record of what was actually enforced. The flow
verdict is not inferred from TCP behavior — it is read directly from the
component that made the enforcement decision. This eliminates false negatives
from application-layer responses that could obscure a network-layer bypass.

### What a Flow Enforcement Failure Means

A `Fail` on a deny-path test is a direct statement: an unauthorized
information flow path exists in the running cluster. Real traffic using
that path would not be blocked. This is not a configuration warning — it is
evidence of an active policy gap that exposes the system to lateral movement
or data exfiltration along that path.

The `SiderealIncident` CR records:
- Source namespace and workload identity
- Destination address, namespace, and port
- Protocol
- CNI flow verdict observed
- Expected verdict
- Timestamp and probe execution identity

### Sidereal's Own Information Flow Implementation

The `sidereal-system` NetworkPolicy models the correct information flow
posture (see SC-7 for the complete ingress/egress table). All flows from
and to `sidereal-system` are explicitly authorized; all others are denied
by default. This NetworkPolicy is itself a test subject of the probe surface
— Sidereal continuously verifies that its own flow policy is enforced.

### Timing Attack Mitigation

Probe scheduling is randomized with ±10% jitter around the configured
interval. An adversary who observes probe timing cannot reliably time an
unauthorized information flow to occur between probe windows. Jitter is
applied per-probe independently, preventing correlation across surfaces.

### Enhancement: AC-4(2) — Processing Domains

Kubernetes namespace isolation, enforced by NetworkPolicy, provides logical
processing domain separation. The NetworkPolicy probe verifies that
cross-namespace flows are blocked unless explicitly permitted — enforcing
the integrity of namespace-as-domain separation continuously.

### Enhancement: AC-4(8) — Security Policy Filters

The CNI NetworkPolicy engine functions as the information flow security
policy filter. The probe validates that the filter is processing flows
consistently with the declared policy. A filter that accepts a flow it
should reject is detected on the next probe execution.

### Enhancement: AC-4(12) — Data Type Identifiers

Sidereal probe traffic is fingerprinted with a unique label/annotation
(the probe execution identity). This allows CNI flow logs to distinguish
Sidereal-generated test flows from real application traffic. Agencies
configuring CNI flow alerting can exclude probe-fingerprinted flows from
production traffic alerts without creating blanket suppression rules
that would also suppress real attacker traffic.

## Evidence Produced

- `SiderealProbeResult` CRs recording pass/fail for each tested flow path,
  with source, destination, protocol, and CNI verdict (continuous,
  append-only)
- `SiderealIncident` CRs for flow enforcement failures, with full flow
  context, exported to SIEM
- `SiderealSystemAlert` CRs for unexpected flows observed by CNI
  observability correlation between probe windows
- CNI flow logs for all probe-generated flows, archived in SIEM

## Customer Responsibility

The deploying agency must:
1. Define NetworkPolicy objects that accurately reflect their authorized
   information flow policy — Sidereal validates enforcement of declared
   policy but does not generate the flow authorization policy itself
2. Enable a CNI with NetworkPolicy enforcement and observability (Cilium
   with Hubble, or Calico with flow logging, or equivalent) before Sidereal installation
3. Configure `SiderealProbe` resources to cover all flow paths critical
   to their system's information flow boundary policy
4. Apply a default-deny NetworkPolicy to all in-scope namespaces to
   ensure only explicitly authorized flows are permitted
