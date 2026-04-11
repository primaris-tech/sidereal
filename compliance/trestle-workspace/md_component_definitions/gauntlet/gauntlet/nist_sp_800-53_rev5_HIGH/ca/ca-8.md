---
x-trestle-comp-def-rules:
  gauntlet:
    - name: detection-probe-requires-ao-authorization
      description: Gauntlet detection coverage probes perform adversarial simulation and require a GauntletAOAuthorization CR before execution; probes run in a sandboxed context with no shell, no network, and a restrictive seccomp profile
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: ca-08
status: implemented
---

# CA-8 — Penetration Testing

## Control Statement

Conduct penetration testing on organizational systems at a defined frequency
and when significant changes occur. Testing must be conducted by testers
with defined rules of engagement, and findings must be tracked to
remediation.

## Gauntlet Implementation

Gauntlet's Detection Coverage probe surface transforms penetration testing
from a periodic engagement into a continuous automated process. Rather than
hiring a red team once per year, Gauntlet emits known-bad syscall patterns
continuously and verifies that the detection layer responds — producing
structured penetration testing evidence on every execution cycle.

### The Detection Probe as Continuous Penetration Testing

Traditional penetration testing asks: "could an attacker use this technique
against us?" at a point in time. Gauntlet's detection probe asks: "would
our detection tooling catch this technique right now?" continuously.

The probe emits adversarial syscall sequences mapped to MITRE ATT&CK for
Containers techniques (e.g., `T1611` — Escape to Host, `T1055` — Process
Injection). The controller then independently queries the detection backend
(e.g., Falco or Tetragon) to verify that an alert was generated within the
verification window (default: 60 seconds, 5-second polling).

**Detection outcomes**:
| Outcome | Meaning | Response |
|---|---|---|
| `Detected` | Alert raised within the verification window | Pass — detection coverage confirmed |
| `Undetected` | No alert raised within the verification window | Fail — detection gap; `GauntletIncident` created |
| `Blocked` | Detection backend enforcement mode (e.g., Tetragon enforcement mode) prevented the syscall | Pass — enforcement active |
| `BackendUnreachable` | Detection backend unavailable | `GauntletSystemAlert` — monitoring halted |

An `Undetected` outcome means a real attacker using that technique would
go undetected by the current detection ruleset. It is a finding that
requires remediation — either updating the detection rules or accepting
the risk with AO approval.

### Mandatory AO Authorization Gate

Detection probes that perform adversarial simulation require explicit
Authorizing Official authorization before execution. The controller will
not schedule a detection probe Job unless a `GauntletAOAuthorization` CR
is present and valid.

The `GauntletAOAuthorization` CR encodes the rules of engagement:

```yaml
apiVersion: gauntlet.io/v1alpha1
kind: GauntletAOAuthorization
metadata:
  name: detection-probe-auth
  namespace: gauntlet-system
spec:
  authorizedBy: "isso-firstname.lastname@agency.gov"
  authorizedAt: "2026-04-10T00:00:00Z"
  expiresAt: "2026-07-10T00:00:00Z"   # 90-day authorization window
  scope:
    probeTypes: ["detection"]
    targetNamespaces: ["production", "staging"]
    techniques: ["T1611", "T1055", "T1003"]
  justification: "Annual ISCM assessment cycle; detection gap closure"
```

Key authorization properties:
- **Named authorizing principal**: the ISSO or AO is identified by name
- **Expiry window**: authorization is time-bounded; expired authorizations
  halt probe execution and generate a `GauntletSystemAlert`
- **Scoped techniques**: only explicitly authorized MITRE techniques are
  executed during the authorization window
- **Target namespaces**: execution scope is bounded to the declared
  namespaces

The `GauntletAOAuthorization` creation event is recorded in the Kubernetes
audit log and exported to the SIEM — the authorization decision is auditable
independent of Gauntlet's own logging.

### Sandboxed Execution — Blast Radius Controls

Detection probe runners operate under the most restrictive execution
posture of any Gauntlet component:

- **No shell**: distroless/scratch image; no `sh`, `bash`, or interpreter
- **No network**: isolated network namespace; cannot initiate connections
- **No volume mounts**: no PVC, no Secret mount (result written via
  the Kubernetes API using the projected SA token)
- **Read-only root filesystem**: `readOnlyRootFilesystem: true`
- **Custom Localhost seccomp profile**: a probe-specific allow-list more
  restrictive than RuntimeDefault; permits only the syscalls required to
  emit the target adversarial pattern and write the result
- **All Linux capabilities dropped**: no `CAP_SYS_ADMIN`,
  `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, or any other elevated capability

The probe binary emits the target syscall pattern and exits. There is no
interactive mode, no persistence, and no lateral movement capability in
the probe binary — the binary cannot do anything except its single
declared function.

### Finding Tracking to Remediation

`Undetected` outcomes are not silent. They produce:
1. `GauntletProbeResult` CR with `result.outcome: Undetected` and the
   specific MITRE technique that went undetected
2. `GauntletIncident` CR with the detection gap details, exported to SIEM
3. IR webhook trigger to the agency's designated security contact
4. `consecutiveUndetected` counter incremented in the probe status
   subresource

Remediation tracking:
- The `GauntletIncident` CR has a `remediationStatus` field updated by the
  operator as the gap is investigated and closed
- Closing a detection gap (e.g., updating a detection rule) is verified by
  the next probe execution — a `Detected` outcome confirms the remediation
  was effective
- The `GauntletProbeResult` record of the first post-fix `Detected` outcome
  is the evidence that the finding has been remediated

### Significant Change Trigger

In addition to scheduled execution, detection probe execution is triggered
when significant changes are detected in the cluster:
- Detection rule update (e.g., Falco rule ConfigMap version change or Tetragon TracingPolicy update)
- Detection backend restart (pod restart event in the detection namespace)

These events trigger an out-of-cycle detection probe execution to confirm
that the change did not degrade detection coverage — satisfying the
"when significant changes occur" requirement of CA-8.

### Enhancement: CA-8(1) — Independent Penetration Testers

The detection probe runner is architecturally independent from the
detection backend instances it tests. The probe runner (Gauntlet) and the
detection backend (e.g., Falco, Tetragon) are separate workloads under separate
identities. The probe runner cannot influence the detection backend's
alerting decisions — it can only emit syscalls and observe whether alerts
are raised.

This independence satisfies CA-8(1)'s intent: the entity conducting the
test cannot also control the outcome of the test.

### Enhancement: CA-8(2) — Red Team Exercises

The Detection Coverage probe surface implements lightweight, continuous
red team exercises against the detection layer. Unlike periodic red team
engagements, Gauntlet's coverage is continuous — detection gaps are found
on the next execution cycle, not in the next annual engagement. Periodic
full red team exercises by human testers remain the agency's responsibility;
Gauntlet provides the continuous baseline between those engagements.

## Evidence Produced

- `GauntletAOAuthorization` CRs recording the authorizing principal, scope,
  authorization window, and justification for each detection probe campaign
- `GauntletProbeResult` CRs mapping simulated MITRE techniques to detection
  outcomes (Detected / Undetected / Blocked / BackendUnreachable)
- `GauntletIncident` CRs for each `Undetected` outcome with technique
  identifier and detection backend query results, exported to SIEM
- Kubernetes audit log entries for `GauntletAOAuthorization` creation
  events (authorization decision audit trail)
- Detection backend response logs (e.g., Falco/Tetragon alerts) correlated with
  probe execution timestamps in SIEM

## Customer Responsibility

The deploying agency must:
1. Have an authorized ISSO or AO create the `GauntletAOAuthorization` CR
   before detection probes execute, defining the scope, time window, and
   authorized MITRE techniques
2. Review `GauntletIncident` records for `Undetected` outcomes and track
   remediation of each detection gap to closure
3. Verify detection coverage remediation by confirming a subsequent
   `Detected` outcome on the same technique after detection backend rule
   updates
4. Conduct periodic full red team exercises by independent human testers
   to supplement Gauntlet's continuous detection coverage testing
5. Document Gauntlet's detection probe results as penetration testing
   evidence in their continuous monitoring reporting
