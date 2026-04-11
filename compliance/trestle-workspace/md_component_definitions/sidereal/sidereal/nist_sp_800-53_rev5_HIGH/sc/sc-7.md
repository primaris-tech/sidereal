---
x-trestle-comp-def-rules:
  sidereal:
    - name: networkpolicy-probe-validates-boundary-enforcement
      description: Sidereal's NetworkPolicy probe surface actively tests that cluster boundary protections (CNI-enforced NetworkPolicies) block unauthorized cross-namespace and external traffic as declared
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: sc-07
status: implemented
---

# SC-7 — Boundary Protection

## Control Statement

Monitor and control communications at the external boundary of the system and
at key internal boundaries. Implement subnetworks for publicly accessible
components that are physically or logically separated from internal networks,
and connect to external networks only through managed interfaces.

## Sidereal Implementation

Sidereal contributes to boundary protection through two distinct mechanisms:
active probing that validates boundary enforcement is operating as declared,
and its own strict boundary implementation that models the expected posture
for the cluster.

### Active Boundary Validation — The NetworkPolicy Probe Surface

The NetworkPolicy probe surface is Sidereal's direct implementation of SC-7
continuous monitoring. It answers a specific question: **is the CNI actually
enforcing the boundary policy that has been declared?** A NetworkPolicy YAML
in the cluster does not guarantee the CNI is enforcing it — a CNI
misconfiguration, upgrade regression, or policy ordering error can silently
break enforcement while the configuration looks correct.

**Probe mechanics**: Ephemeral Rust probe Jobs are launched into the target
namespace. Each Job performs a bounded TCP SYN probe to a specified
destination (cross-namespace endpoint or external address) and queries the
CNI observability layer (e.g., Cilium Hubble or Calico flow logs) for the
flow verdict associated with that probe's fingerprinted connection.

**No persistent responder required**: The probe does not need a server
listening at the target address. The CNI enforces the policy before the
packet reaches its destination — the flow verdict (Dropped / Forwarded) is
readable from the CNI observability API and is the authoritative enforcement
record. The probe reads the verdict directly from the source of enforcement.

**Probe outcomes**:
| Outcome | Meaning |
|---|---|
| `Pass` | Flow was dropped as expected; boundary enforcement confirmed |
| `Fail` | Flow was forwarded on a should-be-blocked path; active boundary gap |
| `Indeterminate` | CNI observability API unreachable; boundary state unknown |

A `Fail` outcome means a real attacker could traverse the same path. It
produces a `SiderealIncident` CR with the source namespace, destination,
and protocol of the detected gap, triggering the agency's IR webhook.

**Both deny and allow paths are tested**: The probe validates that
should-be-blocked flows are dropped AND that should-be-permitted flows are
not inadvertently blocked by an overly restrictive policy. Both failure modes
are security-relevant.

### Continuous Out-of-Band Boundary Monitoring

CNI observability API (e.g., Hubble API) integration provides real-time network flow telemetry between
probe executions. The controller correlates observed flows against the
declared boundary policy. Flows that:
- Originate from `sidereal-system` but do not match any scheduled probe
  (unfingerpinted)
- Cross a namespace boundary that should be deny-all
- Target an external address not in the permitted egress list

generate a `SiderealSystemAlert` with `reason: UnexpectedNetworkFlow`.
This detects boundary violations that occur between probe windows — an
attacker who observes probe timing cannot exploit a between-probe window
without triggering the CNI observability correlation alert.

### Sidereal's Own Boundary Implementation

The `sidereal-system` namespace is a reference implementation of boundary
protection. Its `NetworkPolicy` enforces:

**Ingress**:
- Kubernetes API server → controller: port 443 only (for webhook callbacks)
- Prometheus → controller: port 8080 (metrics scrape only)
- No pod-to-pod ingress from any other namespace

**Egress**:
- Controller → Kubernetes API server: port 443
- Controller → SIEM endpoint: configured port (443 or 9200)
- Controller → Detection backend gRPC (e.g., Falco): port 50051 (when detection probe enabled)
- Controller → CNI observability API (e.g., Hubble): port 4240 (when NetworkPolicy probe enabled)
- All other egress: denied

This NetworkPolicy is itself a test subject. The NetworkPolicy probe runs
against `sidereal-system` on each execution cycle, producing
`SiderealProbeResult` records that continuously attest to the boundary
posture of the monitoring system itself.

### Enhancement: SC-7(3) — Access Points

Sidereal has no publicly accessible endpoints. The controller's HTTP server
(metrics, liveness, readiness) is accessible only within the cluster via
the Service ClusterIP. No LoadBalancer or NodePort Service exists in the
Helm chart. The SIEM export is outbound-only (controller-initiated).

### Enhancement: SC-7(5) — Deny by Default / Allow by Exception

The `sidereal-system` NetworkPolicy implements default-deny for both
ingress and egress. All permitted flows are explicitly enumerated. Any
traffic not matching an explicit allow rule is dropped at the CNI layer.
This is verified by the NetworkPolicy probe surface on each execution cycle.

### Enhancement: SC-7(8) — Route Traffic to Managed Interfaces

All Sidereal external communications (SIEM export, CNI observability API
queries) are initiated from the controller's single managed network
interface within `sidereal-system`. No probe runner establishes external
connections — probe runners communicate only with the Kubernetes API server
using their per-probe ServiceAccount credentials.

## Evidence Produced

- `SiderealProbeResult` CRs for each tested network flow path, with
  allow/deny outcome and CNI flow verdict source (continuous)
- `SiderealIncident` CRs for boundary enforcement failures, with source
  namespace, destination, and protocol
- `SiderealSystemAlert` CRs for unexpected flows detected by CNI
  observability correlation (between-probe-window detections)
- CNI flow logs (e.g., Hubble/Calico flow logs) for all probe-generated flows, exported to SIEM

## Customer Responsibility

The deploying agency must:
1. Enable CNI NetworkPolicy enforcement (Calico, Cilium, or equivalent) in
   the cluster and apply a default-deny posture to all namespaces in scope
2. Author a complete boundary policy (NetworkPolicy manifests) for all
   namespaces — Sidereal validates enforcement of declared policy but cannot
   substitute for the agency's responsibility to declare the correct policy
3. Configure `SiderealProbe` resources to test all boundary-relevant flow
   paths specific to their deployment
4. Enable CNI observability API (e.g., Hubble for Cilium, or Calico flow
   logs) for between-probe boundary monitoring
