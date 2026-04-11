---
x-trestle-comp-def-rules:
  gauntlet:
    - name: controller-probe-separation-security-isolation
      description: Gauntlet separates security functions between the Go controller (policy enforcement, result verification) and Rust probe runners (isolated execution), preventing a compromised probe from affecting the enforcement plane
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: sc-03
status: partial
---

# SC-3 — Security Function Isolation

## Control Statement

The system isolates security functions from non-security functions and maintains a security domain that protects the integrity of the hardware, software, and firmware that implement the security functions. Isolation must prevent unauthorized access to and tampering with security functions.

## Gauntlet Implementation

TODO: Expand with full implementation narrative.

Key implementation points:
- Gauntlet architecturally separates the security enforcement plane (Go controller) from the probe execution plane (Rust probe runner Jobs); the controller manages scheduling, policy, result verification, and SIEM export, while probe runners execute in isolated ephemeral Jobs with no persistent state, no inter-probe communication channel, and no ability to modify controller state directly — all results flow through HMAC-signed ConfigMaps that the controller validates before acting on them
- Probe runner Jobs are isolated at the OS level: non-root UID, read-only root filesystem, all Linux capabilities dropped, and a custom Localhost seccomp profile for detection probes; this ensures that even a fully compromised probe runner cannot modify the controller's configuration, access other probes' credentials, or write to the SIEM directly
- The gauntlet-system namespace ResourceQuota and NetworkPolicy provide an outer isolation boundary; the NetworkPolicy permits only the specific egress paths required by each component type, so a compromised probe runner that attempts to contact the SIEM or the Kubernetes API directly (rather than through the controller) is blocked at the CNI layer

## Evidence Produced

- Kubernetes Pod security context manifests (in the Helm chart) documenting the isolation controls applied to each component
- GauntletProbeResult CRs flow only through the controller's verified ingestion path, with HMAC verification failures logged as GauntletIncident CRs

## Customer Responsibility

The agency must not modify the Pod security context settings for Gauntlet components (e.g., must not add `privileged: true` or remove capability drops) and must ensure that no other workload in the gauntlet-system namespace is granted elevated privileges that could bridge the isolation boundary.
