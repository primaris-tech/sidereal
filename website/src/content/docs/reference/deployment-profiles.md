---
title: Deployment Profiles
description: The six pre-built deployment profiles and custom profile support
---

Sidereal uses a profile abstraction to decouple probe logic from specific infrastructure tools. A deployment profile selects which admission controller, image signature verifier, detection backend, and CNI observability mode the operator integrates with. Probes reference abstract capabilities; the profile determines which concrete backends fulfill them.

## Profile dimensions

Each profile configures four dimensions:

| Dimension | Options |
|-----------|---------|
| **Admission controller** | Kyverno, OPA/Gatekeeper |
| **Signature verifier** | Kyverno, Sigstore Policy Controller |
| **Detection backend** | Falco, Tetragon, none |
| **CNI observability** | Hubble (Cilium), Calico, TCP inference |

## Pre-built profiles

### kyverno-cilium-falco

The default profile for clusters running Cilium and Falco with Kyverno for admission control. Uses Hubble for CNI-layer network flow verification and Kyverno for image signature verification.

### opa-calico-tetragon

For clusters using OPA/Gatekeeper, Calico networking, and Tetragon for runtime detection. Uses the Calico REST API for network policy verification.

### kyverno-eks

Tailored for Amazon EKS. Uses Kyverno for admission and signature verification, Falco for detection, and TCP inference for network policy verification (since EKS VPC CNI does not expose Hubble or Calico observability APIs).

### opa-aks

Tailored for Azure AKS with Azure Policy (OPA-based). Uses Tetragon for detection and TCP inference for network policy verification.

### kyverno-gke

Tailored for Google GKE. Uses Kyverno for admission control, Falco for detection, and TCP inference for network policy verification.

### opa-rke2

For Rancher RKE2 deployments with OPA/Gatekeeper. Uses Falco for detection and Calico for CNI observability (RKE2 ships with Calico by default).

## Configuring a profile

Set the four profile dimensions in your Helm values:

```yaml
profile:
  admissionController: kyverno
  signatureVerifier: kyverno
  detectionBackend: falco
  cniObservability: hubble
```

Or use a named profile shorthand that sets all four values:

```yaml
profile:
  name: kyverno-cilium-falco
```

## Custom profiles

If none of the pre-built profiles match your infrastructure, set the four dimensions individually. Any valid combination works. For example, a cluster running Kyverno with Calico and no detection backend:

```yaml
profile:
  admissionController: kyverno
  signatureVerifier: kyverno
  detectionBackend: none
  cniObservability: calico
```

Setting `detectionBackend: none` disables detection probes entirely. The remaining probe surfaces (RBAC, NetworkPolicy, Admission, Secret Access) operate normally.

## NetworkPolicy verification modes

The `cniObservability` dimension determines how NetworkPolicy probes verify enforcement:

- **hubble** -- queries the Hubble gRPC API for CNI-level flow verdicts. Highest fidelity: Hubble reports whether a packet was dropped by the CNI.
- **calico** -- queries the Calico REST API for policy evaluation logs.
- **tcp-inference** -- works with any CNI. The probe attempts a TCP connection that should be blocked by a NetworkPolicy and checks whether it succeeds or fails. No CNI-specific API required, but provides less detail than CNI-native backends.
