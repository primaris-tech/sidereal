---
title: Installation
description: Deploy Sidereal to your Kubernetes cluster
---

## Prerequisites

### Admission controller (required)

Sidereal requires Kyverno or OPA/Gatekeeper to be installed and running before you deploy. This is not optional for a production deployment.

The admission controller does two things for Sidereal:

1. **Enforces Sidereal's own security model.** Admission policies restrict the controller to creating Jobs only with pre-approved probe ServiceAccounts, verify cosign signatures on all probe images at Pod admission, and deny any UPDATE or DELETE on `SiderealProbeResult` records. Without this layer, those guarantees do not exist.
2. **Serves as a probe target.** The `admission` probe type verifies that your admission webhooks are actively enforcing policy, not just installed and idle.

Install one before proceeding:

- [Kyverno installation guide](https://kyverno.io/docs/installation/)
- [OPA/Gatekeeper installation guide](https://open-policy-agent.github.io/gatekeeper/website/docs/install/)

Your choice of admission controller determines which deployment profile to select. See [Deployment Profiles](/reference/deployment-profiles/) for the full list.

### CNI (required for network policy probes)

The `netpol` probe type requires either Cilium (Hubble API) or Calico for full CNI-level verdict reporting. Without them, Sidereal falls back to `tcp-inference` mode, which works with any CNI but has lower confidence. The `rbac`, `secret`, and `admission` probe types have no CNI requirement.

### Detection backend (required for detection probes)

The `detection` probe type requires Falco or Tetragon. Without a detection backend, `detection` probes cannot run. All other probe types are unaffected.

---

## Quick install

For a cluster with an admission controller and CNI already in place:

```bash
helm install sidereal oci://ghcr.io/primaris-tech/charts/sidereal \
  --namespace sidereal-system \
  --create-namespace \
  --set global.impactLevel=moderate \
  --set global.executionMode=dryRun \
  --set profile.name=kyverno-cilium-falco
```

See [Deployment Profiles](/reference/deployment-profiles/) for the full list of pre-built profiles and how to pick one.

## Local development (kind)

KIND is a minimal cluster and is suitable for development and evaluation only. It ships with kindnet (no Hubble/Calico APIs), no admission controller, and no detection backend.

When `global.requireAdmissionController=false`, the admission enforcement policies that protect Sidereal's own security model are not in effect. Probe image signature verification, Job ServiceAccount restrictions, and result immutability enforcement all depend on the admission layer. Do not run with this flag in production.

Use a custom profile that matches what KIND actually has:

```bash
# Create a kind cluster
kind create cluster --name sidereal-test

# Install CRDs
kubectl apply -f config/crd/bases/

# Build images locally
make docker-build-all

# Load images into kind
kind load docker-image ghcr.io/primaris-tech/sidereal-controller:latest --name sidereal-test
kind load docker-image ghcr.io/primaris-tech/sidereal-probe-rbac:latest --name sidereal-test
kind load docker-image ghcr.io/primaris-tech/sidereal-probe-secret:latest --name sidereal-test
kind load docker-image ghcr.io/primaris-tech/sidereal-probe-admission:latest --name sidereal-test
kind load docker-image ghcr.io/primaris-tech/sidereal-probe-netpol:latest --name sidereal-test
kind load docker-image ghcr.io/primaris-tech/sidereal-probe-bootstrap:latest --name sidereal-test

# Install via Helm with a KIND-compatible profile
helm install sidereal deploy/helm/sidereal/ \
  --namespace sidereal-system \
  --create-namespace \
  --set global.impactLevel=low \
  --set global.executionMode=observe \
  --set global.fips=false \
  --set global.requireAdmissionController=false \
  --set profile.detectionBackend=none \
  --set profile.cniObservability=tcp-inference \
  --set controller.image.tag=latest \
  --set probe.goImage.tag=latest \
  --set probe.detectionImage.tag=latest \
  --set probe.bootstrapImage.tag=latest
```

The key flags for KIND:

| Flag | Value | Why |
|---|---|---|
| `profile.detectionBackend` | `none` | No Falco or Tetragon installed |
| `profile.cniObservability` | `tcp-inference` | kindnet has no observability API |
| `global.requireAdmissionController` | `false` | No Kyverno or OPA installed |

### What works on KIND

Not all probe surfaces require additional infrastructure. On a stock KIND cluster:

| Probe type | Works on KIND | Requires |
|---|---|---|
| `rbac` | Yes | Nothing extra |
| `secret` | Yes | Nothing extra |
| `netpol` | Yes (with tcp-inference) | A NetworkPolicy must exist in the target namespace |
| `admission` | No | Kyverno or OPA/Gatekeeper |
| `detection` | No | Falco or Tetragon |

RBAC and Secret probes are a good starting point for validating the operator end-to-end.

## Verify the installation

```bash
# Check the controller is running
kubectl get pods -n sidereal-system

# Confirm no system alerts fired during bootstrap
kubectl get siderealsystemalerts -n sidereal-system

# Confirm CRDs are installed
kubectl get crd | grep sidereal
```

You should see the controller pod running, an empty system alert list, and 9 Sidereal CRDs registered.

## Configuration

### Impact level

Setting `global.impactLevel` cascades operational defaults:

| Setting | High | Moderate | Low |
|---|---|---|---|
| Default probe interval | 6 hours | 12 hours | 24 hours |
| Result retention | 365 days | 365 days | 180 days |
| Fail-closed on export failure | Yes | No | No |
| Discovery interval | 6 hours | 12 hours | 24 hours |

### Deployment profiles

Select a profile matching your cluster's stack:

| Profile | Admission | Detection | CNI | Platform |
|---|---|---|---|---|
| `kyverno-cilium-falco` | Kyverno | Falco | Hubble | Cilium clusters |
| `opa-calico-tetragon` | OPA | Tetragon | Calico | Calico clusters |
| `kyverno-eks` | Kyverno | Falco | tcp-inference | Amazon EKS |
| `opa-aks` | OPA | Falco | tcp-inference | Azure AKS |
| `kyverno-gke` | Kyverno | Falco | tcp-inference | Google GKE |
| `opa-rke2` | OPA | Tetragon | tcp-inference | RKE2/k3s |

```bash
helm install sidereal oci://ghcr.io/primaris-tech/charts/sidereal \
  --set profile.name=kyverno-cilium-falco
```
