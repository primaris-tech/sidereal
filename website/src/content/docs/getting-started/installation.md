---
title: Installation
description: Deploy Sidereal to your Kubernetes cluster
---

## Quick install

```bash
helm install sidereal oci://ghcr.io/primaris-tech/charts/sidereal \
  --namespace sidereal-system \
  --create-namespace \
  --set global.impactLevel=moderate \
  --set global.executionMode=dryRun
```

## Local development (kind)

If you are working from a local checkout of the repository:

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
kind load docker-image ghcr.io/primaris-tech/sidereal-bootstrap:latest --name sidereal-test

# Install via Helm (override image tags to match local builds)
helm install sidereal deploy/helm/sidereal/ \
  --namespace sidereal-system \
  --create-namespace \
  --set global.impactLevel=low \
  --set global.executionMode=observe \
  --set global.fips=false \
  --set global.requireAdmissionController=false \
  --set controller.image.tag=latest \
  --set probe.goImage.tag=latest \
  --set probe.detectionImage.tag=latest \
  --set probe.bootstrapImage.tag=latest
```

## Verify the installation

```bash
# Check the controller is running
kubectl get pods -n sidereal-system

# Check for bootstrap alerts
kubectl get siderealsystemalerts -n sidereal-system

# Check CRDs are installed
kubectl get crd | grep sidereal
```

You should see the controller pod running and 7 Sidereal CRDs registered.

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
