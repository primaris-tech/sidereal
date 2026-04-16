---
title: Installation
description: Deploy Sidereal to your Kubernetes cluster
---

## Bootstrap script (kind)

For first-time evaluation and local development, start with the repository bootstrap script:

```bash
./hack/bootstrap-kind.sh
```

Run it from a local checkout of the [`primaris-tech/sidereal`](https://github.com/primaris-tech/sidereal) repository.

This script stands up a complete local Sidereal environment on KIND and verifies the stack end-to-end. It:

1. Checks for `kind`, `kubectl`, `helm`, `docker`, and `make` unless you pass `--skip-build`
2. Creates a KIND cluster from `hack/kind-config.yaml`
3. Installs Kyverno `3.3.4`
4. Builds Sidereal images with `make docker-build-all`
5. Loads the locally built images into KIND
6. Applies the Sidereal CRDs from `config/crd/bases/`
7. Installs the Helm chart with a KIND-compatible development profile
8. Verifies the controller is running and reports any `SiderealSystemAlert`
9. Creates a demo namespace and applies a first RBAC probe
10. Waits up to 90 seconds for the first `SiderealProbeResult`

### Assumptions the script makes

The script is opinionated. It assumes:

- You are running it from a checkout of the [`primaris-tech/sidereal`](https://github.com/primaris-tech/sidereal) repository
- Docker is available locally and can build/load images into KIND
- Pulling the Kyverno Helm chart from `https://kyverno.github.io/kyverno/` is acceptable
- Local development can run with `global.fips=false`
- Detection probes are disabled in this environment

The script deliberately configures Sidereal for a safe development path:

| Setting | Value | Why |
|---|---|---|
| `global.impactLevel` | `low` | Lower-friction cadence and retention defaults for dev |
| `global.executionMode` | `observe` | Records results without creating incidents |
| `global.fips` | `false` | Avoids requiring a local BoringCrypto/FIPS build |
| `global.requireAdmissionController` | `true` | Kyverno is installed and should enforce Sidereal's admission policies |
| `profile.admissionController` | `kyverno` | Matches the bootstrap-installed admission layer |
| `profile.signatureVerifier` | `kyverno` | Uses Kyverno for image verification policy |
| `profile.detectionBackend` | `none` | The detection probe image is skipped in dev |
| `profile.cniObservability` | `tcp-inference` | KIND does not provide Hubble or Calico APIs |
| `*.pullPolicy` | `Never` | Images are loaded directly into the KIND nodes |

The detection probe image is intentionally skipped during image loading. The Rust FIPS build path is heavier than a typical first-time local setup, so the script installs Sidereal with `profile.detectionBackend=none`.

### Useful flags

```bash
# Reuse images already built in Docker
./hack/bootstrap-kind.sh --skip-build

# Pick a different cluster name
./hack/bootstrap-kind.sh --cluster-name sidereal-test

# Tear everything down
./hack/bootstrap-kind.sh --teardown --cluster-name sidereal-dev
```

### What success looks like

On a healthy run, you should end with:

- A `kind-<cluster-name>` context selected in `kubectl`
- The `sidereal-controller-manager` deployment ready in `sidereal-system`
- No blocking `SiderealSystemAlert` objects
- A demo namespace named `sidereal-demo`
- A first RBAC probe named `rbac-getting-started`
- At least one `SiderealProbeResult` for that probe

Useful follow-up commands:

```bash
kubectl get siderealprobes -n sidereal-system
kubectl get siderealproberesults -n sidereal-system --watch
kubectl get siderealproberecommendations -n sidereal-system
kubectl get siderealsystemalerts -n sidereal-system
```

If you used the bootstrap script, continue to [Your First Probe](/getting-started/first-probe/).

## Local development (manual kind flow)

The bootstrap script is the fastest path, but the manual steps are useful if you want to understand or customize the environment.

KIND is suitable for development and evaluation only. In this setup, Sidereal runs with:

- Kyverno installed for admission enforcement
- `tcp-inference` for network policy verification
- No detection backend
- Local images loaded directly into the cluster
- `observe` mode and `low` impact defaults

### Prerequisites

Install:

- `kind`
- `kubectl`
- `helm`
- `docker`
- `make`

### Manual installation

```bash
# Create the cluster
kind create cluster --name sidereal-dev --config hack/kind-config.yaml --wait 60s
kubectl config use-context kind-sidereal-dev

# Install Kyverno
helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update
helm install kyverno kyverno/kyverno \
  --namespace kyverno \
  --create-namespace \
  --version 3.3.4 \
  --set admissionController.replicas=1 \
  --set backgroundController.enabled=false \
  --set cleanupController.enabled=false \
  --set reportsController.enabled=false \
  --wait \
  --timeout 5m
kubectl rollout status deployment/kyverno-admission-controller -n kyverno --timeout=120s

# Build images locally
make docker-build-all

# Load the images KIND will use
kind load docker-image ghcr.io/primaris-tech/sidereal-controller:latest --name sidereal-dev
kind load docker-image ghcr.io/primaris-tech/sidereal-probe-go:latest --name sidereal-dev
kind load docker-image ghcr.io/primaris-tech/sidereal-probe-bootstrap:latest --name sidereal-dev

# Install CRDs
kubectl apply -f config/crd/bases/

# Install Sidereal
helm install sidereal deploy/helm/sidereal/ \
  --namespace sidereal-system \
  --create-namespace \
  --set global.impactLevel=low \
  --set global.executionMode=observe \
  --set global.fips=false \
  --set global.requireAdmissionController=true \
  --set profile.admissionController=kyverno \
  --set profile.signatureVerifier=kyverno \
  --set profile.detectionBackend=none \
  --set profile.cniObservability=tcp-inference \
  --set controller.image.tag=latest \
  --set controller.image.pullPolicy=Never \
  --set probe.goImage.tag=latest \
  --set probe.goImage.pullPolicy=Never \
  --set probe.bootstrapImage.tag=latest \
  --set probe.bootstrapImage.pullPolicy=Never \
  --set probe.detectionImage.tag=latest \
  --wait \
  --timeout 3m
```

### What works on KIND

Not all probe surfaces require extra infrastructure. In the bootstrap/manual KIND setup:

| Probe type | Works on KIND | Requires |
|---|---|---|
| `rbac` | Yes | Nothing extra |
| `secret` | Yes | Nothing extra |
| `netpol` | Yes (with `tcp-inference`) | A `NetworkPolicy` in the target namespace |
| `admission` | Yes | Kyverno installed and healthy |
| `detection` | No | Falco or Tetragon |

RBAC is still the best first probe because it works on every cluster and avoids extra prerequisites.

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
