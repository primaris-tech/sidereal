# Getting Started with Sidereal

This guide walks you through deploying Sidereal on a local kind cluster, running your first probe, and reading the results. By the end you will have a working Sidereal installation validating RBAC enforcement in a test namespace.

## What you need

| Requirement | Minimum Version | Notes |
|---|---|---|
| Kubernetes cluster | 1.28+ | kind, minikube, or a real cluster |
| Helm | 3.12+ | |
| kubectl | 1.28+ | |
| Kyverno **or** OPA/Gatekeeper | Kyverno 1.11+ / Gatekeeper 3.14+ | Admission controller for admission probes |
| Falco **or** Tetragon | Falco 0.37+ / Tetragon 1.0+ | Optional, only needed for detection probes |

Sidereal itself does not require Falco, Tetragon, or a specific CNI to function. Those backends are needed only for detection probes and CNI-verdict network policy verification. RBAC, Secret, and Admission probes work on any Kubernetes cluster.

## Environment assumptions

Sidereal assumes:

- **You have cluster-admin access** to install CRDs, create namespaces, and configure RBAC.
- **An HMAC root secret will be created** by the Helm chart in the `sidereal-system` namespace. This is the root of the HMAC integrity chain. In production, back this with a KMS.
- **Probe images are available.** On a local kind cluster you will need to load the images or have internet access to pull from GHCR.
- **The cluster has a working admission controller** if you want admission probes. If you only want RBAC or secret probes, this is not required (set `global.requireAdmissionController: false`).

## Step 1: Create a kind cluster

If you don't already have a cluster:

```bash
kind create cluster --name sidereal-test
```

## Step 2: Install Kyverno (optional, for admission probes)

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm install kyverno kyverno/kyverno \
  --namespace kyverno --create-namespace
```

## Step 3: Install Sidereal

From a local checkout (development):

```bash
# Install CRDs
kubectl apply -f config/crd/bases/

# Build images locally
make docker-build-all

# Load images into kind
kind load docker-image ghcr.io/primaris-tech/sidereal-controller:latest --name sidereal-test
kind load docker-image ghcr.io/primaris-tech/sidereal-probe-go:latest --name sidereal-test
kind load docker-image ghcr.io/primaris-tech/sidereal-probe-detection:latest --name sidereal-test
kind load docker-image ghcr.io/primaris-tech/sidereal-probe-bootstrap:latest --name sidereal-test

# Install the Helm chart (override image tags to match local builds)
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

From GHCR (released images):

```bash
helm install sidereal oci://ghcr.io/primaris-tech/charts/sidereal \
  --namespace sidereal-system \
  --create-namespace \
  --set global.impactLevel=low \
  --set global.executionMode=observe
```

## Step 4: Verify the installation

```bash
# Check the controller is running
kubectl get pods -n sidereal-system

# Check for bootstrap alerts (these indicate missing prerequisites)
kubectl get siderealsystemalerts -n sidereal-system

# Check CRDs are installed
kubectl get crd | grep sidereal
```

You should see the controller pod running and 9 Sidereal CRDs registered.

## Step 5: Create a test namespace

```bash
kubectl create namespace sidereal-test-target
```

## Step 6: Run your first probe

Create an RBAC probe that checks whether a probe ServiceAccount can perform operations it should not be able to in the test namespace:

```bash
kubectl apply -f - <<EOF
apiVersion: sidereal.cloud/v1alpha1
kind: SiderealProbe
metadata:
  name: rbac-test
  namespace: sidereal-system
spec:
  probeType: rbac
  targetNamespace: sidereal-test-target
  executionMode: observe
  intervalSeconds: 300
  controlMappings:
    nist-800-53:
      - AC-6(5)
EOF
```

This tells Sidereal: "Every 5 minutes, use the RBAC probe to verify that the `sidereal-probe-rbac` ServiceAccount cannot perform unauthorized operations in the `sidereal-test-target` namespace. Record the results but don't create incidents (observe mode)."

## Step 7: Watch for results

The probe will execute within a few seconds of creation (first run is immediate). Watch for the Job and then the result:

```bash
# Watch for the probe Job
kubectl get jobs -n sidereal-system -l sidereal.cloud/probe-name=rbac-test --watch

# Once the Job completes, check the result
kubectl get siderealproberesults -n sidereal-system -l sidereal.cloud/probe-name=rbac-test

# Get the full result details
kubectl describe siderealproberesult -n sidereal-system -l sidereal.cloud/probe-name=rbac-test
```

You should see a `SiderealProbeResult` with:
- `outcome: Pass` (the RBAC deny path was enforced)
- `controlEffectiveness: Effective`
- `integrityStatus: Verified` (HMAC check passed)

## Step 8: Check the probe status

```bash
kubectl get siderealprobe rbac-test -n sidereal-system -o yaml
```

The `.status` section shows `lastExecutedAt`, `lastOutcome`, `lastControlEffectiveness`, and `recentResults`.

## Step 9: Try discovery

Sidereal can scan your cluster for existing security controls and recommend probes:

```bash
kubectl get siderealproberecommendations -n sidereal-system
```

Or use the CLI:

```bash
sidereal discover --dry-run
```

## What each execution mode does

| Mode | Jobs Created | Results Recorded | Incidents Created | Use Case |
|---|---|---|---|---|
| `dryRun` | No | No | No | Validate probe configuration without touching the cluster |
| `observe` | Yes | Yes | No | Evaluate probe behavior, build confidence in results |
| `enforce` | Yes | Yes | Yes (on failure) | Full operation with incident pipeline and IR webhook |

Start with `observe`. Move to `enforce` only after you have validated that probe results are accurate for your environment.

## What each probe type tests

| Probe Type | What It Does | What It Needs |
|---|---|---|
| `rbac` | Attempts unauthorized API operations with the probe SA, verifies they are denied | Nothing beyond Kubernetes RBAC |
| `secret` | Attempts to read Secrets in the target namespace from a cross-namespace SA | Nothing beyond Kubernetes RBAC |
| `netpol` | Tests whether NetworkPolicy deny paths are enforced at the CNI layer | A CNI that enforces NetworkPolicy (most do) |
| `admission` | Submits a known-bad resource spec and verifies the admission controller rejects it | Kyverno or OPA/Gatekeeper |
| `detection` | Fires a synthetic syscall pattern and verifies the detection backend raised an alert | Falco or Tetragon, plus an AO authorization |
| `custom` | Runs an operator-provided container with the same security controls as built-in probes | A pre-registered ServiceAccount and a signed image |

## Impact level defaults

Setting `global.impactLevel` cascades these defaults:

| Setting | High | Moderate | Low |
|---|---|---|---|
| Default probe interval | 6 hours | 12 hours | 24 hours |
| Result retention | 365 days | 365 days | 180 days |
| Fail-closed on export failure | Yes | No | No |
| Discovery interval | 6 hours | 12 hours | 24 hours |

You can override any of these per-probe with `spec.intervalSeconds`.

## Troubleshooting

**Controller pod not starting:**
```bash
kubectl describe pod -n sidereal-system -l app.kubernetes.io/name=sidereal-controller
kubectl logs -n sidereal-system -l app.kubernetes.io/name=sidereal-controller
```

**Probe Job not being created:**
- Check that the probe's `executionMode` is not `dryRun`
- Check for unacknowledged SystemAlerts: `kubectl get siderealsystemalerts -n sidereal-system`
- Unacknowledged alerts block all probe scheduling

**HMAC verification failing:**
- The HMAC root secret must exist: `kubectl get secret sidereal-hmac-root -n sidereal-system`
- If it was deleted or rotated, existing in-flight probe results will fail verification

**Detection probes not running:**
- Detection probes require an active `SiderealAOAuthorization`. See `examples/ao-authorization.yaml`

## Next steps

- Browse the [examples/](../examples/) directory for sample probe configurations
- Read the [engineering specification](../sidereal-engineering-summary.md) for the full architecture
- See the [compliance documentation](../compliance/README.md) for ATO-ready artifacts
