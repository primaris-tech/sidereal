---
title: Your First Probe
description: Create an RBAC probe and read the results
---

This walkthrough creates an RBAC probe, watches it execute, and reads the result. It takes about 2 minutes.

## Create a test namespace

```bash
kubectl create namespace sidereal-test-target
```

## Create the probe

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

This tells Sidereal: every 5 minutes, verify that the `sidereal-probe-rbac` ServiceAccount cannot perform unauthorized operations in the `sidereal-test-target` namespace. Record results but don't create incidents (observe mode).

## Watch for execution

The probe executes immediately on creation, then every 5 minutes:

```bash
# Watch for the probe Job
kubectl get jobs -n sidereal-system -l sidereal.cloud/probe-name=rbac-test --watch
```

## Read the result

Once the Job completes:

```bash
kubectl get siderealproberesults -n sidereal-system \
  -l sidereal.cloud/probe-name=rbac-test
```

```bash
kubectl describe siderealproberesult -n sidereal-system \
  -l sidereal.cloud/probe-name=rbac-test
```

You should see:

- **outcome**: `Pass` -- the RBAC deny path was enforced
- **controlEffectiveness**: `Effective`
- **integrityStatus**: `Verified` -- HMAC check passed

## Check the probe status

```bash
kubectl get siderealprobe rbac-test -n sidereal-system -o yaml
```

The `.status` section shows `lastExecutedAt`, `lastOutcome`, `lastControlEffectiveness`, and up to 10 `recentResults`.

## Next steps

- Try other probe types: [Probe Types](/concepts/probe-types/)
- Move from observe to enforce: [Execution Modes](/concepts/execution-modes/)
- Let Sidereal find probes for you: [Discovery](/getting-started/discovery/)
