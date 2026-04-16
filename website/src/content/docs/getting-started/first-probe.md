---
title: Your First Probe
description: Create an RBAC probe and read the results
---

This walkthrough creates an RBAC probe, watches it execute, and reads the result. If you just completed the [Installation](/getting-started/installation/) step, pick up here.

The RBAC probe is the right starting point: it works on every cluster, including KIND, with no additional infrastructure.

## Verify your installation is healthy

Before creating a probe, confirm the controller is running and nothing fired during bootstrap:

```bash
kubectl get pods -n sidereal-system
kubectl get siderealsystemalerts -n sidereal-system
```

You should see the controller pod in `Running` state and an empty alert list. If you see alerts, check `kubectl describe siderealsystemalert <name> -n sidereal-system` before continuing.

## What the RBAC probe does

The RBAC probe verifies that a ServiceAccount with minimal permissions cannot perform operations it should not be able to. Sidereal uses its own `sidereal-probe-rbac` ServiceAccount as the test principal and attempts a set of privilege-escalating operations against the target namespace. A passing result means the deny paths are enforced — the RBAC boundary held.

This maps to NIST 800-53 AC-6(5) (Privileged Accounts) and equivalent controls in CMMC and other frameworks.

## Create a target namespace

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
  profile: rbac
  targetNamespace: sidereal-test-target
  executionMode: observe
  intervalSeconds: 300
  controlMappings:
    nist-800-53:
      - AC-6(5)
EOF
```

`observe` mode records results but does not create incidents. That is the right mode for an initial validation.

## Watch execution

The probe runs immediately on creation. Watch for the Job:

```bash
kubectl get jobs -n sidereal-system -l sidereal.cloud/probe-name=rbac-test --watch
```

You should see a Job appear and reach `1/1 COMPLETIONS` within about 30 seconds. `CTRL-C` when it completes.

## Read the result

```bash
kubectl get siderealproberesults -n sidereal-system \
  -l sidereal.cloud/probe-name=rbac-test
```

Then inspect the full record:

```bash
kubectl describe siderealproberesult -n sidereal-system \
  $(kubectl get siderealproberesults -n sidereal-system \
    -l sidereal.cloud/probe-name=rbac-test \
    -o jsonpath='{.items[0].metadata.name}')
```

A healthy first result looks like this:

```
Name:         sidereal-result-8700ac70
Namespace:    sidereal-system
Labels:       sidereal.cloud/control-effectiveness=Effective
              sidereal.cloud/outcome=Pass
              sidereal.cloud/probe-id=8700ac70-f99c-4b43-952d-fd302bccf7c0
              sidereal.cloud/probe-name=rbac-test
              sidereal.cloud/probe-profile=rbac
              sidereal.cloud/target-namespace=sidereal-test-target
API Version:  sidereal.cloud/v1alpha1
Kind:         SiderealProbeResult
Spec:
  Audit:
    Export Status:  Pending
  Execution:
    Duration Ms:  686
    Job Name:     sidereal-probe-8700ac70
    Timestamp:    2026-04-13T22:25:18.989275093Z
  Probe:
    Id:                8700ac70-f99c-4b43-952d-fd302bccf7c0
    Profile:           rbac
    Target Namespace:  sidereal-test-target
  Result:
    Control Effectiveness:  Effective
    Control Mappings:
      nist-800-53:
        AC-6(5)
    Detail:            All 6 RBAC checks passed for namespace sidereal-test-target
    Integrity Status:  Verified
    Nist Controls:
      AC-6(5)
    Outcome:  Pass
```

**What each field means:**

| Field | Value | Meaning |
|---|---|---|
| `Outcome` | `Pass` | All 6 RBAC checks passed: privilege escalations were denied, and the probe SA has the access it needs |
| `Control Effectiveness` | `Effective` | The control is operationally working, not just configured |
| `Integrity Status` | `Verified` | The result's HMAC signature is valid and has not been tampered with |
| `Detail` | `All 6 RBAC checks passed...` | Human-readable summary; on a failure this lists exactly which checks failed and why |
| `Export Status` | `Pending` | Audit export to a SIEM backend; `Pending` is expected when no export target is configured |

`controlEffectiveness` is the ISSO-facing abstraction. `Effective` means you have evidence, collected from a live cluster, that this control is functioning.

## How result integrity works

`Integrity Status: Verified` is not a label Sidereal sets on success — it is the output of an active cryptographic check that happens every time the controller reads a result.

The chain works like this:

1. Before the probe Job is created, the controller derives a per-execution HMAC key using HKDF-SHA256 from a KMS-encrypted root secret. The probe ID is bound into the derivation, so each execution gets a unique key.
2. That key is written to a short-lived Secret in `sidereal-system` and mounted read-only into the probe container. Nothing else has access to it.
3. The probe signs its result with HMAC-SHA256 using that key and writes the signature alongside the result data.
4. The controller — a separate identity from the probe — re-derives the same key independently and verifies the signature before recording the `SiderealProbeResult`.

If the signature does not match, the controller records `Integrity Status: TamperedResult`, raises a `SiderealSystemAlert`, and suspends that probe surface until an operator acknowledges the alert. A result with a valid `Verified` status cannot have been modified after the probe wrote it, because no one outside that single execution has the key that produced the signature.

Results are also append-only by admission policy: any attempt to UPDATE or DELETE a `SiderealProbeResult` is rejected by the cluster's admission controller. The historical record cannot be quietly revised.

## Check the probe status

```bash
kubectl get siderealprobe rbac-test -n sidereal-system -o yaml
```

The `.status` section shows `lastExecutedAt`, `lastOutcome`, `lastControlEffectiveness`, and the 10 most recent results. After the probe runs a few times you can track the history here without listing individual result records.

## Next steps

- Run a secret access probe: same steps, change `profile: rbac` to `profile: secret`
- Move from observe to enforce: [Execution Modes](/concepts/execution-modes/)
- Let Sidereal find probes automatically: [Discovery](/getting-started/discovery/)
