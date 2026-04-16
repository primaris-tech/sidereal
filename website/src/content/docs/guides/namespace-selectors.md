---
title: Namespace Selectors
description: Using targetNamespaceSelector to cover multiple namespaces with one probe definition
---

By default, a `SiderealProbe` targets a single namespace via the `targetNamespace` field. For clusters with many namespaces that share the same security posture requirements, you can use `targetNamespaceSelector` instead. This lets one probe definition cover every namespace matching a label selector.

## How it works

The `targetNamespace` and `targetNamespaceSelector` fields are mutually exclusive. When you set `targetNamespaceSelector`, the controller lists all namespaces matching the label selector at scheduling time and creates a separate probe Job for each matching namespace.

```yaml
apiVersion: sidereal.cloud/v1alpha1
kind: SiderealProbe
metadata:
  name: rbac-boundary-check
  namespace: sidereal-system
spec:
  profile: rbac
  executionMode: observe
  intervalSeconds: 21600
  targetNamespaceSelector:
    matchLabels:
      environment: production
```

This probe runs an RBAC boundary check in every namespace labeled `environment: production`. If you later add a new namespace with that label, the probe automatically covers it on the next scheduling cycle.

## Label selector syntax

The `targetNamespaceSelector` field accepts a standard Kubernetes `LabelSelector`, which supports both `matchLabels` (exact key-value match) and `matchExpressions` (set-based operators: `In`, `NotIn`, `Exists`, `DoesNotExist`).

```yaml
targetNamespaceSelector:
  matchExpressions:
    - key: compliance-tier
      operator: In
      values:
        - high
        - moderate
    - key: sidereal.cloud/excluded
      operator: DoesNotExist
```

This selects namespaces where `compliance-tier` is either `high` or `moderate`, and the `sidereal.cloud/excluded` label is not present.

## ResourceQuota considerations

Each matching namespace generates a separate probe Job. If you have a selector that matches 20 namespaces and 5 probes using selectors, that could mean 100 concurrent Jobs. The `ResourceQuota` on the `sidereal-system` namespace caps concurrent probe Jobs (default 10), so the controller queues excess Jobs and schedules them as slots become available.

```yaml
resourceQuota:
  maxJobs: 10
  maxCPU: "4"
  maxMemory: 8Gi
```

Adjust these values based on your cluster size and the number of namespaces your selectors match.

## When to use each approach

Use **targetNamespace** when you need probes scoped to specific, individually named namespaces, or when different namespaces require different probe configurations (different intervals, execution modes, or control mappings).

Use **targetNamespaceSelector** when you have a consistent security policy across a class of namespaces and want new namespaces to be covered automatically. This is particularly useful for multi-tenant clusters where teams create namespaces dynamically.

## Results tracking

Each probe Job targets a single namespace, so the resulting `SiderealProbeResult` records are per-namespace. The `spec.probe.targetNamespace` field on each result reflects which namespace was actually probed, making it straightforward to filter results by namespace even when the probe definition uses a selector.
