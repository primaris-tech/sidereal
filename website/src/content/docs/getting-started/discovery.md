---
title: Discovery
description: Let Sidereal find your security controls and recommend probes
---

Sidereal scans your cluster for existing security controls and generates probe recommendations. The intended workflow is review-and-promote, not author-from-scratch.

## What discovery finds

The discovery engine runs on controller startup and on a schedule (every 6, 12, or 24 hours depending on your impact level). It scans five resource types:

| Cluster Resource | Probe Type Generated | Requires |
|---|---|---|
| RoleBinding / ClusterRoleBinding | `rbac` | Nothing extra |
| Secrets (by namespace) | `secret` | Nothing extra |
| NetworkPolicy | `netpol` | A NetworkPolicy in the target namespace |
| ValidatingWebhookConfiguration | `admission` | Kyverno or OPA/Gatekeeper |
| Falco rules / Tetragon TracingPolicy | `detection` | Falco or Tetragon |

On a stock KIND cluster with no additional infrastructure, you will see `rbac` and `secret` recommendations. That is expected — KIND ships without an admission controller or detection backend, so those discovery paths produce nothing.

## View recommendations

```bash
kubectl get siderealproberecommendations -n sidereal-system
```

Short name:

```bash
kubectl get sprec -n sidereal-system
```

Each recommendation shows:
- **confidence**: `high` (fully derivable from cluster state), `medium` (review recommended), `low` (skeleton that needs completion)
- **rationale**: why this probe was suggested
- **probeTemplate**: the complete `SiderealProbe` spec that would be created on promotion

## Inspect a recommendation

```bash
kubectl describe sprec <name> -n sidereal-system
```

The `probeTemplate` field shows exactly what probe would be created. Review it before promoting to confirm the target namespace and control mappings are appropriate.

## Promote a recommendation

Promoting creates a `SiderealProbe` from the recommendation template. The probe starts in `dryRun` mode so it records what it would do without creating incidents.

```bash
kubectl patch sprec <name> -n sidereal-system \
  --type merge --subresource status \
  -p '{"status":{"state":"promoted","promotedTo":"<probe-name>"}}'
```

Once promoted, the probe runs on its configured interval. Check results the same way as [Your First Probe](/getting-started/first-probe/).

## Dismiss a recommendation

```bash
kubectl patch sprec <name> -n sidereal-system \
  --type merge --subresource status \
  -p '{"status":{"state":"dismissed","dismissedBy":"isso@agency.gov","dismissedReason":"Not applicable to this environment"}}'
```

Dismissed recommendations are not regenerated for the same source resource unless that resource changes.

## Supersession

When a source resource changes (for example, a NetworkPolicy is updated), the existing recommendation is automatically marked `superseded` and a new one is created reflecting the updated configuration.

## CLI discovery

For an offline preview that does not write recommendations to the cluster:

```bash
# Preview what would be discovered
sidereal discover --dry-run

# Discover only RBAC probes for a specific namespace
sidereal discover --type rbac --namespace production

# Write SiderealProbe YAML files for manual review
sidereal discover --output probes/
```

The CLI outputs `SiderealProbe` resources (not recommendations) for direct `kubectl apply` without going through the recommendation lifecycle.
