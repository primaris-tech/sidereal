---
title: Discovery
description: Let Sidereal find your security controls and recommend probes
---

Sidereal scans your cluster for existing security controls and generates probe recommendations. The ISSO's first interaction is reviewing and promoting recommendations, not authoring YAML from scratch.

## How discovery works

The discovery reconciler runs automatically on controller startup and every 6 hours (configurable by impact level). It scans for:

| Cluster Resource | Generated Probe Type |
|---|---|
| NetworkPolicy | `netpol` probes for each policy's deny/allow paths |
| RoleBinding / ClusterRoleBinding | `rbac` probes for permission boundary verification |
| ValidatingWebhookConfiguration | `admission` probes for policy enforcement validation |
| Secrets (by namespace) | `secret` probes for cross-namespace isolation |
| Falco rules / Tetragon TracingPolicy | `detection` probes for technique coverage |

## View recommendations

```bash
kubectl get siderealproberecommendations -n sidereal-system
```

Short name:

```bash
kubectl get sprec -n sidereal-system
```

Each recommendation includes:
- **confidence**: `high` (fully derivable), `medium` (review recommended), `low` (skeleton requiring completion)
- **rationale**: why this probe was generated
- **probeTemplate**: the complete SiderealProbe spec that would be created

## Review a recommendation

```bash
kubectl describe sprec <name> -n sidereal-system
```

## Promote a recommendation

Promoting creates a SiderealProbe from the recommendation's template. The probe starts in `dryRun` mode:

```bash
kubectl patch sprec <name> -n sidereal-system \
  --type merge --subresource status \
  -p '{"status":{"state":"promoted","promotedTo":"<probe-name>"}}'
```

## Dismiss a recommendation

```bash
kubectl patch sprec <name> -n sidereal-system \
  --type merge --subresource status \
  -p '{"status":{"state":"dismissed","dismissedBy":"isso@agency.gov","dismissedReason":"Not applicable to this environment"}}'
```

Dismissed recommendations are not re-generated for the same source resource unless the resource changes.

## Supersession

When a source resource changes (e.g., a NetworkPolicy is modified), the old recommendation is automatically marked `superseded` and a new one is created with the updated configuration.

## CLI discovery

For an offline preview without creating recommendations in the cluster:

```bash
# Preview what would be discovered
sidereal discover --dry-run

# Discover only NetworkPolicy probes
sidereal discover --type netpol --namespace production

# Output SiderealProbe YAML for direct kubectl apply
sidereal discover --output probes/
```

The CLI outputs SiderealProbe resources (not recommendations) for manual review and `kubectl apply`.
