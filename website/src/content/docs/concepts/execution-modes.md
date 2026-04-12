---
title: Execution Modes
description: Graduated adoption from dryRun to observe to enforce
---

Sidereal supports three execution modes that provide a safe adoption path. Every probe starts in `dryRun` by default.

## dryRun

The controller validates the probe configuration and logs what it would do, but does not create Jobs or execute any probe logic against the cluster.

Use `dryRun` to verify your probe definitions are correct before executing them.

## observe

The controller creates probe Jobs that execute live against the cluster. Results are recorded as SiderealProbeResult CRDs. No incidents are created regardless of outcome.

Use `observe` to evaluate probe behavior and build confidence in the results. This is the evaluation period where you confirm the probes are producing accurate outcomes for your environment before enabling the incident pipeline.

## enforce

Full operation. Probe Jobs execute, results are recorded, and if `controlEffectiveness` is `Ineffective` or `Compromised`, a SiderealIncident is created and delivered to the configured IR webhook.

Use `enforce` only after validating probe accuracy in `observe` mode.

## Transitioning between modes

Update the probe's `executionMode` field:

```bash
# dryRun -> observe
kubectl patch siderealprobe <name> -n sidereal-system \
  --type merge -p '{"spec":{"executionMode":"observe"}}'

# observe -> enforce
kubectl patch siderealprobe <name> -n sidereal-system \
  --type merge -p '{"spec":{"executionMode":"enforce"}}'
```

Moving to `enforce` requires the `sidereal-live-executor` role.

## Incident severity

In `enforce` mode, incident severity is derived from control effectiveness:

| Control Effectiveness | Incident Severity |
|---|---|
| Compromised | Critical |
| Ineffective | High |
| Degraded | Medium |
