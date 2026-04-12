---
title: Helm Values Reference
description: Key configuration groups in the Sidereal Helm chart
---

The Sidereal Helm chart is the primary deployment mechanism. All operational behavior is configurable through `values.yaml`, with a JSON schema (`values.schema.json`) enforcing validation constraints.

## global

Top-level settings that cascade defaults across the deployment.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `global.impactLevel` | `high\|moderate\|low` | `high` | FIPS 199 impact level. Cascades cadence, retention, and fail-closed defaults. |
| `global.executionMode` | `dryRun\|observe\|enforce` | `dryRun` | Default execution mode for all probes. |
| `global.fips` | bool | `true` | Require FIPS 140-2 validated cryptography (BoringCrypto). |
| `global.requireAdmissionController` | bool | `true` | Require a supported admission controller. |
| `global.controlFrameworks` | list | `["nist-800-53"]` | Compliance frameworks to load crosswalk files for. |

Impact level defaults:

- **high**: 6-hour probe cadence, 365-day retention, fail-closed on export failure
- **moderate**: 12-hour cadence, 365-day retention, no fail-closed
- **low**: 24-hour cadence, 180-day retention, no fail-closed

## profile

Selects backend integrations. Sidereal references abstract capabilities, not specific tools. Six pre-built profiles ship with the chart.

| Key | Options | Default |
|-----|---------|---------|
| `profile.admissionController` | `kyverno`, `opa` | `kyverno` |
| `profile.signatureVerifier` | `kyverno`, `policy-controller` | `kyverno` |
| `profile.detectionBackend` | `falco`, `tetragon`, `none` | `falco` |
| `profile.cniObservability` | `hubble`, `calico`, `tcp-inference` | `tcp-inference` |

## controller

Controller Manager deployment settings.

| Key | Default | Description |
|-----|---------|-------------|
| `controller.image.repository` | `ghcr.io/primaris-tech/sidereal-controller` | Controller image. |
| `controller.image.tag` | `""` (appVersion) | Image tag. |
| `controller.replicas` | `1` | Replica count. |
| `controller.resources.requests.cpu` | `100m` | CPU request. |
| `controller.resources.requests.memory` | `128Mi` | Memory request. |
| `controller.resources.limits.cpu` | `500m` | CPU limit. |
| `controller.resources.limits.memory` | `512Mi` | Memory limit. |

## probe

Probe runner configuration.

| Key | Default | Description |
|-----|---------|-------------|
| `probe.intervalSeconds` | `21600` | Default interval between executions (overridden per-probe). Schema enforces 300-86400. |
| `probe.goImage.repository` | `ghcr.io/primaris-tech/sidereal-probe-go` | Go probe runner image. |
| `probe.detectionImage.repository` | `ghcr.io/primaris-tech/sidereal-probe-detection` | Rust detection probe image. |
| `probe.bootstrapImage.repository` | `ghcr.io/primaris-tech/sidereal-probe-bootstrap` | Bootstrap verification image. |

## audit

Audit record retention and fail-closed behavior.

| Key | Default | Description |
|-----|---------|-------------|
| `audit.retentionDays` | `365` | Minimum retention for probe results. |
| `audit.failClosedOnExportFailure` | `true` | Halt probe scheduling if SIEM export fails consecutively. |

## export

SIEM export target configuration. Supports multiple simultaneous targets.

```yaml
export:
  targets:
    - backend: splunk|elasticsearch|s3
      format: json|cef|leef|syslog|ocsf
      endpoint: https://...
      secretRef: credential-secret-name
      bucket: bucket-name        # S3 only
      region: us-east-1          # S3 only
```

## detection

Detection backend endpoints, used when `profile.detectionBackend` is set.

| Key | Default |
|-----|---------|
| `detection.falco.endpoint` | `falco-grpc.falco:50051` |
| `detection.tetragon.endpoint` | `tetragon.kube-system:54321` |

## cni

CNI observability endpoints, used when `profile.cniObservability` is `hubble` or `calico`.

| Key | Default |
|-----|---------|
| `cni.hubble.endpoint` | `hubble-relay.kube-system:4245` |
| `cni.calico.endpoint` | `https://calico-api.calico-system:5443` |

## tls

| Key | Default | Description |
|-----|---------|-------------|
| `tls.required` | `true` | Require TLS for all backend connections. Schema enforces this must be `true`. |

## customProbes

Register ServiceAccounts for custom probe types.

```yaml
customProbes:
  serviceAccounts:
    - name: my-custom-probe
      namespace: sidereal-system
```

## resourceQuota

Caps concurrent probe Jobs in the `sidereal-system` namespace.

| Key | Default | Description |
|-----|---------|-------------|
| `resourceQuota.maxJobs` | `10` | Maximum concurrent probe Jobs. |
| `resourceQuota.maxCPU` | `"4"` | Total CPU limit for probe Jobs. |
| `resourceQuota.maxMemory` | `8Gi` | Total memory limit for probe Jobs. |
