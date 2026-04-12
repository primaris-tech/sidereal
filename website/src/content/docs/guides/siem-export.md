---
title: SIEM Export
description: Configuring export targets for Splunk, Elasticsearch, and S3 with format selection
---

Sidereal exports every `SiderealProbeResult` to one or more SIEM backends so that audit records live in your existing security monitoring infrastructure. You can run multiple export targets simultaneously, each with its own format.

## Supported backends

| Backend         | Protocol       | Configuration key |
|-----------------|----------------|-------------------|
| Splunk          | HEC (HTTPS)    | `splunk`          |
| Elasticsearch   | REST (HTTPS)   | `elasticsearch`   |
| S3              | AWS S3 API     | `s3`              |

S3 exports use SSE-KMS encryption and Object Lock in COMPLIANCE mode to satisfy append-only audit requirements.

## Supported formats

| Format   | Description                                   |
|----------|-----------------------------------------------|
| `json`   | Native Sidereal JSON (default)                |
| `cef`    | Common Event Format (ArcSight and others)     |
| `leef`   | Log Event Extended Format (QRadar)            |
| `syslog` | RFC 5424 structured syslog                    |
| `ocsf`   | Open Cybersecurity Schema Framework           |

## Configuration

Export targets are configured in Helm values under `export.targets`. Each target specifies a backend, format, endpoint, and a Kubernetes Secret reference for credentials.

```yaml
export:
  targets:
    - backend: splunk
      format: json
      endpoint: https://splunk.example.com:8088
      secretRef: splunk-hec-token

    - backend: elasticsearch
      format: ocsf
      endpoint: https://es.example.com:9200
      secretRef: elasticsearch-credentials

    - backend: s3
      format: ocsf
      endpoint: https://s3.us-gov-west-1.amazonaws.com
      bucket: audit-evidence-bucket
      region: us-gov-west-1
      secretRef: s3-credentials
```

The `secretRef` names a Secret in the `sidereal-system` namespace. For Splunk, this Secret holds the HEC token. For Elasticsearch, it holds username and password or an API key. For S3, it holds AWS credentials (or you can use IRSA/pod identity).

## Export tracking

Each `SiderealProbeResult` has an `audit.exportStatus` field that tracks delivery state: `Pending`, `Exported`, or `Failed`. The result reconciler updates this field after each export attempt.

## Fail-closed behavior

At FIPS 199 High impact level, Sidereal defaults to fail-closed on export failure. If SIEM export fails consecutively, probe scheduling halts and a `SiderealSystemAlert` is raised with reason `SIEMExportDegraded`. This ensures audit records are not generated without a functioning export pipeline.

Control this with:

```yaml
audit:
  failClosedOnExportFailure: true  # default at high impact level
```

At Moderate and Low impact levels, this defaults to false. Probes continue executing even if export is degraded, though the system alert is still raised.
