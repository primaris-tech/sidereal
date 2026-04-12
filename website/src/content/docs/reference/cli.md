---
title: CLI Reference
description: The sidereal command-line tool for discovery and report generation
---

The `sidereal` CLI provides two primary subcommands: `discover` for scanning a cluster and generating probe configurations, and `report` for on-demand report generation. The CLI connects to your cluster using the standard kubeconfig resolution order.

## Global options

```
sidereal <command> [flags]

Commands:
  discover    Discover security controls and generate probe configurations
  report      Generate compliance reports
  version     Print version information
  help        Print this help message
```

## sidereal discover

Scans the cluster for existing security resources and generates `SiderealProbe` manifests that would validate those controls. This is the primary onboarding path: run discovery, review the output, and apply the probes you want.

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--type` | string | `""` (all) | Probe type to discover: `rbac`, `netpol`, `admission`, `secret`, `detection`. Empty runs all discoverers. |
| `--namespace` | string | `""` (all) | Limit discovery to a specific namespace. |
| `--output` | string | `""` (stdout) | Output directory or file for generated YAML. If a directory, each probe is written as a separate file. |
| `--dry-run` | bool | `false` | Show what would be discovered without writing files. |
| `--format` | string | `yaml` | Output format: `yaml` or `json`. |
| `--kubeconfig` | string | `""` | Path to kubeconfig file. Defaults to `$KUBECONFIG` or `~/.kube/config`. |

### Examples

Discover all probe types and print to stdout:

```bash
sidereal discover
```

Discover only NetworkPolicy probes in a specific namespace:

```bash
sidereal discover --type netpol --namespace production
```

Preview what would be discovered without generating files:

```bash
sidereal discover --dry-run
```

Write each discovered probe to a separate file in a directory:

```bash
sidereal discover --output ./generated-probes/
```

Generate JSON instead of YAML:

```bash
sidereal discover --format json --output probes.json
```

### Discovery engine

The CLI runs the same discovery engine used by the controller's recommendation reconciler. Five discoverers scan for:

- **RBAC**: ClusterRoleBindings, RoleBindings, and ServiceAccounts with elevated permissions.
- **NetworkPolicy**: existing NetworkPolicy resources and their target namespaces.
- **Admission**: Kyverno ClusterPolicies or OPA ConstraintTemplates.
- **Secret**: Secrets in non-system namespaces (generates Secret Access probes).
- **Detection**: Falco rules or Tetragon TracingPolicies (generates detection probes with ATT&CK technique mappings).

Each discovered resource produces a probe recommendation with a confidence level (high, medium, low) indicating how fully the probe was derivable from the source resource. The CLI converts recommendations directly to `SiderealProbe` manifests, while the controller creates `SiderealProbeRecommendation` CRs for the review-and-promote workflow.

## sidereal report

Generates compliance reports on-demand from probe result data in the cluster.

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--type` | string | required | Report type: `continuous-monitoring`, `poam`, `coverage-matrix`, `evidence-package`, `executive-summary`. |
| `--format` | string | `markdown` | Output format: `oscal-json`, `pdf`, `markdown`, `csv`, `zip`. |
| `--output` | string | `""` (stdout) | Output file path. Required for binary formats (`pdf`, `zip`). |
| `--frameworks` | string | `""` (all enabled) | Comma-separated list of frameworks to include. |
| `--from` | string | `""` | Start of reporting period (RFC 3339). Defaults to 30 days ago. |
| `--to` | string | `""` | End of reporting period (RFC 3339). Defaults to now. |
| `--kubeconfig` | string | `""` | Path to kubeconfig file. |

### Examples

Generate a continuous monitoring summary in Markdown:

```bash
sidereal report --type continuous-monitoring
```

Generate a POA&M as CSV scoped to specific frameworks:

```bash
sidereal report --type poam --format csv --frameworks nist-800-53,cmmc --output poam.csv
```

Generate an evidence package for a specific time period:

```bash
sidereal report --type evidence-package --format zip \
  --from 2026-01-01T00:00:00Z --to 2026-03-31T23:59:59Z \
  --output q1-evidence.zip
```

Generate an executive summary in PDF:

```bash
sidereal report --type executive-summary --format pdf --output exec-summary.pdf
```
