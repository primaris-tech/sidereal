---
title: Report Generation
description: Generating compliance reports via the CLI and SiderealReport CRD
---

Sidereal generates five report types that cover the documents ISSOs and AOs need for continuous monitoring, POA&M tracking, and ATO evidence. Reports can be generated on-demand through the CLI or on a schedule using the SiderealReport CRD.

## Report types

**Continuous Monitoring Summary** (continuous-monitoring) -- Aggregates probe results over a reporting period, showing control effectiveness trends, pass/fail rates per probe surface, and framework compliance posture. This is the report an ISSO submits monthly to demonstrate ongoing authorization.

**Plan of Action and Milestones** (poam) -- Lists controls with Ineffective or Degraded effectiveness, grouped by framework, with timestamps and remediation tracking. Maps directly to the OMB A-130 POA&M format.

**Coverage Matrix** (coverage-matrix) -- Shows which controls across which frameworks are covered by active probes, which have no probe coverage, and the last-known effectiveness for each. Useful for identifying gaps before an assessment.

**Evidence Package** (evidence-package) -- Bundles probe results, HMAC verification status, export receipts, and control mappings into a single archive suitable for submission to an assessor. Output format is typically zip.

**Executive Summary** (executive-summary) -- A high-level overview of system security posture: total controls validated, percentage effective, incidents created, and framework-specific pass rates. Intended for AO briefings.

## Output formats

Reports can be generated in several formats: oscal-json (NIST OSCAL JSON), pdf, markdown, csv, and zip (compressed archive, used primarily for evidence packages).

## CLI usage

Generate a report on-demand:

```bash
sidereal report --type continuous-monitoring --format markdown --output report.md
sidereal report --type poam --format csv --output poam.csv
sidereal report --type evidence-package --format zip --output evidence.zip
```

You can scope reports to specific frameworks with --frameworks:

```bash
sidereal report --type coverage-matrix --frameworks nist-800-53,cmmc --format csv
```

## Scheduled reports with SiderealReport CRD

For automated generation, create a SiderealReport resource:

```yaml
apiVersion: sidereal.cloud/v1alpha1
kind: SiderealReport
metadata:
  name: monthly-conmon
  namespace: sidereal-system
spec:
  type: continuous-monitoring
  format: oscal-json
  schedule: "0 0 1 * *"
  frameworks:
    - nist-800-53
    - cmmc
  outputSecret: monthly-conmon-report
  retention: 12
  timeRange:
    from: "2026-03-01T00:00:00Z"
    to: "2026-04-01T00:00:00Z"
```

Key fields:

- **schedule** -- a cron expression. The controller generates a new report at each interval.
- **outputSecret** -- the Kubernetes Secret where the generated report is stored. The controller creates or updates this Secret with the report content.
- **retention** -- how many historical reports to keep (default 5). Older reports are pruned automatically.
- **timeRange** -- optional. If omitted, defaults to the period since the last report (or 30 days for the first run).

The status tracks lastGeneratedAt and lastGenerationStatus (Success or Failed).
