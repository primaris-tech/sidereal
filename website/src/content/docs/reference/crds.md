---
title: CRD Reference
description: All eight Sidereal custom resource definitions in the sidereal.cloud/v1alpha1 API group
---

Sidereal defines eight custom resource definitions in the `sidereal.cloud/v1alpha1` API group. Together they model the full lifecycle of security control validation: configuration, execution, results, incidents, alerts, authorization, discovery, and reporting.

## SiderealProbe

**Short name**: `sp`

Defines a security control validation probe. Each probe targets a specific surface (RBAC, NetworkPolicy, Admission, Secret Access, Detection, or Custom), runs on a configurable interval, and maps to MITRE ATT&CK techniques and compliance framework controls.

Key spec fields: `probeType`, `targetNamespace` or `targetNamespaceSelector`, `executionMode` (`dryRun`/`observe`/`enforce`), `intervalSeconds` (300-86400), `controlMappings`, `mitreAttackId`, `aoAuthorizationRef` (required for detection), `customProbe` (for custom probe type).

Status tracks `lastExecutedAt`, `lastOutcome`, `lastControlEffectiveness`, `consecutiveFailures`, and `recentResults`.

## SiderealProbeResult

**Short name**: `spr`

An append-only audit record created for each probe execution. Results are HMAC-signed by the probe runner and verified by the controller. Admission policy denies UPDATE and DELETE operations to guarantee immutability.

Each result contains: `probe` reference (execution ID, type, target namespace), `result` (raw `outcome`, derived `controlEffectiveness`, `controlMappings`, `integrityStatus`), `execution` metadata (timestamp, duration, Job name), and `audit` tracking (`exportStatus`).

**Raw outcomes**: Pass, Fail, Detected, Undetected, Blocked, Rejected, Accepted, NotApplicable, BackendUnreachable, NotEnforced, Indeterminate, TamperedResult.

**Derived effectiveness**: Effective, Ineffective, Degraded, Compromised.

TTL retention varies by FIPS 199 impact level: 365 days for High/Moderate, 180 days for Low.

## SiderealIncident

**Short name**: `si`

A control failure record created only when `executionMode` is `enforce` and `controlEffectiveness` is `Ineffective` or `Compromised`. Incidents are delivered to an IR webhook endpoint for integration with your incident response process.

Severity levels: Critical, High, Medium, Low. Remediation lifecycle: Open, InProgress, Remediated, Accepted. Webhook delivery status: Pending, Delivered, Failed.

## SiderealSystemAlert

**Short name**: `ssa`

A degraded state indicator raised when the system detects an operational problem that requires human attention. Probes in the affected surface are suspended until an individual principal acknowledges the alert.

Alert reasons: AdmissionPolicyMissing, SIEMExportDegraded, AuditWriteFailure, BaselineConfigurationDrift, TamperedResult, AOAuthorizationExpired, BackendUnreachable, UnexpectedNetworkFlow.

Acknowledgment requires an individual Kubernetes user identity, not a shared ServiceAccount.

## SiderealAOAuthorization

**Short name**: `sao`

A time-bounded, technique-scoped, namespace-scoped authorization from an Authorizing Official for detection probe execution. Detection probes will not execute without an active authorization.

Key spec fields: `aoName` (individual AO name), `authorizedTechniques` (MITRE ATT&CK IDs), `authorizedNamespaces` (explicit list, no wildcards), `validFrom`, `expiresAt`, `justification`.

The controller computes `status.active` from the time bounds. Expired authorizations trigger a `SiderealSystemAlert` with reason `AOAuthorizationExpired`.

## SiderealProbeRecommendation

**Short name**: `sprec`

A discovery-generated probe suggestion. The discovery engine scans the cluster for existing security resources (NetworkPolicies, RBAC bindings, admission policies, Secrets, detection rules) and generates recommendations for probes that would validate those controls.

Lifecycle: `pending` (awaiting review), `promoted` (accepted and converted to a SiderealProbe), `dismissed` (rejected by the ISSO), `superseded` (replaced by a newer recommendation when the source resource changes).

Confidence levels: high, medium, low -- indicating how fully the probe was derivable from the source resource.

## SiderealReport

**Short name**: `sr`

An optional scheduled report generation configuration. Supports five report types: `continuous-monitoring`, `poam`, `coverage-matrix`, `evidence-package`, `executive-summary`.

Output formats: `oscal-json`, `pdf`, `markdown`, `csv`, `zip`. Reports are stored in a Kubernetes Secret specified by `outputSecret`. The `retention` field controls how many historical reports to keep (default 5). Scheduling uses cron expressions.

Status tracks `lastGeneratedAt` and `lastGenerationStatus` (Success or Failed).
