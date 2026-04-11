# Kubernetes STIG Crosswalk Analysis

## Overview

This document analyzes the DISA Kubernetes STIG (V2R4, ~91 rules) against Sidereal's probe surfaces to identify where active operational validation adds value beyond static configuration scanning.

## Coverage Summary

| Category | Total Rules | Sidereal-Mapped | Config-Only |
|---|---|---|---|
| RBAC Enforcement | 8 | 4 | 4 |
| NetworkPolicy / PPS Enforcement | 6 | 6 | 0 |
| Admission Control | 5 | 3 | 2 |
| Secret Access | 2 | 1 | 1 |
| Detection / Audit | 9 | 1 | 8 |
| TLS / Crypto | 22 | 0 | 22 |
| File Permissions / Ownership | 20 | 0 | 20 |
| Node Hardening | 4 | 0 | 4 |
| Supply Chain / Image Currency | 3 | 0 | 3 |
| Other (flags, ports, binds) | 12 | 0 | 12 |
| **Total** | **~91** | **15** | **~76** |

## Probe Surface Mapping

### RBAC (4 rules)

| V-Number | Severity | Title |
|---|---|---|
| V-242381 | CAT I | Unique service account credentials per workload |
| V-242383 | CAT I | User resources in dedicated namespaces only |
| V-242435 | CAT I | Non-privileged users cannot execute privileged functions |
| V-242417 | CAT II | User/management functionality separation |

All four are CAT I or CAT II and require active enumeration or testing to validate. The STIG check procedures themselves say things like "verify no user-managed resources exist in default namespace" and "verify that unauthorized access is denied." These are behavioral checks by definition.

### NetworkPolicy (6 rules)

| V-Number | Severity | Title |
|---|---|---|
| V-242410 | CAT II | API Server PPS enforcement |
| V-242411 | CAT II | Scheduler PPS enforcement |
| V-242412 | CAT II | Controller Manager PPS enforcement |
| V-242413 | CAT II | etcd PPS enforcement |
| V-242414 | CAT II | Non-privileged host ports for user pods |
| V-242395 | CAT II | Kubernetes dashboard not enabled |

The Ports, Protocols, and Services (PPS) rules are a natural fit. The PPSM CAL (Category Assurance List) requires that only approved ports are accessible. Sidereal's NetworkPolicy probes can actively test whether traffic on unapproved ports is blocked at the CNI enforcement layer, which is exactly what DISA assessors want to see.

### Admission Control (3 rules)

| V-Number | Severity | Title |
|---|---|---|
| V-242436 | CAT I | ValidatingAdmissionWebhook enabled |
| V-242437 | CAT I | Pod Security Standards enforced |
| V-254800 | CAT I | Pod Security Admission controller configured |

These are the highest-value STIG mappings. All three are CAT I. The distinction between "admission controller is configured" and "admission controller rejects a non-compliant pod" is the entire point of Sidereal. V-242437 and V-254800 map directly to the admission probe's existing behavior of submitting test specs with privileged containers, hostPath mounts, and capability escalations.

### Secret Access (1 rule)

| V-Number | Severity | Title |
|---|---|---|
| V-242415 | CAT I | Secrets not stored as environment variables |

CAT I, and inherently a continuous check. New deployments can introduce secrets-as-env-vars violations at any time. A point-in-time scan misses violations introduced after the scan ran.

### Detection / Audit (1 rule)

| V-Number | Severity | Title |
|---|---|---|
| V-242403 | CAT II | API Server generates audit records at RequestResponse level |

The config dimension of this rule (is the audit policy file set?) is well-covered by kube-bench. The operational dimension (does the audit pipeline actually capture events?) is what Sidereal's detection probe validates by firing a synthetic action and confirming the alert/audit record was generated.

## Gap Analysis

### Potential New Probe Surfaces

Two clusters of STIG rules suggest probe surfaces Sidereal does not currently cover:

**1. Certificate Validity Probing**
V-242441 (CAT I): "Endpoints must use approved organizational certificate and key pair." Currently config-only in the STIG, but operationally testable. A probe could connect to cluster endpoints and validate that the presented certificate chains to an approved CA, is not expired, and uses approved key lengths. This overlaps with the custom probe use case for "certificate expiration" already mentioned in the README.

**2. Image Currency / Supply Chain**
V-242442 and V-242443 require that outdated components are removed and current patches are applied. Sidereal's discovery engine could generate `SiderealProbeRecommendation` entries when it detects pods running images older than a configurable threshold. This is lighter than a full probe surface but still provides continuous validation.

### Rules Intentionally Not Mapped

~76 rules are pure configuration checks (kubelet flags, file permissions, TLS minimum versions, audit log paths). These are well-served by existing tools:

- **kube-bench**: CIS Kubernetes Benchmark, which overlaps heavily with the STIG
- **OpenSCAP / Compliance Operator**: SCAP-based STIG scanning
- **InSpec / Cinc Auditor**: STIG InSpec profiles for Kubernetes

Sidereal should not duplicate this work. The crosswalk file documents these rules in the `config_only_rules` section so that ISSOs understand the boundary and can pair Sidereal with a config scanner for full STIG coverage.

## Recommendations

1. **Add `kubernetes-stig` to `global.controlFrameworks`** in Helm values and the engineering spec's supported frameworks table. Framework ID: `kubernetes-stig`. Control ID format: `V-XXXXXX`.

2. **Ship the crosswalk file** (`kubernetes-stig.json`) alongside existing framework crosswalks in the Helm chart.

3. **Update the engineering spec** to list 7 supported frameworks (add Kubernetes STIG to the existing 6).

4. **Consider a certificate validity probe surface** as a future addition, motivated by V-242441 and the existing custom probe mention in the README.

5. **Add a note to the compliance README** clarifying that full STIG coverage requires pairing Sidereal (operational validation) with a configuration scanner (static checks).

## Framework Table (Updated)

| Framework ID | Framework | Example Control IDs |
|---|---|---|
| `nist-800-53` | NIST SP 800-53 Rev 5 | `AC-3`, `SC-7`, `AU-9` |
| `cmmc` | Cybersecurity Maturity Model Certification (v2) | `AC.L2-3.1.1`, `SC.L2-3.13.1` |
| `cjis` | Criminal Justice Information Services Security Policy | `5.4.1.1`, `5.10.1.2` |
| `irs-1075` | IRS Publication 1075 (Tax Information Security) | `9.3.1.3`, `9.3.16.7` |
| `hipaa` | HIPAA Security Rule (45 CFR 164) | `164.312(a)(1)`, `164.312(e)(1)` |
| `nist-800-171` | NIST SP 800-171 Rev 3 (CUI Protection) | `3.1.1`, `3.13.1` |
| `kubernetes-stig` | DISA Kubernetes STIG | `V-242435`, `V-242437` |
