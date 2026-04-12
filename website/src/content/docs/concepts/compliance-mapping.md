---
title: Compliance Mapping
description: Multi-framework control tagging with crosswalk data files
---

Every SiderealProbeResult is tagged with controls from all active compliance frameworks. This happens automatically at result creation time using versioned crosswalk data files.

## Supported frameworks

| Framework | ID | Description |
|---|---|---|
| NIST SP 800-53 Rev 5 | `nist-800-53` | Federal baseline (High/Moderate/Low) |
| CMMC Level 2 | `cmmc` | Cybersecurity Maturity Model Certification |
| CJIS Security Policy | `cjis` | FBI Criminal Justice Information Services |
| IRS Publication 1075 | `irs-1075` | Federal Tax Information protection |
| HIPAA Security Rule | `hipaa` | Health information privacy |
| NIST SP 800-171 Rev 2 | `nist-800-171` | Controlled Unclassified Information |
| Kubernetes STIG | `kubernetes-stig` | DISA Kubernetes Security Technical Implementation Guide |

## How it works

Crosswalk files are JSON data files that map `(probe_type, nist_800_53_control)` to each framework's control IDs. The result reconciler uses these mappings to populate the `controlMappings` field on every ProbeResult.

For example, when an RBAC probe validates control `AC-6(5)`, the crosswalk resolver maps it to:
- CMMC: `AC.L2-3.1.5`
- NIST 800-171: `3.1.5`
- Kubernetes STIG: `V-242417`

All mappings appear in the ProbeResult's `controlMappings` field, making the result queryable by any framework.

## Configuration

Enable frameworks in your Helm values:

```yaml
global:
  controlFrameworks:
    - nist-800-53
    - cmmc
    - cjis
```

## Extending

Agencies can add custom frameworks by creating a crosswalk JSON file:

```json
{
  "framework_id": "agency-custom",
  "framework_name": "Agency-Specific Controls",
  "crosswalk_version": "1.0.0",
  "mappings": [
    {"probe_type": "rbac", "nist_control": "AC-6", "control_ids": ["AGENCY-AC-001"]},
    {"probe_type": "netpol", "nist_control": "SC-7", "control_ids": ["AGENCY-SC-001"]}
  ]
}
```

Place it in the crosswalk ConfigMap and it will be loaded at controller startup. No code changes or rebuilds required.
