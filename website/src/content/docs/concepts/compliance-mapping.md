---
title: Compliance Mapping
description: Multi-framework control tagging via SiderealFramework CRDs
---

Every SiderealProbeResult is tagged with controls from all loaded compliance frameworks. This happens automatically at result creation time using the crosswalk resolver, which is populated by `SiderealFramework` resources.

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

`SiderealFramework` resources define mappings from `(profile, nist_800_53_control)` to each framework's control IDs. The `FrameworkReconciler` loads these into the in-memory crosswalk resolver when resources are created or updated. The result reconciler reads the resolver after each probe execution to populate the `controlMappings` field on every ProbeResult.

For example, when an RBAC probe validates control `AC-6(5)`, the crosswalk resolver maps it to:
- CMMC: `AC.L2-3.1.5`
- NIST 800-171: `3.1.5`
- Kubernetes STIG: `V-242417`

All mappings appear in the ProbeResult's `controlMappings` field, making the result queryable by any framework.

## Configuration

The seven built-in frameworks are installed by the Helm chart by default. To disable them and manage frameworks through your own GitOps workflow:

```yaml
crosswalk:
  installDefaults: false
```

## Extending

Add a custom framework by applying a `SiderealFramework` resource. The controller loads it immediately without a restart:

```yaml
apiVersion: sidereal.cloud/v1alpha1
kind: SiderealFramework
metadata:
  name: agency-custom
spec:
  frameworkID: agency-custom
  frameworkName: "Agency-Specific Controls"
  version: "1.0.0"
  mappings:
    - profile: rbac
      nistControl: AC-6
      controlIDs: ["AGENCY-AC-001"]
    - profile: netpol
      nistControl: SC-7
      controlIDs: ["AGENCY-SC-001"]
```

No code changes or rebuilds required. Deleting the resource removes the framework from the resolver via a finalizer.
