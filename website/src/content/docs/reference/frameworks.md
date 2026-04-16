---
title: Compliance Frameworks
description: The seven built-in compliance frameworks and how to add custom ones
---

Sidereal maps probe results to compliance controls across compliance frameworks through the `SiderealFramework` CRD. Each probe execution produces a `SiderealProbeResult` tagged with the relevant controls from every loaded framework, so a single probe run generates evidence for multiple compliance programs simultaneously.

## Supported frameworks

| Framework | Crosswalk ID | Description |
|-----------|-------------|-------------|
| NIST 800-53 | `nist-800-53` | The primary control catalog. All other frameworks crosswalk through NIST 800-53 as the canonical reference. Covers High, Moderate, and Low baselines. |
| CMMC | `cmmc` | Cybersecurity Maturity Model Certification. Maps NIST 800-53 controls to CMMC practices across maturity levels. |
| CJIS | `cjis` | Criminal Justice Information Services Security Policy. Maps controls relevant to law enforcement data handling. |
| IRS 1075 | `irs-1075` | Safeguards for Federal Tax Information (FTI). Maps controls required for systems processing tax data. |
| HIPAA | `hipaa` | Health Insurance Portability and Accountability Act security controls. Maps technical safeguards for protected health information. |
| NIST 800-171 | `nist-800-171` | Protecting Controlled Unclassified Information (CUI) in nonfederal systems. Maps the 110 security requirements to NIST 800-53 controls. |
| Kubernetes STIG | `kubernetes-stig` | DISA Security Technical Implementation Guide for Kubernetes. Maps STIG rules to the controls that Sidereal probes validate. |

## Built-in frameworks

The seven built-in frameworks are installed as `SiderealFramework` resources by the Helm chart (`crosswalk.installDefaults: true` by default). They are active as soon as the controller reconciles them — no restart required.

To opt out and manage frameworks entirely through your own GitOps workflow:

```yaml
crosswalk:
  installDefaults: false
```

## How crosswalks work

Each `SiderealFramework` resource defines a list of mappings. Each mapping associates a `(profile, nistControl)` pair with one or more framework-specific control IDs. NIST 800-53 serves as the canonical pivot: every probe profile maps to NIST 800-53 controls first, then the crosswalk resolver expands those to all loaded frameworks.

For example, an RBAC probe that maps to NIST 800-53 AC-6 (Least Privilege) will also map to CMMC AC.L2-3.1.5, CJIS 5.5.2, and other framework-specific controls through the crosswalk data.

The result reconciler calls the crosswalk resolver after each probe execution and populates the `controlMappings` field on the `SiderealProbeResult`:

```yaml
result:
  controlMappings:
    nist-800-53:
      - AC-6
    cmmc:
      - AC.L2-3.1.5
    cjis:
      - "5.5.2"
```

## Adding custom frameworks

Agencies can add custom frameworks without rebuilding the operator or restarting the controller. Apply a `SiderealFramework` resource:

```yaml
apiVersion: sidereal.cloud/v1alpha1
kind: SiderealFramework
metadata:
  name: agency-specific
spec:
  frameworkID: agency-specific
  frameworkName: "Agency-Specific Control Overlay"
  version: "1.0.0"
  mappings:
    - profile: rbac
      nistControl: AC-6
      controlIDs: ["AGENCY-AC-001", "AGENCY-AC-002"]
    - profile: netpol
      nistControl: SC-7
      controlIDs: ["AGENCY-SC-001"]
```

The controller reconciles the resource and loads it into the crosswalk resolver immediately. No Helm values change, no controller restart. Removing the resource evicts the framework from the resolver via a finalizer.

Note that `metadata.name` must match `spec.frameworkID`. The controller sets `Loaded=False` and surfaces an error if they differ.

## Crosswalk versioning

Each `SiderealFramework` includes a `spec.version` field. The version active at execution time is recorded in `result.crosswalkVersion` on the `SiderealProbeResult`, providing traceability for audit purposes. When crosswalk data is updated, new results reference the new version while historical results retain their original version.
