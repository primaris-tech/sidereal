---
title: Compliance Frameworks
description: The seven supported compliance frameworks and crosswalk mapping details
---

Sidereal maps probe results to compliance controls across seven frameworks through a crosswalk data system. Each probe execution produces a `SiderealProbeResult` tagged with the relevant controls from every enabled framework, so a single probe run generates evidence for multiple compliance programs simultaneously.

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

## Enabling frameworks

Select which frameworks to load in your Helm values:

```yaml
global:
  controlFrameworks:
    - nist-800-53
    - cmmc
    - cjis
```

The controller loads crosswalk JSON files for each enabled framework from `/etc/sidereal/crosswalks/` at startup. Only enabled frameworks are loaded, keeping memory usage proportional to what you need.

## How crosswalks work

Crosswalk data is stored as JSON files shipped in the Helm chart. Each file maps a `(probe_type, nist_800_53_control)` pair to a list of control IDs in the target framework. NIST 800-53 serves as the canonical pivot: every probe maps to NIST 800-53 controls first, then the crosswalk resolver expands those to the enabled target frameworks.

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

## Extending with custom frameworks

Agencies can add custom frameworks without rebuilding the operator. Place a new crosswalk JSON file in the crosswalks directory following the standard schema:

```json
{
  "framework_id": "agency-specific",
  "crosswalk_version": "1.0.0",
  "mappings": [
    {
      "probe_type": "rbac",
      "nist_control": "AC-6",
      "control_ids": ["AGENCY-AC-001", "AGENCY-AC-002"]
    }
  ]
}
```

Add the framework ID to `global.controlFrameworks` in your Helm values, and the resolver picks it up on the next controller restart. No code changes required.

## Crosswalk versioning

Each crosswalk file includes a `crosswalk_version` field. The version used for a given probe result is recorded in `result.crosswalkVersion` on the `SiderealProbeResult`, providing traceability for audit purposes. When crosswalk data is updated, new results reference the new version while historical results retain their original version.
