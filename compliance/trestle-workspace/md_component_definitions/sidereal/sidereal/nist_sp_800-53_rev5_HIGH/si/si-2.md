---
x-trestle-comp-def-rules:
  sidereal:
    - name: dependabot-grype-trivy-30-day-critical-patch-sla
      description: Sidereal uses Dependabot for automated dependency updates and Grype/Trivy for SBOM-based vulnerability scanning in CI, with a 30-day SLA for patching critical CVEs
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: si-02
status: implemented
---

# SI-2 — Flaw Remediation

## Control Statement

Identify, report, and correct system flaws. Test software and firmware
updates related to flaw remediation for effectiveness and potential side
effects before installation. Incorporate flaw remediation into the
configuration management process.

## Sidereal Implementation

Flaw remediation in Sidereal is automated from discovery through patch
delivery. The pipeline identifies vulnerabilities, enforces SLA compliance,
and gates deployment of remediated versions behind the same CI testing
and supply chain verification as any other release.

### Flaw Identification — Continuous SBOM Scanning

Grype and Trivy scan the CycloneDX SBOM for each container image on every:
- Pull request (blocks merge if critical findings present)
- Push to the main branch (nightly scan for new disclosures)
- Release build (results archived as a release artifact)

Scans run against the NVD, OSV, and GitHub Advisory databases. Each scan
produces a structured report archived with the build, providing a point-in-time
vulnerability record for every deployed version.

**Severity thresholds and gates:**

| Severity | CVSS Range | CI Gate | SLA |
|---|---|---|---|
| Critical | 9.0–10.0 | Build fails immediately | 30 days from disclosure |
| High | 7.0–8.9 | Build fails unless documented exception | 60 days from disclosure |
| Medium | 4.0–6.9 | Warning in build output | 90 days from disclosure |
| Low | 0.1–3.9 | Recorded in scan report | Best effort |

A Critical finding stops the pipeline before image signing. No artifact is
produced, no image is published, no deployment is possible until the
finding is resolved or a documented exception is approved.

### Flaw Identification — Dependabot Automated Monitoring

Dependabot monitors all dependency manifests in the repository:
- Go modules (`go.mod`, `go.sum`)
- Rust crates (`Cargo.toml`, `Cargo.lock`)
- Base image references (distroless/scratch layer digests)
- GitHub Actions workflow tool pins

When a new version is available, Dependabot opens a pull request
automatically. The PR triggers the full CI pipeline — unit tests, SBOM
generation, Grype/Trivy scan, FIPS compilation verification, and cosign
signing dry-run. A dependency update that introduces a new CVE fails the
CI pipeline before merge.

Base image updates receive the same treatment. Container image digest pins
in the Helm chart are updated by the pipeline when a new base image passes
scanning, ensuring base image vulnerabilities are addressed on the same SLA
as dependency vulnerabilities.

### Remediation SLA Enforcement

Automated issue escalation enforces the CVE remediation SLA:
- Day 0: Critical CVE disclosed; Dependabot PR opened; CI build fails
- Day 7: Automated reminder if PR is not merged
- Day 21: Escalation notification to designated security contact
- Day 30: SLA breach recorded in the SIEM; SiderealSystemAlert created

SLA compliance is tracked per CVE from disclosure date (NVD published date)
to Helm chart release date. Dependabot PR merge timestamps and release
publication timestamps form the evidence record.

### Testing Before Installation

Every flaw remediation update flows through the complete CI pipeline before
reaching a deployable artifact:
1. Dependabot opens PR for the updated dependency version
2. CI runs unit tests, integration tests, SBOM scan, FIPS verification
3. If all checks pass, the PR is eligible for merge
4. Merge triggers the release pipeline: image build, scan, sign, SBOM attest
5. Helm chart digest pins are updated to reference the new signed image

No update bypasses this sequence. There is no expedited path that skips
testing in favor of faster patch deployment — the pipeline is the only
path to a deployable artifact.

### Integration with Configuration Management

Flaw remediation is integrated with the CM process (CM-3):
- Dependency updates are code changes requiring PR review
- New Helm chart versions increment the semantic version
- Deployments require Helm upgrade through the approved change pathway
- The `sidereal-security-override` role gates deployment of patch releases

This ensures that a security patch is not a special-case exception to CM —
it flows through exactly the same change control process as any other update.

### Enhancement: SI-2(2) — Automated Flaw Remediation Status

Flaw remediation status is machine-readable at every stage:
- SBOM scan reports in CI provide per-package vulnerability status
- Dependabot PR status reflects open/merged remediation state
- Helm chart changelog documents which CVEs are addressed per release
- The SIEM receives scan report data as part of the release artifact archive

### Enhancement: SI-2(3) — Time to Remediate / Benchmarks

The 30/60/90-day SLAs represent the benchmarks for corrective actions.
Automated issue escalation at day 7, 21, and 30 enforces these benchmarks
without requiring manual tracking. SLA breach events in the SIEM provide
evidence for assessors that benchmarks were either met or documented as
exceptions with justification.

## Evidence Produced

- Grype/Trivy SBOM vulnerability scan reports archived per release (linked
  in release notes); one report per component image
- Dependabot pull request history with merge timestamps (remediation
  timeline record for each CVE)
- CI pipeline build failure records for any build blocked by a critical CVE
- `SiderealSystemAlert` CRs for SLA breach events, exported to SIEM
- Helm chart changelog mapping each release to addressed CVE identifiers

## Customer Responsibility

The deploying agency must:
1. Update their deployed Sidereal version within the 30-day critical CVE
   SLA by running `helm upgrade` with the patched chart version
2. Monitor the Sidereal release channel (GitHub releases or OCI artifact
   registry) for security advisories and patch releases
3. Document any deviation from the 30-day SLA in their POA&M with an
   accepted risk justification approved by the AO
4. Treat Sidereal patch releases as change-controlled deployments subject
   to their organizational change management process (CM-3)
