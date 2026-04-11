---
x-trestle-comp-def-rules:
  gauntlet:
    - name: sbom-published-per-release
      description: A CycloneDX SBOM is generated and published as a cosign-attested OCI artifact for every Gauntlet release, covering all Go and Rust components and their transitive dependencies
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: cm-08
status: implemented
---

# CM-8 — System Component Inventory

## Control Statement

Develop, document, and maintain an inventory of system components that
accurately reflects the current system, includes all components within the
system boundary, is at the level of granularity required for tracking and
reporting, and is reviewed and updated at defined frequencies and as part
of installations and removals.

## Gauntlet Implementation

Gauntlet's component inventory is a machine-generated, cryptographically
attested artifact produced automatically on every release. The SBOM is not
a manually maintained spreadsheet — it is a structured document derived
directly from the build process and bound to the specific image digest it
describes.

### SBOM Generation

The Gauntlet CI pipeline generates a CycloneDX SBOM for every release using:
- `syft` — scans container image layers and produces a component list for
  each image (base image, OS packages, language runtime packages)
- `cargo cyclonedx` — generates a Rust crate dependency tree with exact
  versions and checksums for probe runner components
- `go mod` analysis — captures all Go module dependencies with their
  checksums for controller components

The SBOM covers all Gauntlet component images:
1. Controller Manager (Go)
2. RBAC probe runner (Rust)
3. NetworkPolicy probe runner (Rust)
4. Admission Control probe runner (Rust)
5. Secret Access probe runner (Rust)
6. Detection Coverage probe runner (Rust)

For each component, the SBOM records:
- Package name and exact version
- Package type (Go module, Rust crate, OS package, base layer)
- Package checksum (SHA-256)
- License identifier
- Known vulnerability status (from Grype/Trivy scan at generation time)

### Cosign Attestation — Binding SBOM to Image Digest

The SBOM for each image is attested to the image's SHA-256 digest using
`cosign attest --type cyclonedx`. The attestation is stored as an OCI
artifact in the same registry repository as the image.

This means:
- The SBOM is cryptographically bound to the exact binary it describes
- The SBOM cannot be swapped out without invalidating the cosign signature
- The SBOM is queryable for any deployed image via:
  `cosign verify-attestation --type cyclonedx <image-digest>`
- An agency's assessor can independently verify the inventory of any
  deployed Gauntlet version without trusting a separately maintained
  document

### Continuous Vulnerability Scanning

Grype and Trivy scan the generated SBOMs in CI on every push, pull request,
and release:
- **Push/PR**: Scan runs as a blocking CI check; critical/high vulnerabilities
  require a documented exception or immediate fix before merge
- **Release**: Scan output is archived as a release artifact; the SBOM and
  scan results are published together

Dependabot monitors all Go module and Rust crate dependencies and opens
pull requests automatically when new versions are available, ensuring the
component inventory is kept current between releases.

### Enhancement: CM-8(1) — Updates During Installations and Removals

Every `helm upgrade` that changes component versions produces a new SBOM
for the affected images as part of the CI release pipeline. The SBOM is
not updated manually — it is regenerated from the new image digest
automatically. Helm release history (CM-2) links each inventory state to a
specific deployment event.

### Enhancement: CM-8(2) — Automated Maintenance

SBOM generation, vulnerability scanning, dependency monitoring, and
attestation are all automated pipeline steps. No manual inventory update
is required. The inventory is current by construction: a deployed image
has an attested SBOM; the attested SBOM is the inventory.

### Enhancement: CM-8(3) — Automated Unauthorized Component Detection

The `gauntlet-image-signature-required` admission enforcement policy (CM-14) blocks
admission of any container image in `gauntlet-system` that does not have
a valid cosign signature from the Gauntlet release key. This policy
functions as an automated unauthorized component detector: any image not
produced by the Gauntlet build pipeline is rejected before it can run.

Combined with the SBOM attestation requirement (configurable in the admission
enforcement policy to require a valid SBOM attestation in addition to a signature),
this ensures that only inventoried, known components execute in the system.

## Evidence Produced

- CycloneDX SBOM OCI attestations for each component image, verifiable via
  `cosign verify-attestation --type cyclonedx <image-digest>`
- Grype/Trivy vulnerability scan reports archived as release artifacts
- Dependabot pull request history (dependency update log)
- Helm release history linking inventory states to deployment events

## Customer Responsibility

The deploying agency must:
1. Retrieve and review the SBOM for each Gauntlet release as part of their
   component inventory process, using `cosign verify-attestation` to confirm
   SBOM authenticity
2. Integrate the SBOM into their organization's software asset management
   system to satisfy their own CM-8 implementation for the Gauntlet
   component
3. Document Gauntlet's component inventory (by image digest and chart
   version) in their SSP component inventory table
4. Review Grype/Trivy scan results for each release and document acceptance
   of any findings that are not remediated before deployment
