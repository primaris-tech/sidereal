---
x-trestle-comp-def-rules:
  gauntlet:
    - name: sbom-cosign-signature-chain-provenance
      description: Gauntlet establishes component provenance through cosign-attested CycloneDX SBOMs and SLSA provenance attestations that link each deployed image digest to its build pipeline, source commit, and dependency tree
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: sr-04
status: implemented
---

# SR-4 — Provenance

## Control Statement

Document and monitor the provenance of systems, system components, and
associated data, including source, chain of custody, and integrity
throughout the system lifecycle. Provenance documentation must support
detection of counterfeit or maliciously altered components.

## Gauntlet Implementation

Gauntlet's provenance chain links every deployed binary back to a specific
source commit, build run, and dependency tree. This chain is machine-verifiable
at any point during the component lifecycle without relying on external
documentation — the provenance is in the artifact itself.

### The Provenance Chain

For any deployed Gauntlet image, the complete provenance chain is:

```
Source commit (git SHA)
  → CI build run (authenticated pipeline identity)
    → Container image (SHA-256 digest, immutable)
      → cosign signature (KMS-signed, Rekor-logged)
        → CycloneDX SBOM (cosign-attested to image digest)
          → SLSA provenance attestation (cosign-attested to image digest)
            → Admission controller verification (verified at every Pod start)
```

Every link in this chain is cryptographically bound to the next. Breaking
the chain (tampering with any component) invalidates the signature, which
the admission controller (e.g., Kyverno or OPA/Gatekeeper) detects at admission.

### SBOM — Dependency Tree Provenance

The CycloneDX SBOM attested to each image digest documents:
- Every Go module with exact version and `go.sum` checksum
- Every Rust crate with exact version and `Cargo.lock` hash
- Every OS package in the base image layer with version and origin
- The base image identity (digest, not tag)

This allows an agency's assessor to answer: "exactly what third-party code
is running in this Gauntlet deployment?" without trusting a separately
maintained spreadsheet. The answer is in the cosign-attested artifact
bound to the deployed image digest.

The SBOM is queryable for any deployed version:
```
cosign verify-attestation \
  --type cyclonedx \
  --key <gauntlet-pub.pem> \
  <image@sha256:digest>
```

### SLSA Provenance — Build Pipeline Provenance

The CI pipeline produces a SLSA (Supply-chain Levels for Software Artifacts)
Level 2 provenance attestation for each image. The attestation records:
- Source repository URL and branch
- Source commit SHA (the exact code that was built)
- Build timestamp
- Build system identity (the CI pipeline's service account)
- Build inputs (tool versions, environment)

The SLSA attestation is signed with cosign and stored as an OCI referrer
alongside the image. It is queryable via:
```
cosign verify-attestation \
  --type slsaprovenance \
  --key <gauntlet-pub.pem> \
  <image@sha256:digest>
```

This allows the agency's AO to independently verify that a deployed Gauntlet
image was produced from a specific auditable source commit by an authorized
pipeline identity — not built locally, not from a fork, not produced outside
the release process.

### Sigstore Rekor — External Chain of Custody

Every cosign signing event (signature and attestations) is recorded in the
Sigstore Rekor transparency log. Rekor is:
- External to Gauntlet's own infrastructure
- Append-only and tamper-evident
- Publicly queryable by any party

This means the chain of custody for each release artifact is independently
verifiable by the agency, their assessors, or any third party — without
trusting Gauntlet as the sole custodian of the provenance record.

### Runtime Provenance Continuity

The admission controller re-verifies the cosign signature at every Pod admission. This means
provenance verification is not a one-time event at install time — it is
continuous. An image that had valid provenance when deployed continues to
be verified on every restart, rescheduling, or upgrade. Provenance cannot
become stale in a running cluster.

### Enhancement: SR-4(1) — Identity

Each component image has a unique, immutable identity: its SHA-256 digest.
The digest is not assigned by Gauntlet — it is derived from the image
content by the OCI registry. Two images with the same digest are
cryptographically identical. An image that has been tampered with has a
different digest and a different (invalid or absent) signature.

### Enhancement: SR-4(3) — Validate as Genuine

The cosign signature verification performed by the admission controller at
admission is the technical implementation of "validate as genuine." A signed
image from the Gauntlet release pipeline is genuine. An unsigned image, an
image signed by a different key, or an image whose signature does not match
the deployed digest is not genuine. The admission controller (e.g., Kyverno
or OPA/Gatekeeper) enforces this distinction at every Pod start.

## Evidence Produced

- CycloneDX SBOM cosign attestations for each component image per release
  (queryable with `cosign verify-attestation --type cyclonedx`)
- SLSA provenance cosign attestations linking each image to its source
  commit and CI build run (queryable with `cosign verify-attestation
  --type slsaprovenance`)
- Sigstore Rekor transparency log entries for every signing and attestation
  event (external, append-only, independently queryable)
- Admission policy records confirming provenance verification at each
  Pod deployment

## Customer Responsibility

The deploying agency must:
1. Verify the cosign signature and SBOM attestation for each Gauntlet image
   before deploying a new version; store the verification output as part of
   the change management record
2. Include Gauntlet component provenance records (image digest, SLSA
   attestation reference, Rekor log index) in their system component
   inventory documentation
3. Query the SLSA provenance attestation as part of their supply chain
   review process for each Gauntlet upgrade
4. Document the Rekor log index for each deployed release version in their
   SSP component inventory to establish an independent external reference
