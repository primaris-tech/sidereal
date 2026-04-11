---
x-trestle-comp-def-rules:
  gauntlet:
    - name: cosign-sbom-digest-pinning-admission-supply-chain-controls
      description: Gauntlet implements supply chain controls via cosign image signing, SBOM attestation, SHA-256 digest pinning in the Helm chart, and admission enforcement of signature verification
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: sr-03
status: implemented
---

# SR-3 — Supply Chain Controls and Plans

## Control Statement

Establish a plan for managing supply chain risks associated with the
development, acquisition, maintenance, and disposal of systems, components,
and services, including counterfeit components, insertion of malicious code,
and installation of unauthorized software.

## Gauntlet Implementation

Gauntlet's supply chain risk management is implemented as a set of automated
technical controls in the CI/CD pipeline and at cluster admission time.
Each control addresses a specific supply chain threat vector.

### Threat: Tag Substitution / Registry Tampering — Digest Pinning

All container image references in the Gauntlet Helm chart are pinned by
SHA-256 digest, not by mutable tag. A tag (`v1.2.0`) can be overwritten
by pushing a new image to the registry. A digest (`sha256:a3f2...`) is
immutable — it is the cryptographic hash of the image manifest. Any change
to the image content produces a different digest.

This means:
- An attacker who gains write access to the registry cannot substitute a
  malicious image under the same tag and have it deployed
- The Helm chart unambiguously identifies the exact binary to deploy; there
  is no ambiguity between "the tag at install time" and "the tag now"
- Image drift between environments (dev, staging, production) is impossible
  when all deploy from the same pinned digest

Dependabot monitors for new image versions and opens pull requests to update
digest pins. Each update is a reviewable code change that flows through CI
before merging.

### Threat: Malicious Code in Dependencies — SBOM + Vulnerability Scanning

The CI pipeline generates a CycloneDX SBOM for each component image on every
build, capturing all Go modules, Rust crates, OS packages, and base image
layers with their exact versions and SHA-256 hashes.

Grype and Trivy scan the SBOM against the NVD, OSV, and GitHub Advisory
databases on every push, pull request, and release:
- **Critical CVE findings**: fail the build immediately; no artifact is
  produced, no image is signed, no deployment is possible
- **High CVE findings**: fail the release unless a documented exception is
  present in the repository with an approved justification
- **Medium/Low findings**: recorded in the release artifact; reviewed as
  part of the release process

Scan results are archived per release. An agency's assessor can retrieve
the scan result for any deployed version and verify the vulnerability
posture at time of release.

### Threat: Unauthorized Software at Deployment — cosign + Admission Enforcement

Every image produced by the CI pipeline is signed using `cosign sign` with
a KMS-backed signing key (SC-12). The signature is bound to the image's
SHA-256 digest.

The `gauntlet-image-signature-required` admission enforcement policy, shipped in
the Gauntlet Helm chart, verifies the cosign signature of every image before
any Pod in `gauntlet-system` is admitted. This policy enforces that only
images produced by the authorized CI pipeline can run in the cluster:
- A locally built image: no signature → admission denied
- An image from a fork: signed by a different key → admission denied
- A registry-mirrored image without re-signing: no signature → admission
  denied (air-gapped exception procedure documented in CM-14)
- A CI-produced, signed image: valid signature → admitted

The admission enforcement policy is deployed before Gauntlet itself (Helm pre-install
hook), ensuring admission enforcement is active from the very first Pod
creation. There is no deployment window during which unsigned images can run.

### Threat: Compromise of Build Environment — CI Pipeline Hardening

The CI pipeline itself is a supply chain component. Gauntlet's pipeline
enforces:
- Pinned actions/tool versions (no `@latest` references in workflow files)
- Separate signing step with access limited to the release pipeline identity
- No developer write access to the signing key (KMS policy)
- Build reproducibility checks (same source commit produces same digest)
- Sigstore Rekor transparency log entry for every signing event (external
  audit trail for the pipeline itself)

### Enhancement: SR-3(3) — Supply Chain Controls for Development

Supply chain controls are applied at every phase:
- **Development**: Dependabot monitors dependencies; Grype/Trivy scan in CI
- **Build**: Digest pinning; FIPS-validated compilation flags verified
- **Release**: cosign signing; SBOM attestation; Rekor transparency log
- **Deployment**: Admission controller enforcement; digest verification
- **Maintenance**: Helm release history for rollback; SBOM diff on upgrade
- **Disposal**: Image digest references remain verifiable in Rekor
  indefinitely

## Evidence Produced

- cosign signature and CycloneDX SBOM attestation OCI artifacts for each
  component image, verifiable with `cosign verify` and
  `cosign verify-attestation --type cyclonedx`
- Grype/Trivy vulnerability scan reports archived per release
- Admission controller policy enforcement records for all Pod deployments in `gauntlet-system`
- CI pipeline build logs with SBOM generation, scan results, and signing
  steps per release
- Sigstore Rekor transparency log entries for each signing event

## Customer Responsibility

The deploying agency must:
1. Integrate Gauntlet's published SBOM into their organization's software
   supply chain risk management program (SCRM)
2. Validate cosign signatures before deploying any Gauntlet update, using
   the public key distributed with the Helm chart
3. Ensure the admission controller (e.g., Kyverno or OPA/Gatekeeper) is deployed in the cluster before Gauntlet installation
   so that admission enforcement is active from the first deployment
4. Treat any admission controller denial for a Gauntlet image as a potential
   supply chain security event requiring investigation and documentation
