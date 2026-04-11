---
x-trestle-comp-def-rules:
  gauntlet:
    - name: fips-140-2-boringcrypto-aws-lc-rs
      description: All Gauntlet cryptographic operations use FIPS 140-2 validated modules — BoringCrypto for Go components and aws-lc-rs for Rust components — with no fallback to non-FIPS primitives; FIPS self-tests run at container startup
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: ia-07
status: implemented
---

# IA-7 — Cryptographic Module Authentication

## Control Statement

Implement mechanisms for authentication to a cryptographic module that meet
the requirements of applicable laws, directives, policies, regulations,
standards, and guidelines for cryptographic module authentication.

## Gauntlet Implementation

IA-7 requires that when a system authenticates using cryptography, the
cryptographic module performing that authentication must itself be validated.
For federal systems, this means FIPS 140-2 validated modules. Gauntlet
satisfies this through two validated cryptographic modules — one per
implementation language — with no non-FIPS fallback path and mandatory
startup self-testing.

### Go Controller — BoringCrypto Module

The Go controller is compiled with `GOEXPERIMENT=boringcrypto`. This build
tag replaces the standard Go `crypto/tls`, `crypto/hmac`, `crypto/sha256`,
and related packages with the BoringCrypto module, validated under CMVP
certificate #3678.

BoringCrypto is the cryptographic module that authenticates the controller
to:
- External services via TLS client certificates (mTLS)
- The Kubernetes API server via TLS (SA token over HTTPS)
- SIEM endpoints via HTTPS

All TLS handshakes, certificate signature verifications, and MAC operations
used in the authentication process are performed by the BoringCrypto module.
The standard Go TLS implementation is unavailable in a BoringCrypto build —
if a codepath attempts to use a non-FIPS primitive, the binary panics at
startup rather than silently falling back.

### Rust Probe Runners — aws-lc-rs FIPS Module

All Rust probe runner binaries are compiled with the `aws-lc-rs` crate's
`fips` feature flag, which links against AWS-LC's FIPS 140-2 validated
cryptographic module (CMVP certificate #4816).

aws-lc-rs is the cryptographic module used for:
- TLS connections to the Kubernetes API server (probe runner authentication)
- HMAC computation for probe result signing

Non-FIPS algorithms are not compiled into the binary. The `fips` feature
flag activates an allow-list of validated algorithms; any algorithm outside
the allow-list results in a compile-time or runtime error, not a silent
fallback to a non-validated implementation.

### Mandatory FIPS Self-Test at Container Startup

Both modules include FIPS Known Answer Tests (KATs) that execute
automatically at module load time:

**BoringCrypto (Go)**: BoringCrypto runs its FIPS KATs when the process
first loads the module. A KAT failure causes the Go runtime to call
`BORINGSSL_FIPS_self_test_failed()`, which terminates the process before
any network connections are established.

**aws-lc-rs (Rust)**: AWS-LC runs its FIPS KATs at library initialization
(`AWSLC_fips_self_test()`). A failure causes the process to exit with a
non-zero code before any probe execution begins.

**Response to self-test failure**:
1. The container exits with non-zero code
2. Kubernetes marks the Pod as failed
3. The Job is not retried (probe execution fails)
4. The absence of a probe result is treated as `Indeterminate`
5. A `GauntletSystemAlert` is created: `reason: FIPSModuleFailure`
6. The alert is exported to the SIEM

A FIPS module failure is treated as a critical security event — monitoring
is halted on the affected probe surface until the alert is acknowledged and
the root cause resolved.

### No Non-FIPS Fallback by Design

Neither module supports runtime configuration to switch to a non-FIPS mode.
The FIPS posture is baked into the compiled binary:
- BoringCrypto: activated by `GOEXPERIMENT=boringcrypto` at compile time
- aws-lc-rs: activated by the `fips` Cargo feature at compile time

There is no environment variable, ConfigMap, or Helm value that can
disable FIPS mode in a running deployment. Disabling FIPS requires
producing a different set of container images — a change-controlled process
(CM-3) that requires a Helm upgrade.

### FIPS Module Version Tracking

CMVP certificate numbers are documented in the Gauntlet release notes
for each release. When an underlying validated module is updated (e.g.,
BoringCrypto updated in a new Go toolchain version), the new CMVP
certificate number is recorded in the release notes and the SBOM. This
allows the agency's ISSO to track the specific validated module version
in use at any point in the system's operational life.

## Evidence Produced

- Container build provenance records confirming `GOEXPERIMENT=boringcrypto`
  and `aws-lc-rs` FIPS feature flag per release (CI pipeline logs)
- `go tool nm` output confirming BoringCrypto symbol presence (CI
  validation step, archived per release)
- FIPS self-test pass log entries at container startup, exported to SIEM
- `GauntletSystemAlert` CRs for any FIPS self-test failure
- SBOM listing aws-lc-rs with FIPS feature flag (cosign-attested)
- Release notes documenting CMVP certificate numbers per release

## Customer Responsibility

The deploying agency must:
1. Verify that `fips.enabled: true` is set in the Gauntlet Helm values and
   that the FIPS image variant is deployed (confirmed by matching image
   digest against the FIPS-specific digest in the release manifest)
2. Ensure that the Kubernetes nodes' operating system cryptographic policy
   does not downgrade TLS negotiation below FIPS-approved cipher suites
3. Document the CMVP certificate numbers for BoringCrypto and AWS-LC in
   their SSP IA-7 statement, referencing the specific Gauntlet release
4. Treat any `GauntletSystemAlert` with `reason: FIPSModuleFailure` as a
   critical security event requiring immediate investigation and AO
   notification
