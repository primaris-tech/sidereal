# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Sidereal, please report it through GitHub's private vulnerability reporting feature:

1. Go to the [Security tab](https://github.com/primaris-tech/sidereal/security) of this repository
2. Click "Report a vulnerability"
3. Provide a description of the vulnerability, steps to reproduce, and any relevant details

**Please do not open public issues for security vulnerabilities.**

We will acknowledge receipt within 48 hours and provide an initial assessment within 5 business days.

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Security Model

Sidereal's security architecture is documented in the [engineering specification](sidereal-engineering-summary.md). Key security properties:

- **Privilege isolation**: Controller, probe runners, and discovery use separate ServiceAccounts with minimum required permissions
- **HMAC result integrity**: Per-execution keys derived via HKDF-SHA256 prevent result tampering
- **FIPS 140-2 cryptography**: BoringCrypto (Go, CMVP #3678) and aws-lc-rs (Rust, CMVP #4816)
- **Image signing**: All container images are signed with cosign (keyless via Sigstore OIDC)
- **Supply chain**: CycloneDX SBOMs, SLSA provenance attestations, Sigstore transparency log

## CVE SLAs

| Severity | Remediation Timeline |
|---|---|
| Critical | 30 days |
| High | 60 days |
| Medium | 90 days |
