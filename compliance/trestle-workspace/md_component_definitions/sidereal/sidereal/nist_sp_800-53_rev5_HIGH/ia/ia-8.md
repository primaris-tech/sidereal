---
x-trestle-comp-def-rules:
  sidereal:
    - name: mtls-non-organizational-external-authentication
      description: Sidereal requires mutual TLS for all connections to non-organizational external systems; server certificates are validated against a configured CA bundle before any data exchange; tlsInsecureSkipVerify cannot be enabled
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: ia-08
status: implemented
---

# IA-8 — Identification and Authentication (Non-Organizational Users)

## Control Statement

Uniquely identify and authenticate non-organizational users or processes
acting on behalf of non-organizational users. Identification and
authentication must use mechanisms meeting the assurance requirements of
applicable access control policy and standards.

## Sidereal Implementation

In Sidereal's architecture, non-organizational users are the external
systems the controller connects to that exist outside the deploying agency's
direct administrative control: detection backends (e.g., Falco, Tetragon),
CNI observability APIs (e.g., Hubble, Calico), and SIEM export targets. Each must
be cryptographically identified before Sidereal delivers probe data or
accepts responses.

IA-8 is the inverse framing from IA-3: where IA-3 focuses on Sidereal
authenticating external devices, IA-8 focuses on external systems
authenticating themselves to Sidereal. Both directions are enforced by
the same mTLS mechanism.

### Cryptographic Identification of External Systems

Before transmitting any probe data to an external system, the controller
validates the remote endpoint's X.509 certificate:

1. **Chain of trust**: The certificate chain is validated against the CA
   bundle configured in `externalSystems.<name>.tlsCABundle` in the Helm
   values. A certificate not anchored to the configured CA is rejected.

2. **SAN matching**: The Subject Alternative Name in the certificate must
   match the expected identity of the peer — the configured hostname or
   SPIFFE URI. A certificate from a different host in the same CA trust
   domain is not accepted.

3. **Validity period**: The certificate must not be expired. An expired
   certificate is rejected unconditionally, even if it otherwise validates.

4. **Revocation** (when CRL/OCSP is configured): The certificate must not
   be revoked. Revocation checking is configurable in Helm values.

If any of these checks fail, the connection is terminated before any data
is sent. The failed authentication event generates a `SiderealSystemAlert`
and SIEM export.

### Layered Authentication for SIEM Endpoints

SIEM endpoints may exist across organizational boundaries (e.g., a
government-managed Splunk instance operated by a separate agency, or a
cloud-hosted Elasticsearch service). Sidereal applies layered
authentication:

| SIEM Target | Layer 1 (Transport) | Layer 2 (Application) |
|---|---|---|
| Splunk HEC | TLS server cert validation | HEC token (Secret reference in Helm values) |
| Elasticsearch | TLS server cert validation + optional mTLS | API key (Secret reference in Helm values) |
| S3 | TLS (AWS ACM certificate) | AWS SigV4 request signing |

The Layer 2 application credential is transmitted only after Layer 1
authentication succeeds — the credential never traverses an unauthenticated
channel.

### No Unauthenticated Fallback

`tlsInsecureSkipVerify` is a configuration option that disables server
certificate validation. In Sidereal:
- The option exists in the Helm values schema for operational completeness
- The Helm schema validation marks it as `deprecated` and emits a warning
  if set to `true`
- The controller startup check logs a `SECURITY_WARNING` event to the SIEM
  if `tlsInsecureSkipVerify: true` is detected in any external system
  configuration
- Admission enforcement policy (CM-6) flags deployments with `tlsInsecureSkipVerify: true`
  as policy violations

Federal deployments must not set this value to `true`. The control exists
to support integration testing in non-federal environments only.

### SPIFFE/SPIRE for Non-Organizational Workload Identity

Where SPIFFE/SPIRE is deployed across the cluster infrastructure, external
systems (e.g., Falco, Tetragon, Hubble) receive SPIFFE SVIDs as their workload
identity. The controller validates the SPIFFE URI in the server SVID
against the expected workload identity for each external system.

This provides a stronger identification assurance than DNS-name-based
certificate validation: a SPIFFE URI encodes the workload's identity
(namespace, ServiceAccount) cryptographically, not just its network
location. A DNS name can be reused for different workloads; a SPIFFE URI
is specific to the workload identity.

SPIFFE federation enables this same identity assurance even when external
systems are operated by a different organization under a different SPIFFE
trust domain — the controller can validate cross-trust-domain SVIDs against
the federated trust bundle.

### Enhancement: IA-8(2) — Acceptance of External Authenticators

Sidereal accepts X.509 certificates issued by any CA configured in the
`tlsCABundle` Helm value. The agency controls which CAs are trusted —
Sidereal does not maintain a hardcoded list of trusted CAs. This allows
the agency to accept certificates from their organization's PKI, a
government CA (e.g., Federal PKI), or a trusted third-party CA, while
rejecting all others.

### Enhancement: IA-8(4) — Use of Defined Profiles

mTLS with X.509 certificates follows the NIST SP 800-63B and SP 800-207
(Zero Trust) identity assurance profiles. SPIFFE/SPIRE SVIDs conform to
the SPIFFE specification (CNCF standard), providing a defined, externally
auditable identity profile for workload authentication.

## Evidence Produced

- TLS connection logs recording peer certificate subject, SAN, issuing CA,
  and validation outcome for every external connection, exported to SIEM
- `SiderealSystemAlert` CRs for any external endpoint that fails mTLS
  authentication or certificate validation
- Controller startup logs confirming CA bundle configuration and
  `tlsInsecureSkipVerify` status for each external endpoint
- Admission policy violation events if `tlsInsecureSkipVerify: true` is
  detected in the deployment configuration

## Customer Responsibility

The deploying agency must:
1. Configure the CA bundle for all external system certificates in the
   Sidereal Helm values; this bundle is the trust anchor for non-org
   system authentication
2. Never set `tlsInsecureSkipVerify: true` in a production or
   government-connected deployment — doing so eliminates the authentication
   assurance IA-8 requires
3. Rotate client certificate credentials (mTLS client certs and SIEM API
   tokens) when personnel with access to those credentials depart the
   organization or when the access period expires
4. Document the external systems Sidereal connects to and their
   authentication mechanism in the SSP Interconnection Table, with an
   ISA/MOU for each connection crossing organizational boundaries
