---
x-trestle-comp-def-rules:
  sidereal:
    - name: tls12-mtls-fips-cipher-suites-all-transmissions
      description: All Sidereal data transmissions use TLS 1.2 or higher with FIPS-approved cipher suites enforced by BoringCrypto (Go) and aws-lc-rs (Rust); mTLS is required for all external connections
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: sc-08
status: implemented
---

# SC-8 — Transmission Confidentiality and Integrity

## Control Statement

Implement cryptographic mechanisms to prevent unauthorized disclosure and
detect changes to information during transmission, unless protected by
alternative physical safeguards. Cryptographic protections must meet
applicable standards and cover all paths where sensitive data traverses.

## Sidereal Implementation

Every Sidereal transmission path — internal to the cluster and external to
SIEM targets — uses cryptographic protection. There are no plaintext
transmission paths. FIPS-approved implementations are used throughout.

### Internal Transmission: Probe Runner to Kubernetes API Server

Probe runners communicate with the Kubernetes API server exclusively over
TLS. The Kubernetes API server certificate is verified against the cluster
CA bundle mounted into the Job at runtime. The probe runner's identity is
authenticated via its per-probe ServiceAccount token (a signed JWT).

The connection uses the Rust `aws-lc-rs` TLS stack, which enforces:
- Minimum TLS 1.2 (`TLSv1.2` floor, `TLSv1.3` preferred)
- FIPS-approved cipher suites only (AES-128-GCM-SHA256,
  AES-256-GCM-SHA384, CHACHA20-POLY1305 is disabled in FIPS mode)
- No non-FIPS cipher suite negotiation fallback

A handshake that negotiates below TLS 1.2 or to a non-FIPS cipher is
rejected at the Rust TLS layer before any application data is sent. The
rejection is logged to the SIEM.

### In-Cluster Integrity: HMAC-Signed Result ConfigMaps

Probe results written to result ConfigMaps are HMAC-signed before writing.
The HMAC key is derived via FIPS-approved HKDF from a per-execution secret
injected into the Job. The signature covers the full result payload.

This provides a data integrity guarantee for information in transit within
the cluster (probe runner → ConfigMap → controller), independent of
Kubernetes' own TLS transport. A man-in-the-middle attack between the probe
runner and the API server (e.g., a compromised API server replica) cannot
produce a valid HMAC signature without the per-execution key material.

The controller verifies the HMAC signature before accepting any result. An
invalid or absent signature produces a `TamperedResult` outcome (see SI-7).

### External Transmission: SIEM Export

All SIEM export channels use TLS with FIPS-approved cipher suites:

| Export Target | Protocol | Authentication |
|---|---|---|
| Splunk HEC | HTTPS (TLS 1.2+) | HEC token over TLS; mTLS optional |
| Elasticsearch | HTTPS (TLS 1.2+) | API key over TLS; mTLS optional |
| S3 | HTTPS (TLS 1.2+) | AWS SigV4; SSE-KMS for at-rest |

The controller's Go TLS stack (BoringCrypto) enforces the same cipher suite
restrictions for outbound connections as for inbound. A `siem.tlsCABundle`
field in the Helm values is required when SIEM export is enabled — the
controller will not start without it, preventing misconfigured deployments
from exporting to an unauthenticated endpoint.

**S3 object lock**: Exported S3 objects are written with object lock in
COMPLIANCE mode, providing write-once protection after transmission.
SSE-KMS with a customer-managed KMS key provides at-rest encryption
(see SC-12 for key management).

### External Transmission: CNI Observability APIs

Controller connections to the CNI observability layer (e.g., Hubble gRPC/TLS, Calico REST/HTTPS) use
mTLS. The controller presents a client certificate issued from the cluster's
internal CA (or a SPIFFE SVID if SPIRE is deployed). The server certificate
is verified against the known cluster CA bundle.

### External Transmission: Detection Backends

Controller connections to detection backends (e.g., Falco gRPC, Tetragon
gRPC) use TLS with mutual authentication. The controller verifies the
detection backend's server certificate before sending any query, preventing
a rogue detection backend instance from returning falsified detection results.

### Enhancement: SC-8(1) — Cryptographic Protection

All transmission paths implement cryptographic protection using
FIPS 140-2 validated modules (BoringCrypto for Go, aws-lc-rs for Rust).
This satisfies SC-8(1) without alternative physical safeguards. See SC-13
for the complete cryptographic module inventory.

### Enhancement: SC-8(2) — Pre- and Post-Transmission Handling

The HMAC signature on result ConfigMaps provides integrity assurance that
is maintained independently of the transmission channel. The signature is
computed before writing (pre-transmission) and verified before reading
(post-transmission). This ensures integrity even if the transmission
channel itself is compromised.

## Evidence Produced

- TLS connection logs capturing negotiated protocol version and cipher suite
  for each external connection, exported to SIEM
- HMAC signature verification log entries in the controller for each probe
  result accepted or rejected
- `TamperedResult` outcome records in `SiderealProbeResult` CRs when HMAC
  verification fails
- Controller startup logs confirming TLS CA bundle configuration and SIEM
  endpoint reachability
- S3 object lock and SSE-KMS configuration in S3 bucket policy (per-agency)

## Customer Responsibility

The deploying agency must:
1. Ensure that the detection backend (e.g., Falco, Tetragon), CNI observability
   (e.g., Hubble), Elasticsearch, and Splunk server
   endpoints support TLS 1.2 or higher with FIPS-approved cipher suites
2. Configure their infrastructure to reject TLS downgrade negotiation from
   any client connecting to these endpoints
3. Provide a valid TLS CA bundle for each SIEM endpoint in the Sidereal
   Helm values (`siem.tlsCABundle`)
4. Configure the S3 bucket used for export with SSE-KMS using a
   FIPS 140-2 validated KMS key and enable object lock in COMPLIANCE mode
