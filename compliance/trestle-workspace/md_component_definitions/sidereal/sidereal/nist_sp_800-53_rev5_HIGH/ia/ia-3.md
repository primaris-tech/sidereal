---
x-trestle-comp-def-rules:
  sidereal:
    - name: mtls-all-external-connections
      description: Sidereal enforces mutual TLS for all connections to external systems including detection backend gRPC APIs, CNI observability APIs, and SIEM endpoints; unauthenticated connections are refused before any data exchange occurs
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: ia-03
status: implemented
---

# IA-3 — Device Identification and Authentication

## Control Statement

Uniquely identify and authenticate devices before establishing connections,
including connections from external systems and components. Device
authentication must use cryptographic mechanisms and must be enforced before
any data exchange occurs.

## Sidereal Implementation

In Sidereal's architecture, "devices" are the external system endpoints the
controller connects to: detection backends (e.g., Falco, Tetragon), CNI
observability APIs (e.g., Hubble, Calico), and SIEM export targets. Every external
connection requires cryptographic device authentication before data exchange
begins. There is no fallback to unauthenticated connections.

### Mutual TLS — Bidirectional Device Authentication

mTLS is enforced on all external connections. Mutual authentication means:
- **Sidereal authenticates the remote device**: the controller validates the
  remote endpoint's X.509 certificate against the CA bundle configured in
  Helm values before accepting any data from that connection
- **The remote device authenticates Sidereal**: the controller presents its
  own X.509 client certificate (or SPIFFE SVID); the remote endpoint must
  accept this credential before the handshake completes

A connection where either side cannot authenticate is refused at the TLS
handshake layer — before any application data (probe results, detection
query responses, SIEM payloads) is transmitted.

External connections and their authentication requirements:

| External System | Authentication Mechanism | Identity Verification |
|---|---|---|
| Detection backend gRPC API (e.g., Falco gRPC Output API) | mTLS (client cert + server cert) | Server SAN matches detection backend SPIFFE URI or DNS name |
| Detection backend gRPC API (e.g., Tetragon gRPC Event API) | mTLS (client cert + server cert) | Server SAN matches detection backend SPIFFE URI or DNS name |
| CNI observability API (e.g., Hubble API) | mTLS (client cert + server cert) | Server SAN matches CNI observability endpoint identity |
| CNI observability API (e.g., Calico API) | mTLS (client cert + server cert) | Server SAN matches CNI observability API server identity |
| Splunk HEC | TLS (server cert) + HEC token | Server SAN + API credential over TLS |
| Elasticsearch | TLS (server cert) + API key | Server SAN + API credential over TLS |
| S3 | TLS (server cert) + AWS SigV4 | Server cert (AWS ACM) + request signing |

### SAN Validation — Identity-Specific Authentication

Certificate validation is not limited to chain-of-trust verification.
The controller validates that the Subject Alternative Name (SAN) in the
remote certificate matches the expected peer identity. For SPIFFE/SPIRE
environments, this is the SPIFFE URI (`spiffe://<trust-domain>/<workload>`).
For non-SPIRE environments, this is the DNS SAN of the configured endpoint.

SAN validation prevents a scenario where a valid certificate from a
different service (but the same CA) is substituted for the expected peer —
a form of man-in-the-middle attack that chain-of-trust verification alone
would not detect.

### Authentication Failure Response

When device authentication fails:
1. The TLS handshake is aborted — no application data is exchanged
2. A `SiderealSystemAlert` is created with `reason: ExternalAuthFailure`
   and the identity of the unreachable or unauthenticated endpoint
3. Probes dependent on the failed connection enter `BackendUnreachable`
   state
4. The alert is exported to the SIEM
5. Probe execution on the affected surface is suspended until the alert
   is acknowledged

An authentication failure is not a silent error — it immediately halts
monitoring on the affected surface and generates an auditable alert.

### SPIFFE/SPIRE — Workload Identity (Recommended at IL4/IL5)

SPIFFE/SPIRE provides automated workload identity for all Sidereal
components. Each component receives a unique SPIFFE URI as its device
identity (`spiffe://<trust-domain>/ns/sidereal-system/sa/<component>`).
SVIDs are rotated automatically by the SPIRE agent before expiry (typical
TTL: 1 hour or less), eliminating manual certificate lifecycle management.

SPIFFE/SPIRE enables cryptographic device identity that is:
- Unique to each component (no shared certificates)
- Short-lived (automatic rotation, bounded exposure window)
- Externally verifiable (SPIFFE trust bundles are federable)

### Enhancement: IA-3(1) — Cryptographic Bidirectional Authentication

mTLS is bidirectional by definition. Both the controller (Sidereal's device)
and the remote endpoint (the external device) must present and validate
X.509 certificates. Neither can authenticate to the other without a valid
certificate from the trusted CA. This satisfies IA-3(1) — bidirectional
device authentication using cryptographic mechanisms.

## Evidence Produced

- TLS handshake logs from the controller recording peer certificate subject,
  SAN, and CA chain for every external connection, exported to SIEM
- `SiderealSystemAlert` CRs for any external connection that fails mTLS
  negotiation or SAN validation
- SPIRE SVID issuance logs (when SPIRE is deployed), recording component
  identity assignments and rotation events
- Controller startup logs confirming CA bundle configuration for each
  external endpoint

## Customer Responsibility

The deploying agency must:
1. Provision and maintain server-side TLS certificates for detection backends
   (e.g., Falco, Tetragon), CNI observability endpoints (e.g., Hubble,
   Calico), and SIEM endpoints with correct SANs
2. Provide the corresponding CA bundle to Sidereal via Helm values
   (`externalSystems.<name>.tlsCABundle`) to enable client-side certificate
   validation
3. Not set `tlsInsecureSkipVerify: true` for any external connection — this
   value must remain `false` in all deployments
4. For IL4/IL5: deploy and operate SPIFFE/SPIRE for automated SVID-based
   device identity management across all Sidereal-connected systems
