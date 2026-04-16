---
title: Custom Probes
description: Building operator-extensible probes with the standardized input/output contract
---

Sidereal supports custom probes for agency-specific security controls that fall outside the five built-in probe surfaces. Custom probes run under the same security controls as built-in probes: non-root, read-only root filesystem, all capabilities dropped, digest-pinned images, cosign-verified at admission.

## Input/output contract

A custom probe is a container image that receives configuration as a JSON file and writes its result as a JSON file. The controller mounts these paths into the probe Job.

**Input**: The probe reads its configuration from a file at a well-known path. The content is the opaque JSON you provide in the `SiderealProbe` spec under `runner.custom.config`.

**Output**: The probe writes a JSON result to a well-known path. The result must include an `outcome` field with one of the standard `ProbeOutcome` values: `Pass`, `Fail`, `Blocked`, `Rejected`, `Accepted`, `NotApplicable`, `Indeterminate`, or `NotEnforced`. It may optionally include a `detail` string with a human-readable explanation.

The controller reads the output, derives `controlEffectiveness`, signs the result with HMAC, and creates the `SiderealProbeResult` resource.

## Image requirements

Custom probe images must meet the same supply chain requirements as built-in probes:

- **Digest-pinned**: the image reference must use a SHA256 digest, not a tag.
- **Cosign-signed**: the image must be signed with cosign. The admission controller (Kyverno or Policy Controller, depending on your deployment profile) verifies the signature at Pod admission.
- **Minimal base**: use distroless or scratch base images. No shell, no package manager.
- **Non-root**: the container runs as a non-root user with a read-only root filesystem and all Linux capabilities dropped.

## ServiceAccount registration

Each custom probe needs a dedicated ServiceAccount registered in Helm values. This ensures the controller only creates Jobs referencing pre-approved ServiceAccounts.

```yaml
customProbes:
  serviceAccounts:
    - name: sidereal-probe-dns-resolution
      namespace: sidereal-system
    - name: sidereal-probe-certificate-expiry
      namespace: sidereal-system
```

The ServiceAccount must exist in the cluster with only the RBAC permissions the probe needs. Follow the principle of least privilege -- if the probe only needs to read Certificate resources, grant only `get` and `list` on `certificates.cert-manager.io`.

## Creating the SiderealProbe

```yaml
apiVersion: sidereal.cloud/v1alpha1
kind: SiderealProbe
metadata:
  name: dns-resolution-check
  namespace: sidereal-system
spec:
  profile: agency.example/dns-resolution
  targetNamespace: production
  executionMode: observe
  intervalSeconds: 3600
  controlMappings:
    nist-800-53:
      - SC-20
      - SC-22
  runner:
    type: custom
    custom:
      image: ghcr.io/my-agency/sidereal-probe-dns@sha256:abc123...
      serviceAccountName: sidereal-probe-dns-resolution
      config:
        domains:
          - "api.internal.agency.gov"
          - "auth.internal.agency.gov"
        expectedResolvers:
          - "10.0.0.53"
```

The `profile` identifies the probe's semantics. The `runner` tells Sidereal how to execute that profile. The `controlMappings` field lets the profile declare its canonical NIST controls, which Sidereal then expands through the same multi-framework mapping pipeline built-in profiles use.

## Security controls

Custom probes are subject to every security control that applies to built-in probes:

- The admission enforcement policy validates that Jobs reference only pre-approved ServiceAccounts.
- A `ResourceQuota` on the `sidereal-system` namespace caps concurrent probe Jobs.
- Probe results are HMAC-signed and verified by the controller.
- Results are append-only (admission policy denies UPDATE/DELETE on `SiderealProbeResult`).
- The probe carries the `sidereal.cloud/probe-id` fingerprint label. Unfingerprinted actions do not execute.
