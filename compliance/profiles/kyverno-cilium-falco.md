# Deployment Profile: kyverno-cilium-falco

**Profile ID**: `kyverno-cilium-falco`
**Description**: Default Gauntlet deployment profile for Cilium-based clusters with Kyverno admission control and Falco runtime detection.

---

## Capability Bindings

| Abstract Capability | Concrete Implementation | Version Constraint |
|---|---|---|
| Admission Enforcement | Kyverno | >= 1.10 |
| Image Signature Verification | Kyverno cosign verifyImages | >= 1.10 |
| Detection Backend | Falco gRPC Output API | >= 0.37 |
| CNI Observability | Hubble gRPC (Cilium) | >= 1.14 |
| SIEM Export | [Agency-configured: Splunk HEC, Elasticsearch, S3] | — |

## Helm Profile Configuration

```yaml
gauntlet:
  profile:
    admissionController: kyverno
    signatureVerifier: kyverno
    detectionBackend: falco
    cniObservability: hubble
```

## Admission Policies Rendered

The Helm chart renders the following Kyverno ClusterPolicies for this profile:

| Policy Name | Abstract Capability | What It Enforces |
|---|---|---|
| `gauntlet-image-signature-required` | Image Signature Verification | cosign signature verification on all Pods in `gauntlet-system` |
| `gauntlet-proberesult-immutable` | Audit Record Immutability | Denies UPDATE and DELETE on `GauntletProbeResult` for all principals |
| `gauntlet-job-constraints` | Job SA Constraints | Controller may only create Jobs referencing pre-approved probe ServiceAccounts |
| `gauntlet-no-writable-pvc` | No Writable PVC | Denies writable PVC mounts on Pods in `gauntlet-system` |
| `gauntlet-admission-probe-target` | Admission Probe Default | Rejects resources with label `gauntlet.io/admission-probe: "true"` |

## Connection Parameters

| System | Port | Protocol | Authentication |
|---|---|---|---|
| Kubernetes API Server | 443/TCP | mTLS | ServiceAccount token (1hr bound expiry) |
| Falco gRPC | 50051/TCP | gRPC/TLS | mTLS, SAN validation |
| Hubble Relay | 4245/TCP | gRPC/TLS | mTLS, SAN validation |
| SIEM endpoints | [Agency-configured] | HTTPS/TLS 1.2+ FIPS | [Agency-configured] |

## Bootstrap Verification Checklist

For this profile, the bootstrap verifier checks:

1. Kyverno CRDs (`clusterpolicies.kyverno.io`) exist
2. All 5 Kyverno ClusterPolicies listed above are present with `validationFailureAction: Enforce`
3. All 6 ServiceAccounts exist with expected RBAC bindings
4. Default-deny NetworkPolicy is in place in `gauntlet-system`
5. HMAC root Secret is accessible
6. Falco gRPC endpoint is reachable on port 50051
7. Hubble Relay gRPC endpoint is reachable on port 4245

## SAP Test Commands

These are the profile-specific commands for the SAP test procedures. Replace the generic `[profile-specific]` placeholders in the SAP template with these commands.

### TEST-SYS-01 — Image Signature Verification

```bash
# Confirm Kyverno policy is in Enforce mode
kubectl get clusterpolicy gauntlet-image-signature-required -o yaml \
  | grep 'validationFailureAction'
# Expected: validationFailureAction: Enforce

# Attempt unsigned image — confirm Kyverno blocks it
kubectl run test-unsigned --image=nginx:latest \
  --overrides='{"metadata":{"namespace":"gauntlet-system"}}' \
  --dry-run=server 2>&1
# Expected: admission webhook error citing signature requirement
```

### TEST-SYS-02 — HMAC Result Integrity

```bash
# Attempt to modify a GauntletProbeResult — confirm Kyverno blocks it
RESULT=$(kubectl get gauntletproberesults -n gauntlet-system -o name | head -1)
kubectl patch $RESULT -n gauntlet-system \
  --type='merge' -p '{"spec":{"result":{"outcome":"Pass"}}}' \
  --dry-run=server 2>&1
# Expected: admission webhook error citing immutability policy
```

### TEST-SYS-03 — Append-Only Enforcement

```bash
# Confirm append-only policy is in Enforce mode
kubectl get clusterpolicy gauntlet-proberesult-immutable -o yaml \
  | grep 'validationFailureAction'
# Expected: validationFailureAction: Enforce
```

### TEST-SYS-04 — NetworkPolicy Verification (Hubble)

```bash
# Review the NetworkPolicy probe's most recent result
kubectl get gauntletproberesults -n gauntlet-system \
  --field-selector='spec.probe.type=netpol' \
  --sort-by=.metadata.creationTimestamp -o yaml | tail -30
# Expected: outcome: Pass (or Dropped), verificationMode: cni-verdict
```

### TEST-SYS-07 — Identity Separation

```bash
# Confirm Kyverno Job-constraints policy is in Enforce mode
kubectl get clusterpolicy gauntlet-job-constraints -o yaml \
  | grep 'validationFailureAction'
# Expected: validationFailureAction: Enforce
```

## Evidence Collection

```bash
# Verify cosign signatures for all deployed images
kubectl get pods -n gauntlet-system -o json \
  | jq -r '.items[].spec.containers[].image' | sort -u \
  | while read IMAGE; do
      echo "Verifying: $IMAGE"
      cosign verify \
        --certificate-identity-regexp 'https://github.com/primaris-tech/gauntlet' \
        --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
        "$IMAGE" 2>&1 | grep -E 'Verification|Error'
    done

# Export Kyverno policy admission events for the assessment period
kubectl get events -n gauntlet-system \
  --field-selector='reason=PolicyViolation' -o json \
  > kyverno-violations-$(date +%Y%m%d).json
```
