# Deployment Profile: opa-calico-tetragon

**Profile ID**: `opa-calico-tetragon`
**Description**: Gauntlet deployment profile for Calico-based clusters with OPA/Gatekeeper admission control and Tetragon runtime detection.

---

## Capability Bindings

| Abstract Capability | Concrete Implementation | Version Constraint |
|---|---|---|
| Admission Enforcement | OPA/Gatekeeper | >= 3.14 |
| Image Signature Verification | Sigstore policy-controller | >= 0.6 |
| Detection Backend | Tetragon gRPC Event API | >= 1.0 |
| CNI Observability | Calico Flow Log API | >= 3.26 |
| SIEM Export | [Agency-configured: Splunk HEC, Elasticsearch, S3] | — |

## Helm Profile Configuration

```yaml
gauntlet:
  profile:
    admissionController: opa
    signatureVerifier: policy-controller
    detectionBackend: tetragon
    cniObservability: calico
```

## Admission Policies Rendered

The Helm chart renders the following OPA/Gatekeeper resources for this profile:

| Resource | Abstract Capability | What It Enforces |
|---|---|---|
| `ConstraintTemplate: GauntletImageSignature` + `Constraint: gauntlet-image-signature-required` | Image Signature Verification | cosign signature verification via Sigstore policy-controller webhook |
| `ConstraintTemplate: GauntletImmutableResult` + `Constraint: gauntlet-proberesult-immutable` | Audit Record Immutability | Denies UPDATE and DELETE on `GauntletProbeResult` for all principals |
| `ConstraintTemplate: GauntletJobConstraints` + `Constraint: gauntlet-job-constraints` | Job SA Constraints | Controller may only create Jobs referencing pre-approved probe ServiceAccounts |
| `ConstraintTemplate: GauntletNoWritablePVC` + `Constraint: gauntlet-no-writable-pvc` | No Writable PVC | Denies writable PVC mounts on Pods in `gauntlet-system` |
| `ConstraintTemplate: GauntletAdmissionProbe` + `Constraint: gauntlet-admission-probe-target` | Admission Probe Default | Rejects resources with label `gauntlet.io/admission-probe: "true"` |

## Connection Parameters

| System | Port | Protocol | Authentication |
|---|---|---|---|
| Kubernetes API Server | 443/TCP | mTLS | ServiceAccount token (1hr bound expiry) |
| Tetragon gRPC | 54321/TCP | gRPC/TLS | mTLS, SAN validation |
| Calico API | 5443/TCP | HTTPS/TLS | mTLS, SAN validation |
| SIEM endpoints | [Agency-configured] | HTTPS/TLS 1.2+ FIPS | [Agency-configured] |

## Bootstrap Verification Checklist

For this profile, the bootstrap verifier checks:

1. Gatekeeper CRDs (`constrainttemplates.templates.gatekeeper.sh`) exist
2. All 5 ConstraintTemplates and their Constraints listed above are present with `enforcementAction: deny`
3. Sigstore policy-controller is running and its webhook is active
4. All 6 ServiceAccounts exist with expected RBAC bindings
5. Default-deny NetworkPolicy is in place in `gauntlet-system`
6. HMAC root Secret is accessible
7. Tetragon gRPC endpoint is reachable on port 54321
8. Calico API endpoint is reachable on port 5443

## SAP Test Commands

These are the profile-specific commands for the SAP test procedures.

### TEST-SYS-01 — Image Signature Verification

```bash
# Confirm Gatekeeper constraint exists and is enforcing
kubectl get constraint gauntlet-image-signature-required -o yaml \
  | grep 'enforcementAction'
# Expected: enforcementAction: deny

# Confirm Sigstore policy-controller webhook is active
kubectl get validatingwebhookconfiguration | grep policy-controller
# Expected: policy-controller webhook listed

# Attempt unsigned image — confirm it is blocked
kubectl run test-unsigned --image=nginx:latest \
  --overrides='{"metadata":{"namespace":"gauntlet-system"}}' \
  --dry-run=server 2>&1
# Expected: admission webhook error
```

### TEST-SYS-02 — HMAC Result Integrity

```bash
# Attempt to modify a GauntletProbeResult — confirm Gatekeeper blocks it
RESULT=$(kubectl get gauntletproberesults -n gauntlet-system -o name | head -1)
kubectl patch $RESULT -n gauntlet-system \
  --type='merge' -p '{"spec":{"result":{"outcome":"Pass"}}}' \
  --dry-run=server 2>&1
# Expected: admission webhook error citing immutability constraint
```

### TEST-SYS-03 — Append-Only Enforcement

```bash
# Confirm immutability constraint exists and is enforcing
kubectl get constraint gauntlet-proberesult-immutable -o yaml \
  | grep 'enforcementAction'
# Expected: enforcementAction: deny
```

### TEST-SYS-04 — NetworkPolicy Verification (Calico)

```bash
# Review the NetworkPolicy probe's most recent result
kubectl get gauntletproberesults -n gauntlet-system \
  --field-selector='spec.probe.type=netpol' \
  --sort-by=.metadata.creationTimestamp -o yaml | tail -30
# Expected: outcome: Pass (or Dropped), verificationMode: cni-verdict
```

### TEST-SYS-07 — Identity Separation

```bash
# Confirm Job-constraints enforcement
kubectl get constraint gauntlet-job-constraints -o yaml \
  | grep 'enforcementAction'
# Expected: enforcementAction: deny
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

# Export Gatekeeper audit violations for the assessment period
kubectl get constraint -o json \
  | jq '.items[].status.violations' \
  > gatekeeper-violations-$(date +%Y%m%d).json
```
