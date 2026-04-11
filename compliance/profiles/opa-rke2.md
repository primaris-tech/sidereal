# Deployment Profile: opa-rke2

> **Note**: This is one of six pre-built deployment profiles shipped with Sidereal. See also: `kyverno-cilium-falco`, `opa-calico-tetragon`, `kyverno-eks`, `opa-aks`, `kyverno-gke`. Custom profiles are supported for agency-specific configurations.

**Profile ID**: `opa-rke2`
**Description**: Sidereal deployment profile for RKE2/k3s on-premises clusters with OPA/Gatekeeper admission control and Tetragon runtime detection.

---

## Capability Bindings

| Abstract Capability | Concrete Implementation | Version Constraint |
|---|---|---|
| Admission Enforcement | OPA/Gatekeeper | >= 3.14 |
| Image Signature Verification | Sigstore policy-controller | >= 0.6 |
| Detection Backend | Tetragon gRPC Event API | >= 1.0 |
| CNI Observability | None (Canal/Flannel — no native flow API) | — |
| SIEM Export | [Agency-configured: Splunk HEC, Elasticsearch, S3] | — |

## Helm Profile Configuration

```yaml
sidereal:
  profile:
    admissionController: opa
    signatureVerifier: policy-controller
    detectionBackend: tetragon
    cniObservability: none
    networkPolicyVerification: tcp-inference  # or responder
```

## Degraded Capabilities

| Capability | Impact | Mitigation |
|---|---|---|
| NetworkPolicy Verification | `tcp-inference` or `responder` mode instead of `cni-verdict` | RKE2 defaults to Canal (Flannel + Calico NetworkPolicy) and k3s defaults to Flannel. Neither exposes a flow-level observability API. Two fallback modes are available: `tcp-inference` validates enforcement by attempting connections and observing TCP RST/timeout behavior; `responder` deploys a Sidereal-managed responder pod to confirm or deny reachability. Choose `responder` when stricter validation is required or when TCP inference results are ambiguous due to network configuration. |

## Admission Policies Rendered

The Helm chart renders the following OPA/Gatekeeper resources for this profile:

| Resource | Abstract Capability | What It Enforces |
|---|---|---|
| `ConstraintTemplate: SiderealImageSignature` + `Constraint: sidereal-image-signature-required` | Image Signature Verification | cosign signature verification via Sigstore policy-controller webhook |
| `ConstraintTemplate: SiderealImmutableResult` + `Constraint: sidereal-proberesult-immutable` | Audit Record Immutability | Denies UPDATE and DELETE on `SiderealProbeResult` for all principals |
| `ConstraintTemplate: SiderealJobConstraints` + `Constraint: sidereal-job-constraints` | Job SA Constraints | Controller may only create Jobs referencing pre-approved probe ServiceAccounts |
| `ConstraintTemplate: SiderealNoWritablePVC` + `Constraint: sidereal-no-writable-pvc` | No Writable PVC | Denies writable PVC mounts on Pods in `sidereal-system` |
| `ConstraintTemplate: SiderealAdmissionProbe` + `Constraint: sidereal-admission-probe-target` | Admission Probe Default | Rejects resources with label `sidereal.cloud/admission-probe: "true"` |

## Connection Parameters

| System | Port | Protocol | Authentication |
|---|---|---|---|
| Kubernetes API Server (RKE2/k3s) | 6443/TCP | mTLS | ServiceAccount token (1hr bound expiry) |
| Tetragon gRPC | 54321/TCP | gRPC/TLS | mTLS, SAN validation |
| SIEM endpoints | [Agency-configured] | HTTPS/TLS 1.2+ FIPS | [Agency-configured] |

## Bootstrap Verification Checklist

For this profile, the bootstrap verifier checks:

1. Gatekeeper CRDs (`constrainttemplates.templates.gatekeeper.sh`) exist
2. All 5 ConstraintTemplates and their Constraints listed above are present with `enforcementAction: deny`
3. Sigstore policy-controller is running and its webhook is active
4. All 6 ServiceAccounts exist with expected RBAC bindings
5. Default-deny NetworkPolicy is in place in `sidereal-system`
6. HMAC root Secret is accessible
7. Tetragon gRPC endpoint is reachable on port 54321
8. NetworkPolicy verification mode is set to `tcp-inference` or `responder` (no CNI observability endpoint expected)

## SAP Test Commands

These are the profile-specific commands for the SAP test procedures. Replace the generic `[profile-specific]` placeholders in the SAP template with these commands.

### TEST-SYS-01 — Image Signature Verification

```bash
# Confirm Gatekeeper constraint exists and is enforcing
kubectl get constraint sidereal-image-signature-required -o yaml \
  | grep 'enforcementAction'
# Expected: enforcementAction: deny

# Confirm Sigstore policy-controller webhook is active
kubectl get validatingwebhookconfiguration | grep policy-controller
# Expected: policy-controller webhook listed

# Attempt unsigned image — confirm it is blocked
kubectl run test-unsigned --image=nginx:latest \
  --overrides='{"metadata":{"namespace":"sidereal-system"}}' \
  --dry-run=server 2>&1
# Expected: admission webhook error
```

### TEST-SYS-02 — HMAC Result Integrity

```bash
# Attempt to modify a SiderealProbeResult — confirm Gatekeeper blocks it
RESULT=$(kubectl get siderealproberesults -n sidereal-system -o name | head -1)
kubectl patch $RESULT -n sidereal-system \
  --type='merge' -p '{"spec":{"result":{"outcome":"Pass"}}}' \
  --dry-run=server 2>&1
# Expected: admission webhook error citing immutability constraint
```

### TEST-SYS-03 — Append-Only Enforcement

```bash
# Confirm immutability constraint exists and is enforcing
kubectl get constraint sidereal-proberesult-immutable -o yaml \
  | grep 'enforcementAction'
# Expected: enforcementAction: deny
```

### TEST-SYS-04 — NetworkPolicy Verification (tcp-inference / responder)

```bash
# Review the NetworkPolicy probe's most recent result
kubectl get siderealproberesults -n sidereal-system \
  --field-selector='spec.probe.type=netpol' \
  --sort-by=.metadata.creationTimestamp -o yaml | tail -30
# Expected: outcome: Pass (or Dropped), verificationMode: tcp-inference or responder
# Note: cni-verdict is not available on Canal/Flannel; tcp-inference or responder is the expected mode

# (If using responder mode) Verify responder pod is running
# kubectl get pods -n sidereal-system -l sidereal.cloud/component=netpol-responder
```

### TEST-SYS-07 — Identity Separation

```bash
# Confirm Job-constraints enforcement
kubectl get constraint sidereal-job-constraints -o yaml \
  | grep 'enforcementAction'
# Expected: enforcementAction: deny
```

## Evidence Collection

```bash
# Verify cosign signatures for all deployed images
kubectl get pods -n sidereal-system -o json \
  | jq -r '.items[].spec.containers[].image' | sort -u \
  | while read IMAGE; do
      echo "Verifying: $IMAGE"
      cosign verify \
        --certificate-identity-regexp 'https://github.com/primaris-tech/sidereal' \
        --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
        "$IMAGE" 2>&1 | grep -E 'Verification|Error'
    done

# Export Gatekeeper audit violations for the assessment period
kubectl get constraint -o json \
  | jq '.items[].status.violations' \
  > gatekeeper-violations-$(date +%Y%m%d).json
```
