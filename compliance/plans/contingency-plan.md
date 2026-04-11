# Gauntlet Contingency Plan

**Document Type**: Supporting Plan — NIST 800-53 CP Family  
**Baseline**: NIST SP 800-53 Rev 5 High  
**Status**: Draft — Agency Customization Required  

---

## 1. Purpose and Scope

This Contingency Plan defines the procedures for maintaining, recovering, and
reconstituting the Gauntlet continuous monitoring operator in the event of
disruption. Gauntlet is a security control — its unavailability halts ATO
evidence generation and creates a documented gap in the continuous monitoring
record.

This plan covers the Gauntlet software components, their configuration, and
the CRD resources they depend on. Infrastructure-level contingency planning
(Kubernetes cluster recovery, etcd backup, node replacement) is the deploying
agency's responsibility and must be documented in the agency's organization-wide
Contingency Plan.

---

## 2. System Description

Gauntlet consists of the following recoverable components:

| Component | Type | Recovery Priority |
|---|---|---|
| Controller Manager | Kubernetes Deployment | P1 — required for all operations |
| `GauntletProbe` CRDs | Kubernetes custom resources | P1 — defines probe configuration |
| `GauntletProbeResult` CRDs | Kubernetes custom resources | P2 — audit records (SIEM is authoritative) |
| Helm release configuration | Kubernetes Secret + GitOps repo | P1 — required to recover controller |
| HMAC root Secret | Kubernetes Secret | P1 — required for result integrity |
| Admission enforcement policies | Kubernetes custom resources | P1 — blast radius controls (e.g., Kyverno or OPA/Gatekeeper) |
| SIEM export records | External SIEM | P1 — authoritative audit record |

---

## 3. Recovery Objectives

| Objective | Target | Rationale |
|---|---|---|
| Recovery Time Objective (RTO) | 4 hours | Monitoring continuity gaps beyond 4 hours require documentation in the continuous monitoring report |
| Recovery Point Objective (RPO) | Last successful GitOps sync + last Velero backup | Configuration is in version control; audit records are in SIEM |
| Maximum Tolerable Downtime | 8 hours | After 8 hours, a POA&M entry is required for the monitoring gap |

*[Agency: Adjust RTO/RPO targets to align with your organization's ISCM requirements.]*

---

## 4. Backup Procedures

### 4.1 Configuration Backup (RPO: Continuous)

The Gauntlet Helm chart `values-override.yaml` is stored in the agency's
GitOps repository. This constitutes the configuration backup. Every commit
to the GitOps repository is a versioned configuration backup with full
history. No additional backup step is required for configuration.

**Verification**: The GitOps repository must be accessible from the recovery
environment. Confirm repository accessibility as part of the monthly
contingency test.

### 4.2 GauntletProbe Resource Backup (RPO: 24 hours)

`GauntletProbe` resources define probe configuration and cannot be reconstructed
from the Helm chart alone (they contain site-specific probe definitions). These
must be backed up separately.

**Backup command:**
```bash
kubectl get gauntletprobes -n gauntlet-system -o yaml > \
  gauntlet-probes-backup-$(date +%Y%m%d).yaml
```

Back up to the agency's designated backup storage (S3, Velero, or equivalent).
Retention: minimum 90 days.

**Automated backup via Velero:**
```yaml
# velero-gauntlet-schedule.yaml
apiVersion: velero.io/v1
kind: Schedule
metadata:
  name: gauntlet-daily
  namespace: velero
spec:
  schedule: "0 2 * * *"   # 02:00 UTC daily
  template:
    includedNamespaces:
      - gauntlet-system
    includedResources:
      - gauntletprobes
      - gauntletsystemalerts
    storageLocation: default
    ttl: 2160h   # 90 days
```

### 4.3 Audit Record Backup (Continuous)

`GauntletProbeResult` CRs are continuously exported to the SIEM. The SIEM
is the authoritative long-term backup for audit records. In-cluster CRDs are
the resilient short-term copy.

In-cluster records do not need to be separately backed up beyond the SIEM
export — the SIEM holds the authoritative copy. However, if SIEM export has
been degraded, in-cluster records must be backed up before cluster recovery
procedures are initiated.

**Pre-recovery audit record capture (if SIEM export was degraded):**
```bash
kubectl get gauntletproberesults -n gauntlet-system -o json > \
  audit-records-pre-recovery-$(date +%Y%m%d-%H%M).json
# Upload to SIEM manually or to S3 backup bucket
```

### 4.4 HMAC Secret Backup

The HMAC root Secret is critical — without it, the controller cannot sign
new probe results and will fail integrity verification. It is backed up as
part of the `gauntlet-system` namespace Velero backup.

For KMS-encrypted HMAC secrets (recommended for IL4/IL5), the KMS key
provides its own HA and backup guarantee. Confirm KMS key availability
is included in the agency's KMS recovery procedures.

---

## 5. Recovery Procedures

### 5.1 Controller Recovery (RTO: 1 hour)

The controller is a Kubernetes Deployment. For controller failures (crash,
node failure, OOMKill):

1. Kubernetes automatically restarts the controller via the Deployment
   controller (no manual intervention required for transient failures)
2. If the node is lost, Kubernetes reschedules the Pod on an available node
3. On startup, the controller performs bootstrap verification checks before
   resuming probe scheduling
4. Verify recovery: `kubectl get pods -n gauntlet-system`

For persistent failures, investigate controller logs before escalating:
```bash
kubectl logs -n gauntlet-system deployment/gauntlet-controller-manager --previous
```

### 5.2 Full Cluster Recovery (RTO: 4 hours)

In the event the Kubernetes cluster is lost or Gauntlet must be redeployed
to a new cluster:

**Step 1: Restore prerequisites** (30 minutes)
- Verify admission controller (e.g., Kyverno or OPA/Gatekeeper) is deployed and operational
- Verify CNI with NetworkPolicy enforcement is active
- Verify detection backend (e.g., Falco, Tetragon) is operational
- Verify SIEM endpoint is reachable

**Step 2: Deploy Gauntlet** (15 minutes)
```bash
# Pull Helm chart at the pinned version
helm repo add gauntlet https://charts.gauntlet.io
helm repo update

# Deploy from GitOps repository values
helm install gauntlet gauntlet/gauntlet \
  --version <chart-version> \
  --namespace gauntlet-system \
  --create-namespace \
  --values values-override.yaml
```

**Step 3: Restore GauntletProbe resources** (15 minutes)
```bash
# From Velero backup
velero restore create --from-backup gauntlet-daily-<date> \
  --include-namespaces gauntlet-system \
  --include-resources gauntletprobes

# Or from manual backup
kubectl apply -f gauntlet-probes-backup-<date>.yaml
```

**Step 4: Verify bootstrap checks pass** (15 minutes)
```bash
kubectl get gauntletsystemalerts -n gauntlet-system
# Should be empty after successful bootstrap
kubectl describe deployment gauntlet-controller-manager -n gauntlet-system
# DegradedMode condition should be False
```

**Step 5: Confirm probe execution resumes** (up to 6 hours for High impact)
```bash
kubectl get gauntletproberesults -n gauntlet-system \
  --sort-by='.metadata.creationTimestamp' | tail -5
```

**Step 6: Document the outage**
- Record outage start and end times
- Calculate duration per probe surface
- Submit monitoring gap documentation per Section 6

### 5.3 Partial Degradation Recovery

For scenarios where some probe surfaces are degraded but not all (e.g.,
detection backend unavailable):

1. `GauntletSystemAlert` with `reason: SecurityFunctionUnavailable` is
   created automatically
2. Restore the unavailable security function (detection backend, CNI observability layer, etc.)
3. Acknowledge the `GauntletSystemAlert` after confirming the function is
   restored:
   ```bash
   kubectl annotate gauntletsystemalert <name> -n gauntlet-system \
     gauntlet.io/acknowledged-by="firstname.lastname@agency.gov" \
     gauntlet.io/acknowledgment-notes="Detection backend DaemonSet restarted; verified operational"
   ```
4. Probe execution on the affected surface resumes automatically

---

## 6. Monitoring Gap Documentation

Any Gauntlet outage that results in a gap in continuous monitoring evidence
must be documented. A monitoring gap occurs when probe executions are not
completing on schedule (High: every 6 hours; Moderate: every 24 hours).

**Documentation required:**
- Outage start time (UTC)
- Outage end time (UTC)
- Duration per probe surface
- Root cause
- Whether any `GauntletIncident` records were generated during the gap
  (i.e., was monitoring partially functional)
- Remediation actions taken
- Whether a POA&M entry is required (outages > 8 hours)

**Where to document:**
- Continuous monitoring report (monthly)
- POA&M (if outage exceeds maximum tolerable downtime)
- SSP CA-7 notes section for extended outages

*[Agency: Define the specific document and record-keeping location here.]*

---

## 7. Testing

The contingency plan must be tested on the following schedule:

| Test Type | Frequency | Scope |
|---|---|---|
| Tabletop exercise | Annual | Full recovery procedure walkthrough |
| Backup verification | Monthly | Confirm GauntletProbe backup is restorable |
| GitOps recovery drill | Semi-annual | Deploy from GitOps values to a test environment |
| Full recovery exercise | Annual | Complete cluster recovery per Section 5.2 |

Test results must be documented and retained per AU-11 requirements.

*[Agency: Schedule tests and assign responsible personnel here.]*

---

## 8. Roles and Responsibilities

| Role | Contingency Responsibility |
|---|---|
| System Administrator | Execute recovery procedures; perform backup verification |
| ISSO | Declare contingency activation; authorize emergency changes during recovery; document monitoring gaps |
| Authorizing Official | Notified of outages exceeding RTO; approves POA&M entries for monitoring gaps |

*[Agency: Map to named individuals and provide after-hours contact information.]*

---

## 9. Related Controls

- **CP-2** Contingency Plan — this document
- **CP-4** Contingency Plan Testing — Section 7 of this plan
- **CP-9** System Backup — Section 4 of this plan
- **CP-10** System Recovery and Reconstitution — Section 5 of this plan
- **CA-7** Continuous Monitoring — monitoring gap documentation
- **AU-11** Audit Record Retention — SIEM as authoritative backup
