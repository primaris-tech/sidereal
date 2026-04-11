# System Architecture Diagram

**Purpose**: Illustrates the internal architecture of the Gauntlet operator —
component relationships, probe execution lifecycle, result storage tiers, and
the separation of identity between the controller and probe runners.

---

## Component Architecture

```mermaid
flowchart TB
    subgraph GAUNTLET ["Gauntlet System — gauntlet-system namespace"]
        direction TB

        subgraph CONTROLLER_BOX ["Controller Manager (Deployment — always running)"]
            direction LR
            SCHED["Probe\nScheduler"]
            RECONCILE["Result\nReconciler"]
            EXPORT["Audit Export\nPipeline"]
            BOOTSTRAP["Bootstrap\nVerifier"]
            ALERT["Alert\nManager"]
        end

        subgraph SA_BOX ["Per-Probe ServiceAccounts (pre-provisioned at install)"]
            direction LR
            SA_CTRL["gauntlet-controller\n(Job create/watch\nCRD read/write)"]
            SA_RBAC["gauntlet-probe-rbac\n(RBAC read + test operations)"]
            SA_NET["gauntlet-probe-netpol\n(NetworkPolicy read)"]
            SA_ADM["gauntlet-probe-admission\n(test resource create/delete)"]
            SA_SEC["gauntlet-probe-secret\n(Secret GET attempts)"]
            SA_DET["gauntlet-probe-detection\n(no API access)"]
        end

        subgraph JOBS_BOX ["Probe Runner Jobs (ephemeral — one per execution)"]
            direction LR
            J_RBAC["RBAC Job\n(Go)\n• Non-root\n• Read-only FS\n• Caps: DROP ALL"]
            J_NET["NetworkPolicy Job\n(Go)\n• Non-root\n• Read-only FS\n• Caps: DROP ALL"]
            J_ADM["Admission Job\n(Go)\n• Non-root\n• Read-only FS\n• Caps: DROP ALL"]
            J_SEC["Secret Access Job\n(Go)\n• Non-root\n• Read-only FS\n• Caps: DROP ALL"]
            J_DET["Detection Job\n(Rust/FIPS)\n• No network\n• No mounts\n• Custom seccomp"]
        end

        subgraph TIER1 ["Tier 1 — Operational (mutable)"]
            STATUS["GauntletProbe.status\n(last N results\nconsecutiveFailures)"]
        end

        subgraph TIER2 ["Tier 2 — Audit Log (append-only, admission-enforced)"]
            GPR["GauntletProbeResult\n• HMAC-verified\n• NIST control mapping\n• 365-day min TTL"]
            GI["GauntletIncident\n• Failure details\n• NIST controls\n• MITRE technique"]
            GSA["GauntletSystemAlert\n• Degraded state\n• Acknowledgment gate"]
            GAO["GauntletAOAuthorization\n• AO name + scope\n• Expiry window"]
        end

        subgraph ADMISSION_BOX ["Admission Controls (Admission Enforcement Policies)"]
            K1["Image signature\nrequired"]
            K2["ProbeResult\nappend-only"]
            K3["Job SA\nconstraints"]
            K4["No writable\nPVC mounts"]
        end

        BOOTSTRAP -->|"Checks prerequisites\nbefore scheduling"| SCHED
        SCHED -->|"Derives per-exec HMAC key\nCreates Job with SA token"| JOBS_BOX
        SA_CTRL -.->|"Identity used by"| CONTROLLER_BOX
        SA_RBAC -.->|"Identity used by"| J_RBAC
        SA_NET -.->|"Identity used by"| J_NET
        SA_ADM -.->|"Identity used by"| J_ADM
        SA_SEC -.->|"Identity used by"| J_SEC
        SA_DET -.->|"Identity used by"| J_DET

        JOBS_BOX -->|"Writes HMAC-signed\nresult ConfigMap"| RECONCILE
        RECONCILE -->|"Verifies HMAC\nTamperedResult if invalid"| RECONCILE
        RECONCILE -->|"Updates"| STATUS
        RECONCILE -->|"Creates (append-only)"| GPR
        RECONCILE -->|"Creates on failure"| GI
        ALERT -->|"Creates on degraded state"| GSA
        SCHED -->|"Reads authorization\nbefore detection probe"| GAO

        EXPORT -->|"Reads and exports\nto SIEM"| GPR
        EXPORT -->|"Reads and exports\nto SIEM"| GI

        ADMISSION_BOX -.->|"Enforces at admission\n(independent of controller)"| JOBS_BOX
        ADMISSION_BOX -.->|"Enforces append-only\nat admission"| TIER2
    end
```

---

## Probe Execution Lifecycle

```mermaid
sequenceDiagram
    participant SCHED as Probe Scheduler
    participant K8S as Kubernetes API
    participant ADMISSION as Admission Controller
    participant JOB as Probe Runner Job
    participant RECONCILE as Result Reconciler
    participant SIEM as SIEM Export

    SCHED->>SCHED: Schedule fires (±10% jitter)
    SCHED->>K8S: Derive per-execution HMAC key
    K8S-->>SCHED: HMAC Secret created

    SCHED->>K8S: Create Job (SA + HMAC Secret + fingerprint label)
    K8S->>ADMISSION: Admission request — verify cosign signature
    ADMISSION-->>K8S: Admitted (signature valid) OR Denied (invalid)
    Note over ADMISSION: Per deployment profile (e.g., Kyverno or OPA/Gatekeeper)
    K8S-->>SCHED: Job created

    JOB->>JOB: Execute probe action (bounded scope)
    JOB->>JOB: Sign result payload with HMAC key
    JOB->>K8S: Write signed result ConfigMap
    JOB->>JOB: Exit (container terminates)

    RECONCILE->>K8S: Read result ConfigMap
    RECONCILE->>RECONCILE: Verify HMAC signature

    alt Signature valid
        RECONCILE->>K8S: Create GauntletProbeResult (append-only)
        RECONCILE->>K8S: Delete result ConfigMap
        RECONCILE->>SIEM: Export ProbeResult record
    else Signature invalid
        RECONCILE->>K8S: Create GauntletProbeResult (TamperedResult outcome)
        RECONCILE->>K8S: Create GauntletSystemAlert (TamperedResult)
        RECONCILE->>SIEM: Export TamperedResult alert
        RECONCILE->>RECONCILE: Suspend probe surface pending acknowledgment
    end

    K8S->>K8S: TTL controller deletes Job + Pod (after ttlSecondsAfterFinished)
    K8S->>K8S: Delete per-execution HMAC Secret
```

---

## Two-Tier Result Storage

```mermaid
flowchart LR
    PROBE["Probe\nExecution"] --> RECONCILE["Result\nReconciler"]

    RECONCILE -->|"Mutable\nOperational view"| TIER1

    subgraph TIER1 ["Tier 1 — GauntletProbe.status"]
        OP1["lastExecutedAt"]
        OP2["lastOutcome"]
        OP3["consecutiveFailures"]
        OP4["last N results\n(configurable window)"]
    end

    RECONCILE -->|"Append-only\nAudit record\n(admission-enforced)"| TIER2

    subgraph TIER2 ["Tier 2 — GauntletProbeResult CR"]
        AU1["probeType + outcome"]
        AU2["probeStartTime / probeEndTime"]
        AU3["result.nistControls"]
        AU4["result.integrityStatus (HMAC)"]
        AU5["audit.exportStatus"]
        AU6["probe.id (fingerprint)"]
    end

    TIER2 -->|"TLS 1.2+ FIPS\nReal-time export"| SIEM

    subgraph SIEM ["Off-Cluster SIEM (authoritative long-term)"]
        S1["Splunk / Elasticsearch\n3-year retention"]
        S2["S3 + Object Lock COMPLIANCE\n3-year retention"]
    end

    style TIER1 fill:#e8f4f8,stroke:#2196F3
    style TIER2 fill:#e8f8e8,stroke:#4CAF50
    style SIEM fill:#fff3e0,stroke:#FF9800
```

---

## Role and Identity Separation

The following table documents the explicit separation between controller
and probe runner identities — a critical design property for AC-3, AC-6,
and CA-2 independence requirements.

| Identity | Can Do | Cannot Do |
|---|---|---|
| `gauntlet-controller` SA | Create Jobs; read/write CRDs; read HMAC Secret | Perform any probe operation; access target namespace resources |
| `gauntlet-probe-rbac` SA | RBAC test operations in target namespace | Access other namespaces; modify any resource |
| `gauntlet-probe-netpol` SA | Read NetworkPolicy objects | Any write; cross-namespace access |
| `gauntlet-probe-admission` SA | Create/delete test resources (specific types) | Access Secrets; persistent resource creation |
| `gauntlet-probe-secret` SA | Attempt GET on test Secret names | Write Secrets; cross-namespace read (expects 403) |
| `gauntlet-probe-detection` SA | None — no Kubernetes API access | Any Kubernetes API operation |

**Key property**: The controller cannot perform the operations the probes
perform. A compromised controller cannot produce a falsified probe result
through direct API access — it would need to compromise a probe runner Job
AND defeat HMAC verification.
