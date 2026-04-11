# Data Flow Diagrams

**Purpose**: Documents the data flows between Gauntlet and each external system.
Each diagram shows what data flows, in which direction, and what security controls
protect the flow. Required for ATO boundary analysis and ISA/MOU documentation.

---

## DF-1: Probe Execution → Kubernetes API Server

The most frequent data flow. Every probe runner communicates exclusively with
the Kubernetes API server to execute its probe action and write its result.

```mermaid
flowchart LR
    subgraph GAUNTLET ["Gauntlet Authorization Boundary"]
        CTRL["Controller Manager\ngauntlet-controller SA"]
        JOB["Probe Runner Job\nprobe-specific SA\n(1-hr bound token)"]
        HMAC_SEC["Per-execution\nHMAC Secret\n(tmpfs mount)"]
    end

    subgraph K8S ["Kubernetes API Server (External)"]
        JOBS_API["Jobs API"]
        SECRETS_API["Secrets API"]
        CRD_API["CRD API\n(GauntletProbeResult\nGauntletIncident\netc.)"]
        RBAC_API["RBAC API\n(probe test target)"]
        AUDIT_LOG["Kubernetes\nAudit Log"]
    end

    CTRL -->|"CREATE Job\nmTLS · SA token\nFIPS cipher"| JOBS_API
    CTRL -->|"CREATE/DELETE\nHMAC Secret\nmTLS · SA token"| SECRETS_API
    CTRL -->|"CREATE/READ\nGauntletProbeResult\nmTLS · SA token"| CRD_API
    JOB -->|"Test operation\n(e.g., GET Secret — expects 403)\nmTLS · probe SA token"| RBAC_API
    JOB -->|"WRITE result ConfigMap\n(HMAC-signed payload)\nmTLS · probe SA token"| SECRETS_API
    CTRL -->|"READ result ConfigMap\nverify HMAC\nmTLS · SA token"| SECRETS_API

    JOBS_API -.->|"Audit event"| AUDIT_LOG
    SECRETS_API -.->|"Audit event"| AUDIT_LOG
    CRD_API -.->|"Audit event"| AUDIT_LOG
    RBAC_API -.->|"Audit event (incl. 403)"| AUDIT_LOG

    style HMAC_SEC fill:#fff3cd,stroke:#ffc107
```

**Data flowing across boundary:**

| Flow | Data | Direction | Protection |
|---|---|---|---|
| Job creation | Job spec (SA reference, HMAC Secret ref, labels) | Outbound | mTLS, RBAC |
| Probe test operation | API request (verb, resource, namespace) | Outbound | mTLS, probe SA token (1hr) |
| Result ConfigMap write | HMAC-signed probe result payload | Outbound | mTLS, HMAC |
| GauntletProbeResult create | Structured audit record | Outbound | mTLS, admission enforcement append-only |
| Kubernetes audit log | All API operations | Internal to K8s | K8s audit log controls |

---

## DF-2: Detection Probe → Detection Backends (e.g., Falco, Tetragon)

The most security-sensitive data flow. Two separate actions by two separate
identities — the probe emits a syscall pattern; the controller independently
queries whether it was detected.

```mermaid
flowchart TB
    subgraph GAUNTLET ["Gauntlet Authorization Boundary"]
        CTRL["Controller Manager"]
        DET_JOB["Detection Probe Runner\n(Rust / FIPS)\n• No network\n• Custom seccomp\n• No mounts"]
        GAO["GauntletAOAuthorization\n(required before execution)"]
    end

    subgraph CLUSTER ["Cluster Runtime (External to Gauntlet Boundary)"]
        KERNEL["Linux Kernel\n(syscall layer)"]
        DET_BACKEND_A["Detection Backend\n(profile A)\n(gRPC Output API)"]
        DET_BACKEND_B["Detection Backend\n(profile B)\n(gRPC Event API)"]
    end

    CTRL -->|"Checks expiry + scope\nbefore creating Job"| GAO
    CTRL -->|"Creates Job\n(AO-authorized technique only)"| DET_JOB
    DET_JOB -->|"Emits adversarial syscall pattern\n(AO-approved catalog entry)\nNo network I/O — syscall only"| KERNEL
    KERNEL -.->|"Syscall observed\n(async — kernel telemetry)"| DET_BACKEND_A
    KERNEL -.->|"Syscall observed\n(async — kernel telemetry)"| DET_BACKEND_B
    DET_BACKEND_A -->|"Alert carries probe-id label\n(Kubernetes pod metadata enrichment)"| DET_BACKEND_A
    DET_BACKEND_B -->|"Event carries probe-id label\n(Kubernetes pod metadata enrichment)"| DET_BACKEND_B

    CTRL -->|"Polls detection backend for alert matching probe-id\nmTLS · gRPC · FIPS\nSAN-validated server cert\n(60s window, 5s interval)"| DET_BACKEND_A
    CTRL -->|"Polls detection backend for event matching probe-id\nmTLS · gRPC · FIPS\nSAN-validated server cert\n(60s window, 5s interval)"| DET_BACKEND_B

    CTRL -->|"Records outcome:\nDetected / Undetected / Blocked / BackendUnreachable"| CTRL

    style DET_JOB fill:#ffecec,stroke:#f44336
    style GAO fill:#e8f5e9,stroke:#4CAF50
```

**Key design property**: The detection probe runner has **no network access**.
It cannot communicate with the detection backends or the controller. The controller
independently queries the detection backends (e.g., Falco, Tetragon) after the probe completes —
two separate identities, two separate actions, independent of each other.

**Data flowing across boundary:**

| Flow | Data | Direction | Protection |
|---|---|---|---|
| Detection backend query (e.g., Falco) | `QueryAlerts(probeID, window)` gRPC call | Outbound | mTLS, SAN validation, FIPS |
| Detection backend response (e.g., Falco) | Alert records with pod metadata | Inbound | mTLS, TLS record layer |
| Detection backend query (e.g., Tetragon) | `GetEventsStream(probeID, window)` gRPC call | Outbound | mTLS, SAN validation, FIPS |
| Detection backend response (e.g., Tetragon) | Event records with pod metadata | Inbound | mTLS, TLS record layer |

**Outcomes and responses:**

| Outcome | Meaning | GauntletIncident? |
|---|---|---|
| `Detected` | Alert raised within 60s window | No (pass) |
| `Undetected` | No alert within 60s window | Yes — detection gap |
| `Blocked` | Syscall blocked by detection backend enforcement mode (e.g., Tetragon) | No (pass — enforcement active) |
| `BackendUnreachable` | gRPC query failed | GauntletSystemAlert |

---

## DF-3: NetworkPolicy Probe → CNI Observability Backends (e.g., Hubble, Calico)

The NetworkPolicy probe reads enforcement verdicts directly from the CNI
observability layer — the authoritative source of what the enforcement plane
decided — rather than inferring from TCP behavior.

```mermaid
flowchart LR
    subgraph GAUNTLET ["Gauntlet Authorization Boundary"]
        CTRL["Controller Manager"]
        NET_JOB["NetworkPolicy Probe Runner\n(Go)\nprobe-id label applied"]
    end

    subgraph CLUSTER ["Cluster Network (External to Gauntlet Boundary)"]
        CNI_ENFORCE["CNI Enforcement Plane\n(Cilium / Calico)"]
        TARGET_SVC["Target ClusterIP\n(probe destination)"]

        subgraph CNI_OBS_A ["CNI Observability Layer\n(profile A, e.g., Hubble)"]
            CNI_OBS_API_A["CNI Observability API\n(gRPC)"]
            CNI_OBS_FLOWS_A["Flow records\n(includes pod labels)"]
        end

        subgraph CNI_OBS_B ["CNI Observability Layer\n(profile B, e.g., Calico)"]
            CNI_OBS_API_B["CNI Observability API\n(REST)"]
            CNI_OBS_FLOWS_B["Flow log records\n(includes pod labels)"]
        end
    end

    NET_JOB -->|"TCP SYN to target ClusterIP\n(probe-id label on pod)\nReal packet — real policy decision"| TARGET_SVC
    CNI_ENFORCE -->|"Policy decision:\nDropped OR Forwarded"| TARGET_SVC
    CNI_ENFORCE -->|"Emits flow record\nwith pod label metadata"| CNI_OBS_FLOWS_A
    CNI_ENFORCE -->|"Emits flow record\nwith pod label metadata"| CNI_OBS_FLOWS_B

    CTRL -->|"CNI observability query\nQueryFlowVerdict(probeID, window)\nmTLS · gRPC · FIPS\nSAN-validated cert"| CNI_OBS_API_A
    CNI_OBS_API_A -->|"Flow record matching probe-id:\nverdict = Dropped OR Forwarded"| CTRL

    CTRL -->|"CNI observability query\nQueryFlowVerdict(probeID, window)\nmTLS · REST · FIPS\nSAN-validated cert"| CNI_OBS_API_B
    CNI_OBS_API_B -->|"Flow record matching probe-id:\nverdict = Dropped OR Forwarded"| CTRL

    style CNI_ENFORCE fill:#e3f2fd,stroke:#2196F3
```

**Why CNI verdict, not TCP response:**
Reading from the CNI observability API eliminates false negatives from
application-layer responses. A TCP RST from the destination could indicate
either a NetworkPolicy drop or an application rejection — ambiguous. The
CNI flow verdict is unambiguous: it is the enforcement decision.

**Data flowing across boundary:**

| Flow | Data | Direction | Protection |
|---|---|---|---|
| CNI observability flow verdict query (e.g., Hubble) | `GetFlows(filter: probe-id label)` gRPC | Outbound | mTLS, SAN validation, FIPS |
| CNI observability flow verdict response (e.g., Hubble) | Flow records (src, dst, protocol, verdict, pod labels) | Inbound | mTLS, TLS record layer |
| CNI observability flow verdict query (e.g., Calico) | REST query (filter: probe-id label) | Outbound | mTLS, SAN validation, FIPS |
| CNI observability flow verdict response (e.g., Calico) | Flow log entries (src, dst, protocol, action, labels) | Inbound | mTLS, TLS record layer |

---

## DF-4: Audit Export → SIEM Targets

All `GauntletProbeResult` and `GauntletIncident` records are exported to
the configured SIEM immediately on creation. SIEM export is a first-class
feature — it is not optional for federal deployments.

```mermaid
flowchart TB
    subgraph GAUNTLET ["Gauntlet Authorization Boundary"]
        GPR_STORE["GauntletProbeResult\n(in-cluster, append-only)"]
        GI_STORE["GauntletIncident\n(in-cluster, append-only)"]
        EXPORT["Audit Export Pipeline\n• Exponential backoff retry\n• Bounded in-memory buffer\n• Fail-closed option"]
    end

    GPR_STORE -->|"Read on creation"| EXPORT
    GI_STORE -->|"Read on creation"| EXPORT

    subgraph SPLUNK_TARGET ["Splunk HEC (External)"]
        SPLUNK["Splunk HTTP Event\nCollector"]
        SPLUNK_IDX["Splunk Index\n(3-year retention)"]
    end

    subgraph ELASTIC_TARGET ["Elasticsearch (External)"]
        ELASTIC["Elasticsearch\nIngest API"]
        ELASTIC_IDX["Elasticsearch Index\n(3-year retention)"]
    end

    subgraph S3_TARGET ["Amazon S3 (External)"]
        S3_API["S3 PutObject API"]
        S3_BUCKET["S3 Bucket\n• SSE-KMS (FIPS key)\n• Object Lock COMPLIANCE\n• 3-year retention"]
    end

    EXPORT -->|"HTTPS · TLS 1.2+ FIPS\nHEC token (Secret ref)\nFailed: retry + metric"| SPLUNK
    SPLUNK --> SPLUNK_IDX

    EXPORT -->|"HTTPS · TLS 1.2+ FIPS\nAPI key (Secret ref)\nFailed: retry + metric"| ELASTIC
    ELASTIC --> ELASTIC_IDX

    EXPORT -->|"HTTPS · TLS 1.2+ FIPS\nAWS SigV4\nFailed: retry + metric"| S3_API
    S3_API --> S3_BUCKET

    subgraph FAILURE ["Export Failure Response"]
        F1["gauntlet_siem_export_failures_total\n(Prometheus metric)"]
        F2["GauntletSystemAlert\nreason: SIEMExportDegraded"]
        F3["Probe scheduling halted\n(if failClosedOnExportFailure: true)"]
    end

    EXPORT -.->|"On consecutive failure"| FAILURE

    style S3_BUCKET fill:#fff3e0,stroke:#FF9800
    style FAILURE fill:#ffebee,stroke:#f44336
```

**Audit record fields exported to SIEM:**

| Field | Value | Purpose |
|---|---|---|
| `probe.type` | `rbac`, `netpol`, `admission`, `secret`, `detection` | Filter by control surface |
| `result.outcome` | `Pass`, `Fail`, `Undetected`, etc. | Gap identification |
| `execution.timestamp` | RFC 3339 UTC, nanosecond precision | Timeline reconstruction |
| `result.nistControls` | `["AC-3", "AC-6"]` etc. | Control-specific reporting |
| `result.integrityStatus` | `Verified` / `TamperedResult` | Integrity assurance |
| `probe.targetNamespace` | `production` (or redacted ID) | Scope identification |
| `probe.id` | UUID | Correlation key |
| `audit.exportStatus` | `Exported` / `Pending` / `Failed` | Delivery confirmation |

**Data flowing across boundary:**

| Flow | Data | Direction | Protection |
|---|---|---|---|
| Probe result export (Splunk) | Structured JSON audit record | Outbound | TLS 1.2+ FIPS, HEC token |
| Probe result export (Elasticsearch) | Structured JSON audit record | Outbound | TLS 1.2+ FIPS, API key |
| Probe result export (S3) | Structured JSON audit record | Outbound | TLS 1.2+ FIPS, SigV4, SSE-KMS |
| Export acknowledgment | Delivery confirmation (token / `_id` / ETag) | Inbound | TLS record layer |

---

## Summary — All Data Flows

| Flow ID | Source | Destination | Data Classification | ISA Required |
|---|---|---|---|---|
| DF-1 | Controller / Probe Jobs | Kubernetes API | System operations + audit | No (same infrastructure) |
| DF-2 | Controller | Detection backends (e.g., Falco, Tetragon) | Detection query (no PII) | Yes (if separate org) |
| DF-3 | Controller | CNI observability backends (e.g., Hubble, Calico) | Flow verdict query (no PII) | Yes (if separate org) |
| DF-4 | Controller | Splunk / Elasticsearch / S3 | Audit records (potentially PII — see PIA) | Yes |

*[Agency: Complete the ISA Required column with actual agreement references.]*
