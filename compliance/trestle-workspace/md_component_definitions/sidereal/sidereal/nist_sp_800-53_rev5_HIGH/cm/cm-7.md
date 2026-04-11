---
x-trestle-comp-def-rules:
  sidereal:
    - name: no-debug-endpoints-no-shell-in-probe-runners
      description: Sidereal probe runner images contain no shell, no debug endpoints, and no package manager; only the compiled Rust binary and its minimal runtime dependencies are present
x-trestle-global:
  profile:
    title: NIST SP 800-53 Rev 5 High Baseline
    href: trestle://profiles/nist_sp_800-53_rev5_HIGH/profile.json
  sort-id: cm-07
status: implemented
---

# CM-7 — Least Functionality

## Control Statement

Configure the system to provide only essential capabilities, prohibiting or
restricting functions, ports, protocols, and services not required by the
mission or operational requirements. Disable or remove unused functionality.

## Sidereal Implementation

Least functionality is enforced at every layer of the Sidereal stack: container
image composition, process execution posture, network egress, and controller
runtime configuration. Each layer is independently verifiable.

### Layer 1: Container Image Composition

Rust probe runner container images are built from a distroless or scratch base
containing only:
- The statically compiled Rust binary
- The FIPS-validated `aws-lc-rs` shared library (when FIPS mode enabled)
- No shell (`sh`, `bash`, `dash`)
- No package manager (`apt`, `apk`, `yum`)
- No curl, wget, or network diagnostic tooling
- No debug tooling (gdb, strace, ltrace)
- No interpreters (Python, Perl, Node.js)

The absence of a shell is the most consequential least-functionality
control for container security. Without a shell, an attacker who achieves
code execution in a probe runner container cannot spawn interactive commands,
pivot to other hosts, or exfiltrate data interactively — the container is a
dead end beyond its single compiled binary.

The Go controller image is built from a minimal base with the same
prohibitions. The Go runtime does not require a shell for operation.

### Layer 2: Disabled Debug Endpoints

The controller's HTTP server exposes only the endpoints required for
operation:

- `/healthz` — liveness probe (required for Kubernetes scheduling)
- `/readyz` — readiness probe (required for Kubernetes scheduling)
- `/metrics` — Prometheus scrape endpoint (required for monitoring)

Disabled in production release builds via Go build tags:
- `/debug/pprof` — profiling endpoint (disabled; would expose memory layout)
- `/debug/vars` — runtime variable endpoint (disabled)
- Kubernetes leader election debug handler (disabled)

The metrics endpoint is restricted by NetworkPolicy to scrape from the
Prometheus ServiceAccount only. It is not exposed externally.

### Layer 3: NetworkPolicy Egress Restrictions

A `NetworkPolicy` for the `sidereal-system` namespace restricts egress to
only the specific ports and protocols required for each component:

| Component | Permitted Egress |
|---|---|
| Controller | Port 443 to Kubernetes API server |
| Controller | Configured SIEM endpoint port (443 or 9200) |
| Controller | Port 50051 to detection backend gRPC API (e.g., Falco) (when detection probe enabled) |
| Controller | Port 4240 to CNI observability API (e.g., Hubble) (when NetworkPolicy probe enabled) |
| RBAC probe runner | Port 443 to Kubernetes API server only |
| NetworkPolicy probe runner | Probe target ports only (no internet egress) |
| Admission Control probe runner | Port 443 to Kubernetes API server only |
| Secret Access probe runner | Port 443 to Kubernetes API server only |
| Detection Coverage probe runner | No network (seccomp enforcement only) |

Any egress not explicitly permitted by these policies is blocked at the CNI
layer. The NetworkPolicy probe surface continuously verifies that these
egress restrictions are enforced (a SiderealProbeResult documents each
verification), providing ongoing evidence that least functionality is
maintained at the network layer.

### Layer 4: Pod Security Posture

Every Sidereal probe runner Job enforces:
- `runAsNonRoot: true` — no root execution
- `readOnlyRootFilesystem: true` — no runtime filesystem modification
- `allowPrivilegeEscalation: false` — no setuid/setgid elevation
- All Linux capabilities dropped (`drop: [ALL]`)
- Seccomp profile applied (probe runner-specific allow-list)
- No volume mounts beyond the HMAC key Secret (read-only, mounted as
  tmpfs, injected per execution)

The controller holds no probe-class permissions. It can create Jobs but
cannot perform the operations those Jobs perform.

### Enhancement: CM-7(1) — Periodic Review

The Sidereal SBOM (CM-8) is reviewed on every release to confirm that no
new capabilities, shells, or debug tools have been introduced into probe
runner images. The CI pipeline enforces this review as part of the image
build process — a new shell binary appearing in the container layer would
be visible in the SBOM diff and would require explicit review.

### Enhancement: CM-7(2) — Prevent Program Execution

The detection probe runner container operates with a seccomp profile that
allows only the minimal syscall set required for:
1. Emitting the targeted synthetic syscall pattern
2. Writing the HMAC-signed result to the result ConfigMap

All other syscalls are blocked at the kernel level. The container cannot
execute arbitrary programs, spawn subprocesses, or perform network I/O.

### Enhancement: CM-7(5) — Authorized Software / Whitelisting

The cosign image signing and admission enforcement policy (CM-14) constitute a
software whitelist: only images signed by the Sidereal release key are
admitted into the `sidereal-system` namespace. No unsigned or externally
sourced image can run as a Sidereal component, preventing unauthorized
software from executing under the Sidereal identity.

## Evidence Produced

- Container image SBOM listing only the declared runtime components
  (verifiable via `cosign verify-attestation --type cyclonedx`)
- `SiderealProbeResult` CRs from the NetworkPolicy probe confirming that
  unexpected egress paths are blocked (continuous verification)
- Pod Security Admission logs confirming probe runner security context
  enforcement
- Admission policy events for any image admission attempt

## Customer Responsibility

The deploying agency must:
1. Not add sidecar containers or additional init containers to
   `sidereal-system` Pods that introduce shell access, debug functionality,
   or network connectivity not present in the baseline deployment
2. Review the SBOM for each Sidereal release to confirm that no new
   capabilities have been introduced without authorization
3. Not create exceptions to the `sidereal-system` NetworkPolicy without
   AO authorization and documented security impact analysis
4. Apply the Kubernetes Pod Security admission policy at `restricted` level
   for the `sidereal-system` namespace
