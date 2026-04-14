---
title: Introduction
description: What Sidereal is and what problem it solves
---

Sidereal is a Kubernetes-native operator for continuous security control validation on federal systems. It runs targeted, low-impact probes against a live cluster to verify that security controls are operationally effective, not merely configured.

## The problem

Federal systems running on Kubernetes face a gap that no existing open-source tool closes in a single, continuous operator.

**Configuration is not enforcement.** A NetworkPolicy can be defined and not enforcing. An admission webhook can be configured and silently disabled. A Falco rule can be deployed and suppressed by a config change. That drift is where real-world compromises happen and where ATO evidence goes stale.

This is not theoretical. See [The Configuration-Effectiveness Gap](/concepts/real-world-gaps/) for documented incidents where correctly configured controls failed operationally.

**The swivel chair.** Today, an ISSO validating Kubernetes security controls pivots between disconnected tools: Kubescape for posture, Falco dashboards for detection, the SIEM for audit records, manual crosswalks to NIST 800-53, hand-built reports, spreadsheet POA&Ms. Each tool covers one piece. None of them connect the pieces. The ISSO becomes the integration layer.

**Manual scans produce stale evidence.** A penetration test or quarterly assessment tells you what was true on one day. Sidereal runs on a configurable recurring schedule — the probe interval is operator-defined, the results are timestamped and HMAC-verified, and the audit log always reflects the most recent validation. The gap between probes is explicit and bounded, not unknown.

## What Sidereal does

Sidereal continuously probes your cluster's security controls, verifies they are working, and produces compliance evidence from a single tool:

- **Active probing**: fires real actions against real enforcement layers
- **Detection validation**: fires known-bad syscalls, independently confirms alerts were raised
- **Multi-framework mapping**: tags every result with all active compliance framework controls
- **Report generation**: continuous monitoring summaries, POA&M, coverage matrices, evidence packages
- **Graduated adoption**: `dryRun` to `observe` to `enforce`, so ISSOs can validate before activating incident pipelines

## Prerequisites

| Requirement | Minimum Version | Notes |
|---|---|---|
| Kubernetes cluster | 1.28+ | kind, minikube, or a real cluster |
| Helm | 3.12+ | |
| kubectl | 1.28+ | |
| Admission controller | Kyverno 1.11+ or Gatekeeper 3.14+ | Only needed for admission probes |
| Detection backend | Falco 0.37+ or Tetragon 1.0+ | Only needed for detection probes |

RBAC, Secret, and NetworkPolicy probes work on any Kubernetes cluster without additional tooling.
