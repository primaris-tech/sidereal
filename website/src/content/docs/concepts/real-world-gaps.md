---
title: The Configuration-Effectiveness Gap
description: Real documented incidents where Kubernetes security controls were correctly configured but failed to prevent an attack.
---

Security tools report on configuration. Sidereal validates operational effectiveness. The gap between those two things is documented, recurring, and exploitable.

Each incident below is drawn from public CVE disclosures, security research, or published post-mortems. In every case, the relevant control existed and appeared correct. The failure happened anyway.

---

## Admission Control

### CVE-2023-34091 — Kyverno policy bypass via Kubernetes finalizers

**Control in place:** Kyverno `validate`, `generate`, and `mutate-existing` policies with `validationFailureAction: Enforce`.

**What happened:** In Kyverno versions prior to 1.10.0, any resource with a `deletionTimestamp` field set was excluded from policy validation — an intentional design choice to reduce processing load on objects being deleted. An attacker with create and update permissions could add a Kubernetes finalizer to a resource, causing the API server to set `deletionTimestamp` without completing the deletion. The resource then persisted in a permanently policy-bypassed state, exempted from every Kyverno policy for its lifetime.

This affected Services, ConfigMaps, Secrets, and all Custom Resource types. The bypass required no special privileges beyond what a typical developer or namespace-scoped service account holds.

Source: [CVE-2023-34091](https://github.com/advisories/GHSA-hq4m-4948-64cc) (CVSS 8.8, patched in Kyverno 1.10.0); [technical analysis by Defense Unicorns](https://medium.com/defense-unicorns/kyverno-cve-2023-34091-bypassing-policies-using-kubernetes-finalizers-14e51843016e) (June 2023).

**What Sidereal catches:** The admission probe fires test actions against the live enforcement layer, not the policy object. A resource in a bypassed state causes the probe to return `Ineffective` regardless of what the policy configuration says.

---

### OPA Gatekeeper — image registry policy bypass via prefix matching

**Control in place:** OPA Gatekeeper admission policy using the `k8sallowedrepos` constraint template, intended to restrict container images to approved registries.

**What happened:** When the allowed registry was specified without a trailing slash — `myregistry.io` instead of `myregistry.io/` — the policy performed a plain prefix match on the image string. An attacker could pull images from `myregistry.io.attacker.com` and satisfy the match. Aqua Security found this flaw in widely deployed Gatekeeper templates, including templates shipped by major cloud providers as pre-built policy examples.

Source: [Aqua Security](https://www.aquasec.com/blog/risks-misconfigured-kubernetes-policy-engines-opa-gatekeeper/) (February 2025). The same post benchmarks Kyverno and Kubewarden against identical bypasses.

**What Sidereal catches:** The admission probe fires test actions using images from disallowed registries and verifies they are denied. A policy with a broken match condition returns `Ineffective` the same way a missing policy does — the test action succeeds when it should not.

---

### Webhook `failurePolicy: Ignore` — fail-open when the policy engine is unavailable

**Control in place:** Validating or mutating admission webhooks enforcing image signature verification, privileged container restrictions, or registry allowlists.

**What happened:** When configured with `failurePolicy: Ignore`, any outage of the webhook service causes the Kubernetes API server to admit all requests unconditionally. The policies have not changed and no alert is raised. The enforcement gap begins the moment the webhook becomes unavailable and lasts until it recovers.

This has historically been a common default in Kyverno and OPA/Gatekeeper deployments, particularly in older versions and tutorial configurations. Operators often set it explicitly to avoid blocking cluster operations during webhook outages — a reasonable tradeoff with real security consequences. Current Kyverno versions have moved away from `Ignore` as a default, but many production deployments retain it either through legacy configuration or deliberate choice.

The attack path is direct: cause the webhook to become unavailable, then deploy the workload that policy was preventing.

Source: [Kyverno GitHub Issue #1983](https://github.com/kyverno/kyverno/issues/1983) (documenting the `failurePolicy: Ignore` default and request for hardening guidance); [Cisco Tech Blog — "The dark side of Kubernetes admission webhooks"](https://staging.ciscotechblog.com/blog/dark-side-of-kubernetes-admission-webhooks/).

**What Sidereal catches:** The admission probe runs on a continuous schedule against the live enforcement layer. If the webhook is down, the probe's test action succeeds when it should be denied — surfacing the bypass window as an `Ineffective` result before an attacker finds it.

---

### CVE-2021-25741 — runtime symlink race bypasses hostPath restrictions (a class of problem, not a current vulnerability)

CVE-2021-25741 is patched. It is included here because it illustrates a class of failure that admission control cannot address: runtime behavior on the node that occurs after a pod has been admitted.

**Control in place:** PodSecurityPolicy or OPA/Gatekeeper policies blocking `hostPath` volume mounts, correctly configured and enforcing.

**What happened:** A TOCTOU (time-of-check-time-of-use) race condition in the kubelet's handling of `subPath` volume mounts allowed a container to swap a symlink after the pod was admitted. The kubelet followed the swapped symlink at runtime, giving the container access to arbitrary host paths. Admission control evaluated a legitimate pod spec and passed it. The exposure happened on the node, after admission was complete.

The broader lesson: admission control evaluates the pod spec at scheduling time. It has no visibility into what happens on the node at runtime. This gap persists regardless of how well-configured the admission layer is.

Source: [CVE-2021-25741](https://nvd.nist.gov/vuln/detail/CVE-2021-25741); Lightspin Research technical writeup (2021).

**What Sidereal catches:** Nothing, for this specific vulnerability. It is a kernel-level race condition that occurs after admission has finished, and no probe-based tool observes it. This example is included because it illustrates a hard limit of admission control as a category: it evaluates the pod spec at scheduling time and has no visibility into what happens on the node afterward. Sidereal validates the admission layer; complementary node-level hardening and runtime security controls are required for the layer below it.

---

## Network Policy

### EKS VPC CNI — NetworkPolicies accepted, nothing enforced

**Control in place:** NetworkPolicy objects applied to Amazon EKS clusters using the default VPC CNI plugin, with the intent of isolating workloads.

**What happened:** Until Amazon added native NetworkPolicy support in October 2023, the default VPC CNI plugin for EKS did not enforce Kubernetes NetworkPolicy at all. The Kubernetes API server accepted and stored every policy. `kubectl apply` returned success. Configuration scanners reported the policies as present. Traffic between pods was never filtered. Any team applying NetworkPolicies to an EKS cluster before this date — without explicitly choosing a CNI plugin that supported enforcement — had policies that were complete no-ops.

This is not an EKS-specific bug; it reflects the structural design of Kubernetes networking. The API spec states that creating a NetworkPolicy without a controller that implements it has no effect. The problem is that nothing in the API surface communicates whether enforcement is actually occurring.

Source: [Kubernetes documentation — Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/); [AWS EKS native network policy announcement](https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy-configure.html) (October 2023).

**What Sidereal catches:** The network policy probe attempts a connection that an active policy should block and checks the actual packet verdict. Whether the CNI enforces policies is irrelevant to how the question is asked.

---

### Flannel — NetworkPolicies are silently ignored

**Control in place:** NetworkPolicy objects defined and deployed. Teams believed inter-pod traffic was isolated.

**What happened:** Flannel does not implement NetworkPolicy enforcement. Every policy applied to a Flannel-backed cluster is ignored entirely — accepted by the API, stored in etcd, and never acted on. This is documented in the Flannel project but consistently missed at cluster setup time. Configuration scanners that check for the presence of NetworkPolicy objects will report the cluster as compliant.

Source: [Flannel project documentation](https://github.com/flannel-io/flannel); [Kubernetes networking documentation](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

**What Sidereal catches:** The network policy probe attempts a connection that a correctly enforcing policy should block and checks the actual result. A CNI that ignores all policies produces the same probe outcome as having no policies at all — `Ineffective` — regardless of how many objects exist in etcd.

---

### Tesla (2018) — no default-deny, cryptominer reaches AWS IMDS

**Control in place:** AWS IAM roles for EC2 node identity. The Kubernetes cluster had no NetworkPolicy restricting pod egress.

**What happened:** Attackers gained access to an internet-exposed Kubernetes dashboard with no authentication. From there, a cryptomining workload was deployed that freely reached the AWS EC2 metadata service at `169.254.169.254`, retrieved IAM role credentials, and accessed Tesla's S3-stored telemetry and mapping data. A single NetworkPolicy blocking pod egress to the metadata endpoint would have broken the lateral movement chain.

Source: RedLock Cloud Security Intelligence, ["Lessons from the Cryptomining Attack at Tesla"](https://www.paloaltonetworks.com/resources/whitepapers/cloud-security-trends-and-attacks) (February 2018). Included as a well-documented public example of the metadata endpoint exposure class; the underlying risk remains current wherever IMDSv2 is not enforced.

**What Sidereal catches:** The network policy probe validates that egress rules are actually enforcing by attempting connections that a correctly configured policy should block. What destinations are tested depends on how probes are configured — Sidereal validates the rules it is set up to probe, not all possible egress paths automatically.

---

## RBAC

### GKE — FluentBit and Anthos Service Mesh dual privilege escalation

**Control in place:** RBAC configured throughout the cluster. GKE's default platform components — FluentBit and Anthos Service Mesh — were granted the permissions they needed for their stated functions.

**What happened:** Unit 42 researchers found that FluentBit, the default GKE logging agent since March 2023, mounted `/var/lib/kubelet/pods` as a `hostPath` volume. This exposed the projected service account tokens of every pod on the node to any process in the FluentBit container. Separately, the ASM CNI DaemonSet (`istio-cni-node`) retained RBAC permissions beyond what ongoing operation required — permissions scoped for initial installation that were never reduced.

Combining the two: steal a high-privilege service account token via FluentBit's hostPath mount, then use ASM's retained permissions to create a pod in `kube-system` and reach `cluster-admin`. No user RBAC misconfiguration was required. The excessive permissions were in Google's own platform defaults.

Source: [Unit 42 — "Dual Privilege Escalation Chain: Exploiting Monitoring and Service Mesh Configurations and Privileges in GKE"](https://unit42.paloaltonetworks.com/google-kubernetes-engine-privilege-escalation-fluentbit-anthos/) (December 2023). Patched December 14, 2023 (GCP-2023-047).

**What Sidereal catches:** The RBAC probe validates whether specific privilege escalation paths are denied. FluentBit's hostPath mount exposure is a container security context issue rather than an RBAC rule the probe directly exercises. The discovery engine does surface over-permissioned ServiceAccounts and DaemonSet configurations as probe recommendations, which would flag the excessive permissions present in this case before they are exploited.

---

### Azure Data Factory — Airflow AKS service account with cluster-admin

**Control in place:** RBAC configured. Apache Airflow pods ran under a dedicated service account.

**What happened:** Unit 42 found that Azure's managed Apache Airflow integration in Azure Data Factory ran workloads in AKS with a service account bound to `cluster-admin` — far beyond what DAG execution requires. An attacker who could write to the DAG storage (via a compromised SAS token, service principal, or repository) could inject code that runs in the Airflow pod and then uses the attached token to take over the entire cluster and pivot into internal Azure services. The over-permissioned binding was in the platform's default configuration.

Source: [Unit 42 — "Dirty DAG: New Vulnerabilities in Azure Data Factory's Apache Airflow Integration"](https://unit42.paloaltonetworks.com/azure-data-factory-apache-airflow-vulnerabilities/) (December 2024).

**What Sidereal catches:** The RBAC probe tests whether service accounts can take actions beyond their intended scope. An over-permissioned binding — whether set by a user or a managed platform — surfaces as an exploitable escalation path the probe can exercise and report on.

---

### Aqua Nautilus — RBAC-Buster campaign backdoors 60 clusters

**Control in place:** RBAC present and configured. The vulnerability was a binding of `system:unauthenticated` to an elevated ClusterRole — a misconfiguration, but one that made RBAC functionally irrelevant for unauthenticated callers.

**What happened:** Threat actors scanned for Kubernetes API servers with anonymous access enabled and permissive bindings on the `system:unauthenticated` group. After confirming access, they created a `ClusterRole` with near-admin permissions, a `ServiceAccount` named `kube-controller` in `kube-system` (designed to blend into system components), and a `ClusterRoleBinding` tying them together. The backdoor survives fixing the original anonymous access misconfiguration. Aqua found 60 clusters actively compromised and 350 total exposed, across organizations from small companies to Fortune 500 firms.

Source: [Aqua Security — "First-Ever Attack Leveraging Kubernetes RBAC to Backdoor Clusters"](https://www.aquasec.com/blog/leveraging-kubernetes-rbac-to-backdoor-clusters/) (April 2023).

**What Sidereal catches:** The discovery engine scans ClusterRoleBindings and surfaces permissive grants — including bindings on system groups like `system:unauthenticated` — as probe recommendations before they become an active incident. The RBAC probe then validates whether those escalation paths are actually exploitable.

---

### CVE-2018-1002105 — API server proxied requests as cluster-admin (a class of problem, not a current vulnerability)

CVE-2018-1002105 is patched. It is included here because it illustrates a category of failure where correctly scoped RBAC provides no protection: an attacker leverages a different identity rather than escalating their own.

**Control in place:** RBAC correctly configured and limiting the attacker's account to minimal read permissions.

**What happened:** A flaw in the Kubernetes API server's aggregated API proxy allowed an authenticated user with limited permissions to send a specially crafted upgrade request. The API server then proxied backend requests using its own credentials — which carry cluster-admin access. The attacker never escalated their own permissions; they used the API server's identity instead.

The broader lesson: RBAC governs what a principal can do through normal API operations. When another system component acts on a user's behalf, the permissions of that component apply, not the user's. Any path where a low-privileged user can cause a high-privileged component to take an action on their behalf exists outside of what RBAC alone can prevent.

Source: [CVE-2018-1002105](https://nvd.nist.gov/vuln/detail/CVE-2018-1002105) (CVSS 9.8); disclosure by Jordan Liggitt (Google), December 2018.

**What Sidereal catches:** Nothing specific to this attack class. The API server proxy hijacking operated entirely outside the RBAC evaluation path — RBAC was correctly configured and the attacker never needed to bypass it. This example is included because it illustrates a category of failure that RBAC-based controls cannot close: when a trusted system component acts on a user's behalf with the component's own higher privileges. Validating that class of risk requires architectural review of aggregated API service registrations, not a probe.

---

## Runtime Detection

### ARMO "Curing" rootkit — io_uring bypasses Falco, Tetragon, and Microsoft Defender

**Control in place:** Falco (default ruleset) and Tetragon (default configuration) deployed for runtime threat detection.

**What happened:** ARMO published a proof-of-concept rootkit named "Curing" that conducts all operations — file reads, network communication, command execution — exclusively through Linux's `io_uring` asynchronous I/O interface rather than traditional system calls. The rootkit demonstrated full data exfiltration (reading `/etc/shadow` and transmitting over TCP) without triggering any alert in Falco, Tetragon in default configuration, or Microsoft Defender for Endpoint on Linux.

Both Falco and Tetragon instrument system calls. `io_uring` routes I/O through a shared memory ring buffer between userspace and the kernel, bypassing the syscall interface entirely. `io_uring` supports 61 operations covering file I/O, networking, and process management — sufficient to run a complete command-and-control channel without a single detectable syscall.

Source: [ARMO — "io_uring Rootkit Bypasses Linux Security Tools"](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/); [The Hacker News](https://thehackernews.com/2025/04/linux-iouring-poc-rootkit-bypasses.html) (April 2025); [armosec/curing on GitHub](https://github.com/armosec/curing). Note: Tetragon can detect io_uring when explicitly configured with specific kprobes or LSM hooks; this requires operators to know the technique exists and to configure accordingly.

**What Sidereal catches:** The detection probe fires synthetic syscall patterns and verifies the alert was raised — but io_uring bypasses the syscall layer entirely. A Falco or Tetragon deployment could pass every Sidereal detection probe while remaining completely blind to io_uring-based attacks. This example is included specifically because it represents a coverage gap that Sidereal cannot validate without explicit probe configuration targeting io_uring operations. Tetragon can be configured to detect io_uring via specific kprobes or LSM hooks; once that configuration exists, a Sidereal detection probe can verify it is working.

---

### Falco + `memfd_create` — fileless execution is invisible to default rules

**Control in place:** Falco deployed with the default ruleset, actively alerting on process execution anomalies.

**What happened:** Falco's default rules pattern-match on file paths. Execution via `memfd_create` creates an anonymous in-memory file descriptor; the resulting process has no path that matches any default rule. Datadog Security Labs demonstrated this against real Falco deployments, showing that an attacker running arbitrary code inside a container produced zero Falco alerts using this technique. The fileless pattern is standard in Metasploit and Cobalt Strike payloads.

Aqua Nautilus subsequently reported a 1,400% year-over-year increase in memory-based attacks against container environments, noting that "only more sophisticated dynamic analysis that analyzes a running system's processes can help detect these attacks."

Source: Datadog Security Labs, "Fileless Malware in Kubernetes" (2022); [Aqua Nautilus — "1,400% Surge in Memory-Based Attacks"](https://www.globenewswire.com/news-release/2023/6/27/2695275/0/en/Aqua-Nautilus-Research-Finds-1-400-Surge-in-Memory-Based-Attacks-as-Hackers-Evade-Traditional-Cloud-Security-Defenses.html) (June 2023).

**What Sidereal catches:** The detection probe fires known-bad syscall patterns and independently verifies the alert was raised. A ruleset gap that lets a specific technique through is indistinguishable from a disabled detection tool if you are only checking whether the tool is running. Whether the probe specifically covers fileless execution techniques depends on how detection probes are configured — Sidereal validates coverage for the patterns it is set up to fire, not the full universe of possible techniques.

---

### Sysdig 2024 — 70% of containers live less than five minutes

**Control in place:** Runtime detection tools deployed and active.

**What happened:** Sysdig's 2024 Cloud-Native Security and Usage Report found that 70% of containers in production environments live less than five minutes. Most runtime detection tools depend on behavioral observation over time — baselining, correlation, threshold-based alerting. An attack that completes inside a short-lived container (initial access, token theft, credential exfiltration) may be entirely gone before a detection event is correlated and acted on.

The same report found that 91% of granted permissions in container environments were unused, indicating that RBAC is consistently over-permissioned in practice.

Source: [Sysdig 2024 Cloud-Native Security and Usage Report](https://www.sysdig.com/2024-cloud-native-security-and-usage-report).

**What Sidereal catches:** Sidereal's detection probe validates that the detection pipeline raised an alert for a specific known-bad action — not that it observed behavior over time. Short container lifetimes do not affect probe coverage because the probe does not depend on behavioral baselining. The same report's finding on over-permissioned RBAC is surfaced separately by the RBAC probe and discovery engine.

---

## Production breaches

### SCARLETEEL — Kubernetes cluster breach to AWS data theft (2023)

**Control in place:** AWS IAM roles, CloudTrail logging, and Kubernetes RBAC. An IAM policy was intended to limit what credentials stolen from the cluster could do.

**What happened:** Sysdig's Threat Research Team documented a breach that began at an internet-exposed service running in a Kubernetes pod. The attacker reached the AWS Instance Metadata Service from inside the container, harvested IAM credentials, and pivoted into the victim's AWS account. The attacker then installed `pacu` (AWS exploitation framework) and `peirates` (Kubernetes attack tooling) from within the cluster. CloudTrail logging was disabled using the stolen credentials. API calls were routed through a proxy that supported the AWS protocol, causing them to not appear in the victim's CloudTrail.

A separate finding: a single-character typo in the IAM policy intended to restrict the blast radius of compromised credentials granted a broader permission than intended. The intended control was not the actual control.

Source: [Sysdig — "SCARLETEEL: Operation leveraging Terraform, Kubernetes, and AWS for data theft"](https://www.sysdig.com/blog/cloud-breach-terraform-data-theft) (February 2023); [SCARLETEEL 2.0](https://www.sysdig.com/blog/scarleteel-2-0) (July 2023).

**What Sidereal catches:** The secret access probe validates that Kubernetes secrets cannot be read by workloads without explicit authorization. The network policy probe validates that configured egress rules are enforcing — what destinations are tested depends on probe configuration, not automatic coverage of all sensitive endpoints. A policy typo or misconfiguration surfaces as `Ineffective` on the next scheduled run.

---

### Microsoft — OpenMetadata RCE, active exploitation of Kubernetes clusters (2024)

**Control in place:** Authentication on the OpenMetadata service, network exposure controls, and the Kubernetes RBAC posture of the cluster.

**What happened:** Microsoft Threat Intelligence documented active exploitation of five critical vulnerabilities in OpenMetadata (CVE-2024-28255 and related, affecting versions prior to 1.3.1) that allowed authentication bypass and remote code execution. Attackers scanned for internet-exposed Kubernetes workloads running vulnerable versions, gained code execution in the container, performed internal reconnaissance to determine RBAC scope and network layout, then downloaded and executed cryptomining malware. Active exploitation began in early April 2024.

The application-layer authentication control was broken by the vulnerabilities. Once inside the container, the attacker operated with whatever ambient Kubernetes permissions the OpenMetadata service account held.

Source: [Microsoft Security Blog — "Attackers exploiting new critical OpenMetadata vulnerabilities on Kubernetes clusters"](https://www.microsoft.com/en-us/security/blog/2024/04/17/attackers-exploiting-new-critical-openmetadata-vulnerabilities-on-kubernetes-clusters/) (April 2024).

**What Sidereal catches:** Sidereal cannot prevent application-layer vulnerabilities. What it validates is what happens after initial container compromise: whether the ambient RBAC permissions are minimal enough to contain the blast radius, and whether network policy prevents lateral movement to other workloads or sensitive endpoints. A compromised container with `Effective` RBAC and network policy results is a contained incident. One with `Ineffective` results is an uncontained one.

---

## Further reading

- [NSA/CISA Kubernetes Hardening Guidance](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) (2021, updated 2022)
- [Red Hat — State of Kubernetes Security Report 2024](https://www.redhat.com/en/engage/state-kubernetes-security-report-2024)
- [CNCF-commissioned Kubernetes Security Audit](https://github.com/trailofbits/audit-kubernetes) — Trail of Bits / NCC Group (2019)
- [Aqua Security Team Nautilus research](https://blog.aquasec.com/tag/team-nautilus)
- [Sysdig Threat Research](https://www.sysdig.com/blog/category/threat-research/)
- *Hacking Kubernetes* — Andrew Martin and Michael Hausenblas (O'Reilly, 2021)
