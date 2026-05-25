# Container Security Assessment
**Candidate:** Halin Gordon | **Role:** Senior Security/Software Engineer  
**Date:** 2026-05-25 | **Environment:** GCP Ubuntu 26.04, 2 vCPU, 2GB RAM

---

## 1. Architecture Overview (3 min)

```
┌─────────────────────────────────────────────────────┐
│                    GCP VM                           │
│  ┌──────────────────┐  ┌──────────────────────────┐ │
│  │   Docker 29.1.3  │  │   k3s v1.35.5            │ │
│  │   (CIS hardened) │  │   (CIS hardened)         │ │
│  │                  │  │                          │ │
│  │  LocalStack:3    │  │  Kubernetes Goat         │ │
│  │  (sentinel dev)  │  │  (intentional vulns)     │ │
│  └──────────────────┘  └──────────────────────────┘ │
│                                                     │
│  Scanners: docker-bench | kube-bench | kube-hunter  │
└─────────────────────────────────────────────────────┘
```

**Why k3s over kubeadm:** Production-grade, CNCF-certified, ~512MB footprint. Used in edge, IoT, and constrained cloud workloads. Same CIS benchmark applies.

---

## 2. Docker Hardening Applied (CIS Docker Benchmark v1.6)

### daemon.json Controls

| Control | Setting | CIS ID | NIST 800-53 |
|---------|---------|--------|-------------|
| No inter-container comms | `icc: false` | 2.2 | SC-7 |
| No privilege escalation | `no-new-privileges: true` | 2.14 | AC-6, CM-7 |
| Live restore | `live-restore: true` | 2.15 | CP-10 |
| Userland proxy disabled | `userland-proxy: false` | 2.16 | CM-7 |
| Log size limits | `max-size: 100m, max-file: 3` | 2.12 | AU-9 |
| Storage driver | `overlay2` | 2.8 | CM-6 |

### Audit Rules (CIS 1.x → NIST AU-2, AU-3)
Watching: `/var/lib/docker`, `/etc/docker`, `docker.service`, `docker.sock`, `docker` binary, `containerd`, `runc`

### docker-bench-security Results
```
Total Checks: 117  |  Score: 34
```

**Passed (key):** ICC disabled ✓ | no-new-privileges ✓ | live-restore ✓ | overlay2 ✓ | audit rules ✓ | no insecure registries ✓ | no AUFS ✓

**Open Findings:**

| ID | Finding | Risk | Remediation | NIST |
|----|---------|------|-------------|------|
| **5.32** | LocalStack mounts `/var/run/docker.sock` | CRITICAL — full Docker API = host escape | Remove socket mount; use LocalStack's new DNS endpoint mode | AC-6, AC-17 |
| **2.9** | User namespace remapping disabled | HIGH — container root = host root | `"userns-remap": "default"` in daemon.json (requires LocalStack reconfiguration) | AC-6, SC-39 |
| **5.29** | No PID cgroup limit on LocalStack | MEDIUM — fork bomb risk | Add `--pids-limit 200` to compose | CM-6 |
| **2.12** | No Docker daemon TLS auth | LOW — local socket only, no remote exposure | Enable TLS if remote access ever needed | IA-3 |
| **2.13** | No centralized log shipping | LOW — logs local only | Ship to GCP Cloud Logging / SIEM | AU-9 |

> **Interview note on 5.32:** This is the most interesting finding. The LocalStack container has `/var/run/docker.sock` mounted — an attacker who escapes the container can spawn privileged containers and own the host. This is a known architectural tradeoff in LocalStack (it needs Docker to spin up Lambda functions). In prod: scope it with a Docker socket proxy (e.g., `tecnativa/docker-socket-proxy`) that permits only the specific Docker API calls LocalStack needs.

---

## 3. k3s Hardening Applied (CIS Kubernetes Benchmark)

### Install Flags

| Flag | Value | CIS ID | NIST 800-53 |
|------|-------|--------|-------------|
| `anonymous-auth` | `false` | 1.2.1 | IA-2 |
| `profiling` (API/CM/Scheduler) | `false` | 1.2.21, 1.3.2, 1.4.1 | CM-7 |
| `audit-log-path` | `/var/log/k3s/audit.log` | 1.2.22–25 | AU-2, AU-3 |
| `audit-policy-file` | `/etc/k3s/audit-policy.yaml` | 1.2.22 | AU-2 |
| `secrets-encryption` | enabled | 1.2.33 | SC-28 |
| `protect-kernel-defaults` | `true` | 4.2.6 | CM-6 |
| traefik ingress | disabled | — | CM-7 (reduce attack surface) |

### kube-bench Results (k3s-cis-1.7)
```
PASS: 57  |  FAIL: 6  |  WARN: 53  |  INFO: 15
```

**FAILs — all kubelet section (4.2.x):**

| ID | Finding | Root Cause | Remediation |
|----|---------|------------|-------------|
| 1.2.28 | etcd-cafile not set | k3s uses embedded SQLite/etcd, different TLS path | Configure `--etcd-cafile` in k3s server args or accept for embedded mode |
| 4.2.1 | kubelet anonymous-auth | kube-bench looks in `/etc/kubernetes/` — k3s stores config differently | Create kubelet config file at expected path or use `--kubelet-arg=anonymous-auth=false` |
| 4.2.2 | kubelet authorization-mode | Same path issue | `--kubelet-arg=authorization-mode=Webhook` |
| 4.2.3 | kubelet client-ca-file | k3s auto-rotates CA but in non-standard path | Symlink or add kubelet arg explicitly |
| 4.2.4 | read-only-port not 0 | k3s defaults differ | `--kubelet-arg=read-only-port=0` |
| 4.2.9 | kubelet TLS certs | k3s manages certs internally | Point kube-bench at correct k3s cert paths |

> **Interview note:** These FAILs are largely k3s/kube-bench path mismatch — kube-bench expects kubeadm filesystem layout. In k3s, the kubelet gets its config from k3s server flags, not a kubelet config file. You can verify the actual kubelet settings with `k3s kubectl get --raw /api/v1/nodes/<node>/proxy/configz`. A production remediation would patch the kubelet config via the k3s config file at `/etc/rancher/k3s/config.yaml`.

---

## 4. Kubernetes Goat — Intentional Vulnerabilities

> **Purpose:** Demonstrate ability to identify, exploit, and remediate K8s security flaws.

### Deployed Scenarios

| Scenario | Vulnerability Class | OWASP | NIST |
|----------|--------------------|----|------|
| `insecure-rbac` | Wildcard ClusterRoleBinding — any pod = cluster-admin | A01 Broken Access Control | AC-3, AC-6 |
| `metadata-db` | SSRF to cloud metadata endpoint (169.254.169.254) | A10 SSRF | SI-10 |
| `hidden-in-layers` | Secrets baked into Docker image layers | A02 Cryptographic Failures | SC-28 |
| `cache-store` | Unauthenticated Redis exposed in cluster | A07 Auth Failures | IA-2 |
| `hunger-check` | Sensitive env vars (API keys) in pod spec | A02 Cryptographic Failures | SC-28 |
| `internal-proxy` | SSRF → internal service access | A10 SSRF | SI-10 |
| `system-monitor` | Privileged container with host path mounts | A05 Misconfiguration | AC-6 |
| `build-code` | RCE via unsanitized build input | A03 Injection | SI-10 |
| `poor-registry` | Pulls from unauthenticated/public registry | A06 Vulnerable Components | CM-7 |

### Key Attack: insecure-rbac → Cluster Takeover
```bash
# The superadmin service account has ClusterRoleBinding to cluster-admin
kubectl get clusterrolebinding superadmin -o yaml
# Any pod using this SA can run:
kubectl auth can-i '*' '*' --as system:serviceaccount:default:superadmin
# yes → full cluster control
```

**Remediation:** Apply least-privilege RBAC — role-per-namespace, no wildcards, no cluster-admin for app service accounts.

### Key Attack: hidden-in-layers
```bash
# Pull image and inspect all layers for secrets
docker save <image> | tar x
# Find hardcoded secrets committed before they were removed
```

**Remediation:** Never commit secrets; use K8s Secrets or Vault. Use `trivy image` or `trufflehog` in CI.

---

## 5. kube-hunter Results

```
Passive scan — 127.0.0.1
Services discovered: K8s API (6443), Kubelet API (10250)
Vulnerabilities found: NONE
```

**Interpretation:** External attack surface is clean from the outside. The vulnerabilities are internal (RBAC, service-to-service, container escape) — which is the realistic threat model for a compromised workload.

---

## 6. Risk Summary & Remediation Priority

| Priority | Finding | Effort | Impact |
|----------|---------|--------|--------|
| P0 | Docker socket mount in LocalStack | Medium | Host escape |
| P0 | K8s Goat wildcard RBAC | Low | Cluster takeover |
| P1 | userns-remap disabled | High (app compat) | Container root = host root |
| P1 | Secrets in image layers | Medium | Credential exposure |
| P2 | Kubelet bench FAILs (path issue) | Low | Compliance gap |
| P2 | PID cgroup limit missing | Low | DoS risk |
| P3 | No centralized log shipping | Medium | Audit gap |

---

## 7. FedRAMP Moderate Alignment

FedRAMP is a control framework (NIST 800-53 Rev 5 Moderate baseline), not a scanner. Key applicable controls addressed:

| Control Family | Controls | Status |
|---------------|---------|--------|
| **AU** — Audit & Accountability | AU-2, AU-3, AU-9 | ✅ auditd + k3s audit log |
| **AC** — Access Control | AC-3, AC-6, AC-17 | ⚠️ RBAC ok; docker.sock = gap |
| **CM** — Config Management | CM-6, CM-7 | ✅ icc, profiling, traefik off |
| **SC** — System Communications | SC-7, SC-28, SC-39 | ⚠️ SC-39 needs userns-remap |
| **IA** — Identification & Auth | IA-2, IA-3 | ✅ anonymous-auth=false |
| **SI** — System Integrity | SI-10 | ⚠️ SSRF scenarios in Goat |

---

*Artifacts: `kube-bench.txt` · `kube-hunter.json` · `docker-bench.log` · `tests/test_security.py`*
