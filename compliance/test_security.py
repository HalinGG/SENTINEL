"""
Security smoke tests — verifies Docker hardening and k3s cluster are up and configured correctly.
Run: python3 compliance/test_security.py
"""

import json
import subprocess
import sys
import unittest


def run(cmd, check=False):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\n{r.stderr}")
    return r.stdout.strip(), r.returncode


class DockerHardeningTests(unittest.TestCase):

    def test_docker_running(self):
        out, code = run("systemctl is-active docker")
        self.assertEqual(out, "active", "Docker daemon must be running")

    def test_icc_disabled(self):
        out, _ = run("docker network inspect bridge")
        data = json.loads(out)
        icc = data[0]["Options"].get("com.docker.network.bridge.enable_icc")
        self.assertEqual(icc, "false", "ICC must be disabled on default bridge (CIS 2.2)")

    def test_no_new_privileges(self):
        out, _ = run("docker info")
        self.assertIn("no-new-privileges", out, "no-new-privileges must be set (CIS 2.14)")

    def test_live_restore_enabled(self):
        out, _ = run("docker info")
        self.assertIn("Live Restore Enabled: true", out, "Live restore must be enabled (CIS 2.15)")

    def test_userland_proxy_disabled(self):
        out, _ = run("cat /etc/docker/daemon.json")
        cfg = json.loads(out)
        self.assertFalse(cfg.get("userland-proxy", True), "Userland proxy must be disabled (CIS 2.16)")

    def test_storage_driver_overlay2(self):
        out, _ = run("docker info")
        self.assertIn("overlay2", out, "Storage driver must be overlay2 (CIS 2.8)")

    def test_log_driver_json_file(self):
        out, _ = run("cat /etc/docker/daemon.json")
        cfg = json.loads(out)
        self.assertEqual(cfg.get("log-driver"), "json-file", "Log driver must be json-file (CIS 2.12)")

    def test_log_size_limits(self):
        out, _ = run("cat /etc/docker/daemon.json")
        cfg = json.loads(out)
        opts = cfg.get("log-opts", {})
        self.assertIn("max-size", opts, "Log max-size must be set (CIS 2.12)")
        self.assertIn("max-file", opts, "Log max-file must be set (CIS 2.12)")

    def test_auditd_rules_docker(self):
        out, code = run("auditctl -l")
        self.assertIn("docker", out, "auditd rules for Docker must be active (CIS 1.x)")

    def test_no_privileged_containers(self):
        out, _ = run("docker ps -q")
        if not out:
            return  # no containers running
        for cid in out.splitlines():
            inspect, _ = run(f"docker inspect {cid}")
            data = json.loads(inspect)
            privileged = data[0]["HostConfig"]["Privileged"]
            name = data[0]["Name"]
            self.assertFalse(privileged, f"Container {name} must not run privileged")

    def test_daemon_json_exists(self):
        out, code = run("test -f /etc/docker/daemon.json")
        self.assertEqual(code, 0, "/etc/docker/daemon.json must exist")


class K3sClusterTests(unittest.TestCase):

    KUBECTL = "KUBECONFIG=/home/halingordon/.kube/config kubectl"

    def test_k3s_running(self):
        out, code = run("systemctl is-active k3s")
        self.assertEqual(out, "active", "k3s must be running")

    def test_node_ready(self):
        out, _ = run(f"{self.KUBECTL} get nodes -o jsonpath='{{.items[0].status.conditions[-1].type}}'")
        self.assertEqual(out, "Ready", "k3s node must be in Ready state")

    def test_audit_logging_enabled(self):
        out, code = run("test -f /var/log/k3s/audit.log")
        self.assertEqual(code, 0, "k3s audit log must exist (CIS 1.2.22)")

    def test_secrets_encryption_enabled(self):
        # Secrets encryption creates an encryption-config secret or file
        out, code = run("test -f /var/lib/rancher/k3s/server/cred/encryption-state.json")
        self.assertEqual(code, 0, "Secrets encryption must be enabled (CIS 1.2.33)")

    def test_anonymous_auth_disabled(self):
        out, _ = run("cat /etc/systemd/system/k3s.service")
        self.assertIn("anonymous-auth=false", out, "API server anonymous-auth must be false (CIS 1.2.1)")

    def test_profiling_disabled(self):
        out, _ = run("cat /etc/systemd/system/k3s.service")
        self.assertIn("profiling=false", out, "Profiling must be disabled (CIS 1.2.21)")

    def test_rbac_enabled(self):
        out, _ = run(f"{self.KUBECTL} api-versions")
        self.assertIn("rbac.authorization.k8s.io", out, "RBAC API must be enabled")

    def test_kubernetes_goat_running(self):
        out, _ = run(f"{self.KUBECTL} get pods -A --field-selector=status.phase=Running -o name")
        self.assertGreater(len(out.splitlines()), 5, "Kubernetes Goat pods must be running")

    def test_coredns_running(self):
        out, _ = run(f"{self.KUBECTL} get pods -n kube-system -l k8s-app=kube-dns -o jsonpath='{{.items[0].status.phase}}'")
        self.assertEqual(out, "Running", "CoreDNS must be running")

    def test_no_default_namespace_cluster_admin(self):
        """Flag wildcard cluster-admin bindings — the Kubernetes Goat insecure-rbac scenario."""
        out, _ = run(f"{self.KUBECTL} get clusterrolebindings -o json")
        data = json.loads(out)
        wildcard_bindings = []
        for item in data.get("items", []):
            role = item.get("roleRef", {}).get("name", "")
            name = item.get("metadata", {}).get("name", "")
            subjects = item.get("subjects") or []
            if role == "cluster-admin":
                for s in subjects:
                    if s.get("namespace") == "default":
                        wildcard_bindings.append(name)
        self.assertEqual(
            wildcard_bindings, [],
            f"SECURITY FINDING: cluster-admin bound to default namespace SA: {wildcard_bindings} (CIS 5.1.1)"
        )


class KubernetesGoatFindingsTests(unittest.TestCase):
    """Documents known intentional vulnerabilities in Kubernetes Goat for interview demo."""

    KUBECTL = "KUBECONFIG=/home/halingordon/.kube/config kubectl"

    def test_find_insecure_rbac_binding(self):
        """CIS 5.1.1 / OWASP A01 — superadmin ClusterRoleBinding exists (intentional)."""
        out, code = run(f"{self.KUBECTL} get clusterrolebinding superadmin 2>/dev/null")
        self.assertEqual(code, 0, "Kubernetes Goat insecure-rbac scenario must be deployed")

    def test_find_secret_in_namespace(self):
        """OWASP A02 — goatvault secret exposed in default namespace."""
        out, code = run(f"{self.KUBECTL} get secret goatvault -n default 2>/dev/null")
        self.assertEqual(code, 0, "Kubernetes Goat goatvault secret must exist")

    def test_find_unauthenticated_redis(self):
        """OWASP A07 — cache-store Redis deployed with no auth configured."""
        out, code = run(f"{self.KUBECTL} get svc cache-store-service -n secure-middleware 2>/dev/null")
        self.assertEqual(code, 0, "cache-store (Redis) must be deployed without auth")

    def test_docker_socket_mounted_localstack(self):
        """CIS 5.32 / OWASP A05 — docker.sock mounted in LocalStack (real finding, not Goat)."""
        out, _ = run("docker inspect localstack 2>/dev/null || true")
        if not out or out == "[]":
            self.skipTest("LocalStack not running")
        data = json.loads(out)
        mounts = data[0].get("Mounts", [])
        socket_mounted = any(m.get("Source") == "/var/run/docker.sock" for m in mounts)
        self.assertTrue(socket_mounted, "FINDING: docker.sock is mounted in LocalStack (CIS 5.32)")


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Order matters for the demo narrative
    for cls in [DockerHardeningTests, K3sClusterTests, KubernetesGoatFindingsTests]:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
