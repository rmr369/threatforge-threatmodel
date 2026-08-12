# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Control detection / fact extraction.

This module answers one question for every asset: **which security controls are
present, which are absent, and where is the proof?**  Rules then fire on facts
rather than on asset types, which is the entire difference between "every pod
has a spoofing threat" and "this pod runs as root with a mounted docker socket".

Every fact key is dotted and stable; rule packs reference them by name.
`asset.facts` is a flat dict of scalars/lists, plus `_ev` holding a SourceRef
pointer per fact so findings can cite file:line.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .ingest.kubernetes import all_containers, pod_labels_of, pod_spec_of
from .model import Asset, DataClass, Element, SourceRef, ThreatModel

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DANGEROUS_CAPS = {
    "ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO",
    "SYS_BOOT", "DAC_READ_SEARCH", "DAC_OVERRIDE", "NET_RAW", "SETUID", "SETGID",
    "BPF", "PERFMON", "CHECKPOINT_RESTORE", "SYS_CHROOT",
}

SENSITIVE_HOST_PATHS = (
    "/", "/etc", "/var/run/docker.sock", "/var/run/containerd", "/var/run/crio",
    "/var/lib/kubelet", "/proc", "/sys", "/dev", "/root", "/home", "/var/log",
    "/etc/kubernetes", "/var/lib/docker",
)

WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection", "*"}
ESCALATION_RESOURCES = {
    "secrets", "pods/exec", "pods/attach", "pods/portforward", "serviceaccounts/token",
    "clusterrolebindings", "rolebindings", "clusterroles", "roles",
    "mutatingwebhookconfigurations", "validatingwebhookconfigurations",
    "nodes/proxy", "persistentvolumes", "certificatesigningrequests/approval",
}

SECRETISH_ENV = re.compile(
    r"(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|credential|conn(ection)?[_-]?str|dsn|auth)", re.I)

# Values that are clearly placeholders, not real secrets.
PLACEHOLDER = re.compile(
    r"^(\s*|changeme|change_me|xxx+|todo|placeholder|<[^>]+>|\$\{[^}]+\}|\$\([^)]+\)|"
    r"TF_TEMPLATED|example|test|dummy|none|null|n/?a)$", re.I)

REGISTRY_ALLOW_DEFAULT = ()   # configured via .threatforge.yml


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def extract_facts(model: ThreatModel, config: Optional[Dict[str, Any]] = None) -> None:
    cfg = config or {}
    ns_netpol = _namespace_netpol_index(model)

    for asset in model.assets.values():
        f: Dict[str, Any] = asset.facts
        ev: Dict[str, SourceRef] = {}
        f.setdefault("_ev", ev)
        ev = f["_ev"]

        f["kind"] = asset.kind
        f["provider"] = asset.provider
        f["element"] = asset.element.value
        f["namespace"] = asset.namespace
        f["name"] = asset.name
        f["tags"] = sorted(asset.tags)
        f["sensitivity"] = asset.sensitivity
        f["data_classes"] = sorted(dc.value for dc in asset.data_classes)

        # Legacy imports carry no raw spec. Extracting "facts" from an absent
        # spec would manufacture findings out of missing data, so we skip them
        # and let only graph/topology rules apply.
        if "legacy_import" in asset.tags and not asset.spec.get("spec"):
            f["legacy_import"] = True
            continue

        if asset.provider in ("kubernetes", "live"):
            if "workload" in asset.tags:
                _workload_facts(asset, f, ev, ns_netpol, cfg)
            if asset.kind == "Container":
                _container_facts(asset, f, ev, cfg)
            if asset.kind in ("Role", "ClusterRole"):
                _rbac_facts(asset, f, ev)
            if asset.kind == "ServiceAccount":
                _sa_facts(asset, f, ev)
            if asset.kind == "Service":
                _service_facts(asset, f, ev)
            if asset.kind == "Ingress":
                _ingress_facts(asset, f, ev)
            if asset.kind in ("Secret", "ConfigMap"):
                _secret_facts(asset, f, ev)
            if asset.kind == "PersistentVolume":
                _pv_facts(asset, f, ev)
            if asset.kind == "Namespace":
                _namespace_facts(asset, f, ev, model)
        elif asset.provider == "terraform":
            _terraform_facts(asset, f, ev)
        elif asset.provider == "docker":
            _dockerfile_facts(asset, f, ev)
        elif asset.provider == "compose":
            _compose_facts(asset, f, ev)

    _flow_facts(model)
    _coverage_summary(model)


# ---------------------------------------------------------------------------
# Kubernetes: workload / pod level
# ---------------------------------------------------------------------------

def _workload_facts(a: Asset, f: Dict[str, Any], ev: Dict[str, SourceRef],
                    ns_netpol: Dict[str, Dict[str, bool]], cfg: Dict[str, Any]) -> None:
    pod, prefix = pod_spec_of(a.spec)
    pod = pod or {}
    src = a.source.file
    sc = pod.get("securityContext") or {}

    def mark(key: str, value: Any, pointer: str) -> None:
        f[key] = value
        ev[key] = SourceRef(file=src, line=a.source.line, pointer=pointer)

    mark("pod.host_network", bool(pod.get("hostNetwork")), f"{prefix}.hostNetwork")
    mark("pod.host_pid", bool(pod.get("hostPID")), f"{prefix}.hostPID")
    mark("pod.host_ipc", bool(pod.get("hostIPC")), f"{prefix}.hostIPC")
    mark("pod.host_ports",
         sorted({p["hostPort"] for c in all_containers(pod)
                 for p in (c.get("ports") or [])
                 if isinstance(p, dict) and p.get("hostPort")}),
         f"{prefix}.containers[].ports[].hostPort")
    mark("pod.run_as_non_root", sc.get("runAsNonRoot"), f"{prefix}.securityContext.runAsNonRoot")
    mark("pod.run_as_user", sc.get("runAsUser"), f"{prefix}.securityContext.runAsUser")
    mark("pod.fs_group", sc.get("fsGroup"), f"{prefix}.securityContext.fsGroup")
    mark("pod.seccomp",
         ((sc.get("seccompProfile") or {}).get("type")
          or (a.annotations or {}).get("seccomp.security.alpha.kubernetes.io/pod")),
         f"{prefix}.securityContext.seccompProfile")
    mark("pod.has_seccomp", bool(f.get("pod.seccomp")) and f.get("pod.seccomp") != "Unconfined",
         f"{prefix}.securityContext.seccompProfile")
    mark("pod.automount_sa_token", pod.get("automountServiceAccountToken"),
         f"{prefix}.automountServiceAccountToken")
    mark("pod.service_account",
         pod.get("serviceAccountName") or pod.get("serviceAccount") or "default",
         f"{prefix}.serviceAccountName")
    mark("pod.uses_default_sa", f["pod.service_account"] == "default",
         f"{prefix}.serviceAccountName")
    mark("pod.priority_class", pod.get("priorityClassName"), f"{prefix}.priorityClassName")
    mark("pod.share_process_namespace", bool(pod.get("shareProcessNamespace")),
         f"{prefix}.shareProcessNamespace")
    mark("pod.dns_policy", pod.get("dnsPolicy"), f"{prefix}.dnsPolicy")
    mark("pod.replicas", (a.spec.get("spec") or {}).get("replicas"), "spec.replicas")
    mark("pod.single_replica",
         (a.spec.get("spec") or {}).get("replicas") in (0, 1)
         and a.kind in ("Deployment", "StatefulSet"), "spec.replicas")

    # host path volumes
    hostpaths: List[Dict[str, Any]] = []
    docker_sock = False
    for i, vol in enumerate(pod.get("volumes") or []):
        if not isinstance(vol, dict):
            continue
        hp = vol.get("hostPath")
        if hp:
            path = str(hp.get("path", ""))
            hostpaths.append({"path": path, "name": vol.get("name"),
                              "pointer": f"{prefix}.volumes[{i}].hostPath"})
            if path.startswith("/var/run/docker.sock") or "containerd.sock" in path \
                    or "crio.sock" in path:
                docker_sock = True
    mark("pod.host_paths", [h["path"] for h in hostpaths], f"{prefix}.volumes")
    mark("pod.sensitive_host_path",
         [h["path"] for h in hostpaths
          if any(h["path"] == p or h["path"].startswith(p.rstrip("/") + "/")
                 for p in SENSITIVE_HOST_PATHS)],
         f"{prefix}.volumes")
    mark("pod.container_runtime_socket", docker_sock, f"{prefix}.volumes")

    # network policy coverage (namespace level, refined by relationship engine tags)
    nsinfo = ns_netpol.get(a.namespace or "default", {})
    mark("net.has_ingress_policy",
         "netpol_ingress" in a.tags or nsinfo.get("default_deny_ingress", False), "")
    mark("net.has_egress_policy",
         "netpol_egress" in a.tags or nsinfo.get("default_deny_egress", False), "")

    # aggregate container facts up to the pod for convenience
    containers = all_containers(pod)
    mark("pod.container_count", len(containers), prefix)
    agg = {
        "privileged": False, "allow_priv_esc": False, "run_as_root": False,
        "read_only_root_fs": True, "no_limits": False, "no_requests": False,
        "dangerous_caps": [], "latest_tag": False, "unpinned_image": False,
        "plaintext_secret_env": [], "no_probes": False,
    }
    for c in containers:
        cf = _container_security(c, pod)
        agg["privileged"] |= cf["privileged"]
        agg["allow_priv_esc"] |= cf["allow_priv_esc"]
        agg["run_as_root"] |= cf["run_as_root"]
        agg["read_only_root_fs"] &= cf["read_only_root_fs"]
        agg["no_limits"] |= cf["no_limits"]
        agg["no_requests"] |= cf["no_requests"]
        agg["dangerous_caps"] += cf["dangerous_caps"]
        agg["latest_tag"] |= cf["latest_tag"]
        agg["unpinned_image"] |= cf["unpinned_image"]
        agg["plaintext_secret_env"] += cf["plaintext_secret_env"]
        agg["no_probes"] |= cf["no_probes"]
    if not containers:
        agg["read_only_root_fs"] = False
    for k, v in agg.items():
        f[f"pod.{k}"] = v
        ev.setdefault(f"pod.{k}", SourceRef(file=src, line=a.source.line,
                                            pointer=f"{prefix}.containers"))
    if agg["privileged"]:
        a.tag("privileged")
    if f["pod.host_network"]:
        a.tag("host_network")
    if f["pod.sensitive_host_path"]:
        a.tag("host_path_mount")
    if agg["plaintext_secret_env"]:
        a.tag("plaintext_secret_env")
        a.classify(DataClass.CREDENTIAL)


# ---------------------------------------------------------------------------
# Kubernetes: container level
# ---------------------------------------------------------------------------

def _container_security(c: Dict[str, Any], pod: Dict[str, Any]) -> Dict[str, Any]:
    sc = c.get("securityContext") or {}
    pod_sc = pod.get("securityContext") or {}
    caps = (sc.get("capabilities") or {})
    added = [str(x).upper() for x in (caps.get("add") or [])]
    dropped = [str(x).upper() for x in (caps.get("drop") or [])]
    res = c.get("resources") or {}
    limits = res.get("limits") or {}
    requests = res.get("requests") or {}
    image = str(c.get("image") or "")

    run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
    run_as_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
    run_as_root = (run_as_user == 0) or (run_as_non_root is not True and run_as_user is None)

    plaintext = []
    for env in c.get("env") or []:
        if not isinstance(env, dict):
            continue
        name, val = str(env.get("name", "")), env.get("value")
        if val is None or not isinstance(val, str):
            continue
        if SECRETISH_ENV.search(name) and not PLACEHOLDER.match(val.strip()):
            plaintext.append(name)

    return {
        "privileged": bool(sc.get("privileged")),
        "allow_priv_esc": sc.get("allowPrivilegeEscalation") is not False,
        "allow_priv_esc_explicit": sc.get("allowPrivilegeEscalation"),
        "run_as_root": run_as_root,
        "run_as_user": run_as_user,
        "run_as_non_root": run_as_non_root,
        "read_only_root_fs": sc.get("readOnlyRootFilesystem") is True,
        "caps_added": added,
        "caps_dropped": dropped,
        "drops_all": "ALL" in dropped,
        "dangerous_caps": [x for x in added if x in DANGEROUS_CAPS],
        "no_limits": not (limits.get("cpu") and limits.get("memory")),
        "no_cpu_limit": not limits.get("cpu"),
        "no_memory_limit": not limits.get("memory"),
        "no_requests": not (requests.get("cpu") and requests.get("memory")),
        "image": image,
        "image_registry": _registry_of(image),
        "latest_tag": image.endswith(":latest") or (":" not in image.split("/")[-1]
                                                    and "@" not in image),
        "unpinned_image": "@sha256:" not in image,
        "pull_policy": c.get("imagePullPolicy"),
        "plaintext_secret_env": plaintext,
        "no_probes": not (c.get("livenessProbe") or c.get("readinessProbe")),
        "no_liveness_probe": not c.get("livenessProbe"),
        "no_readiness_probe": not c.get("readinessProbe"),
        "proc_mount": sc.get("procMount"),
        "host_ports": [p.get("hostPort") for p in (c.get("ports") or [])
                       if isinstance(p, dict) and p.get("hostPort")],
    }


def _container_facts(a: Asset, f: Dict[str, Any], ev: Dict[str, SourceRef],
                     cfg: Dict[str, Any]) -> None:
    c = a.spec.get("container") or {}
    pod = a.spec.get("pod_spec") or {}
    pointer = a.spec.get("pointer") or ""
    sec = _container_security(c, pod)
    for k, v in sec.items():
        f[f"container.{k}"] = v
        ev[f"container.{k}"] = SourceRef(file=a.source.file, line=a.source.line,
                                         pointer=f"{pointer}.{_ptr_for(k)}")
    f["container.role"] = a.spec.get("role")
    f["container.owner_kind"] = a.spec.get("owner_kind")
    f["container.owner_name"] = a.spec.get("owner_name")

    allowed = cfg.get("allowed_registries") or REGISTRY_ALLOW_DEFAULT
    f["container.registry_allowed"] = (
        True if not allowed else sec["image_registry"] in set(allowed))

    # pod-level context available to container rules
    f["pod.host_network"] = bool(pod.get("hostNetwork"))
    f["pod.host_pid"] = bool(pod.get("hostPID"))
    f["pod.service_account"] = (pod.get("serviceAccountName")
                                or pod.get("serviceAccount") or "default")

    if sec["privileged"]:
        a.tag("privileged")
    if sec["dangerous_caps"]:
        a.tag("dangerous_capabilities")
    if sec["plaintext_secret_env"]:
        a.tag("plaintext_secret_env")
        a.classify(DataClass.CREDENTIAL)


_PTR = {
    "privileged": "securityContext.privileged",
    "allow_priv_esc": "securityContext.allowPrivilegeEscalation",
    "allow_priv_esc_explicit": "securityContext.allowPrivilegeEscalation",
    "run_as_root": "securityContext.runAsUser",
    "run_as_user": "securityContext.runAsUser",
    "run_as_non_root": "securityContext.runAsNonRoot",
    "read_only_root_fs": "securityContext.readOnlyRootFilesystem",
    "caps_added": "securityContext.capabilities.add",
    "caps_dropped": "securityContext.capabilities.drop",
    "dangerous_caps": "securityContext.capabilities.add",
    "drops_all": "securityContext.capabilities.drop",
    "no_limits": "resources.limits",
    "no_cpu_limit": "resources.limits.cpu",
    "no_memory_limit": "resources.limits.memory",
    "no_requests": "resources.requests",
    "image": "image", "image_registry": "image",
    "latest_tag": "image", "unpinned_image": "image",
    "pull_policy": "imagePullPolicy",
    "plaintext_secret_env": "env",
    "no_probes": "livenessProbe",
    "no_liveness_probe": "livenessProbe",
    "no_readiness_probe": "readinessProbe",
    "proc_mount": "securityContext.procMount",
    "host_ports": "ports",
}


def _ptr_for(key: str) -> str:
    return _PTR.get(key, key)


def _registry_of(image: str) -> str:
    if not image:
        return ""
    first = image.split("/")[0]
    if "." in first or ":" in first or first == "localhost":
        return first
    return "docker.io"


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------

def _rbac_facts(a: Asset, f: Dict[str, Any], ev: Dict[str, SourceRef]) -> None:
    rules = a.spec.get("rules") or []
    wildcard_verb = wildcard_res = wildcard_api = False
    write_secrets = read_secrets = False
    escalation: List[str] = []
    all_verbs, all_res = set(), set()

    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            continue
        verbs = {str(v).lower() for v in (r.get("verbs") or [])}
        res = {str(v).lower() for v in (r.get("resources") or [])}
        apis = {str(v) for v in (r.get("apiGroups") or [])}
        all_verbs |= verbs
        all_res |= res
        if "*" in verbs:
            wildcard_verb = True
        if "*" in res:
            wildcard_res = True
        if "*" in apis:
            wildcard_api = True
        if "secrets" in res or "*" in res:
            if verbs & {"get", "list", "watch", "*"}:
                read_secrets = True
            if verbs & WRITE_VERBS:
                write_secrets = True
        for target in ESCALATION_RESOURCES:
            if target in res and (verbs & WRITE_VERBS or "get" in verbs or "*" in verbs):
                escalation.append(f"{target}:{','.join(sorted(verbs))[:40]}")
        if "escalate" in verbs or "bind" in verbs or "impersonate" in verbs:
            escalation.append(f"verb:{','.join(sorted(verbs & {'escalate','bind','impersonate'}))}")

    ptr = SourceRef(file=a.source.file, line=a.source.line, pointer="rules")
    for k, v in {
        "rbac.wildcard_verbs": wildcard_verb,
        "rbac.wildcard_resources": wildcard_res,
        "rbac.wildcard_api_groups": wildcard_api,
        "rbac.cluster_admin": wildcard_verb and wildcard_res and a.kind == "ClusterRole",
        "rbac.reads_secrets": read_secrets,
        "rbac.writes_secrets": write_secrets,
        "rbac.escalation_paths": sorted(set(escalation)),
        "rbac.rule_count": len(rules),
        "rbac.verbs": sorted(all_verbs),
        "rbac.resources": sorted(all_res),
        "rbac.is_cluster_scoped": a.kind == "ClusterRole",
    }.items():
        f[k] = v
        ev[k] = ptr
    if f["rbac.cluster_admin"] or escalation:
        a.tag("privileged_role")


def _sa_facts(a: Asset, f: Dict[str, Any], ev: Dict[str, SourceRef]) -> None:
    f["sa.automount"] = a.spec.get("automountServiceAccountToken")
    f["sa.is_default"] = a.name == "default"
    f["sa.has_irsa"] = "irsa" in a.tags
    f["sa.secrets"] = [s.get("name") for s in (a.spec.get("secrets") or [])
                       if isinstance(s, dict)]
    ev["sa.automount"] = SourceRef(file=a.source.file, line=a.source.line,
                                   pointer="automountServiceAccountToken")


# ---------------------------------------------------------------------------
# Network objects
# ---------------------------------------------------------------------------

def _service_facts(a: Asset, f: Dict[str, Any], ev: Dict[str, SourceRef]) -> None:
    spec = a.spec.get("spec") or {}
    ports = spec.get("ports") or []
    f["svc.type"] = spec.get("type", "ClusterIP")
    f["svc.ports"] = [p.get("port") for p in ports if isinstance(p, dict)]
    f["svc.node_ports"] = [p.get("nodePort") for p in ports
                           if isinstance(p, dict) and p.get("nodePort")]
    f["svc.external_ips"] = spec.get("externalIPs") or []
    f["svc.external_traffic_policy"] = spec.get("externalTrafficPolicy")
    f["svc.load_balancer_source_ranges"] = spec.get("loadBalancerSourceRanges") or []
    f["svc.unrestricted_lb"] = (f["svc.type"] == "LoadBalancer"
                                and not f["svc.load_balancer_source_ranges"])
    f["svc.exposes_plaintext_port"] = any(
        p.get("port") in (80, 8080, 3000, 5000, 8000, 9000) for p in ports
        if isinstance(p, dict))
    f["svc.exposes_admin_port"] = sorted({
        p.get("port") for p in ports if isinstance(p, dict)
        and p.get("port") in (22, 23, 2375, 2376, 3306, 5432, 6379, 9200, 27017,
                              11211, 5984, 8500, 2379, 9092, 15672, 10250)})
    ev["svc.type"] = SourceRef(file=a.source.file, line=a.source.line, pointer="spec.type")
    ev["svc.exposes_admin_port"] = SourceRef(file=a.source.file, line=a.source.line,
                                             pointer="spec.ports")


def _ingress_facts(a: Asset, f: Dict[str, Any], ev: Dict[str, SourceRef]) -> None:
    spec = a.spec.get("spec") or {}
    ann = a.annotations or {}
    f["ing.tls"] = bool(spec.get("tls"))
    f["ing.hosts"] = (a.spec.get("_derived") or {}).get("hosts", [])
    f["ing.wildcard_host"] = any(str(h).startswith("*") for h in f["ing.hosts"])
    f["ing.ssl_redirect"] = str(ann.get("nginx.ingress.kubernetes.io/ssl-redirect",
                                        "true")).lower() != "false"
    f["ing.force_ssl_redirect"] = str(
        ann.get("nginx.ingress.kubernetes.io/force-ssl-redirect", "")).lower() == "true"
    f["ing.has_auth"] = any(k for k in ann if "auth-" in k or "auth_" in k
                            or "oauth" in k.lower())
    f["ing.has_rate_limit"] = any("limit-rps" in k or "rate-limit" in k or "limit-connections" in k
                                  for k in ann)
    f["ing.has_waf"] = any("modsecurity" in k or "waf" in k.lower() for k in ann)
    f["ing.snippet_annotations"] = [k for k in ann if "snippet" in k]
    f["ing.backend_protocol"] = ann.get("nginx.ingress.kubernetes.io/backend-protocol")
    ev["ing.tls"] = SourceRef(file=a.source.file, line=a.source.line, pointer="spec.tls")
    ev["ing.has_auth"] = SourceRef(file=a.source.file, line=a.source.line,
                                   pointer="metadata.annotations")


# ---------------------------------------------------------------------------
# Data stores
# ---------------------------------------------------------------------------

_B64 = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")


def _secret_facts(a: Asset, f: Dict[str, Any], ev: Dict[str, SourceRef]) -> None:
    data = a.spec.get("data") or {}
    string_data = a.spec.get("stringData") or {}
    f["secret.type"] = a.spec.get("type")
    f["secret.keys"] = sorted(list(data.keys()) + list(string_data.keys()))
    f["secret.has_inline_data"] = bool(data or string_data) and a.kind == "Secret"
    f["secret.committed_to_repo"] = (
        f["secret.has_inline_data"]
        and a.source.file not in (None, "<undeclared>", "<implicit>", "<live-cluster>")
        and not str(a.source.file).startswith("<"))
    f["secret.is_sealed"] = a.kind in ("SealedSecret", "ExternalSecret")
    f["secret.immutable"] = a.spec.get("immutable")

    if a.kind == "ConfigMap":
        risky = []
        for k, v in (a.spec.get("data") or {}).items():
            if SECRETISH_ENV.search(str(k)) and isinstance(v, str) \
                    and v.strip() and not PLACEHOLDER.match(v.strip()):
                risky.append(k)
        f["configmap.secretish_keys"] = risky
        f["configmap.key_count"] = len(a.spec.get("data") or {})
        if risky:
            a.tag("secret_in_configmap")
            a.classify(DataClass.CREDENTIAL)
    ev["secret.committed_to_repo"] = SourceRef(file=a.source.file, line=a.source.line,
                                               pointer="data")


def _pv_facts(a: Asset, f: Dict[str, Any], ev: Dict[str, SourceRef]) -> None:
    spec = a.spec.get("spec") or {}
    f["pv.reclaim_policy"] = spec.get("persistentVolumeReclaimPolicy")
    f["pv.access_modes"] = spec.get("accessModes") or []
    f["pv.host_path"] = bool(spec.get("hostPath"))
    f["pv.nfs"] = bool(spec.get("nfs"))
    f["pv.encrypted_hint"] = bool((spec.get("csi") or {}).get("volumeAttributes", {}).get("encrypted"))
    ev["pv.reclaim_policy"] = SourceRef(file=a.source.file, line=a.source.line,
                                        pointer="spec.persistentVolumeReclaimPolicy")


def _namespace_facts(a: Asset, f: Dict[str, Any], ev: Dict[str, SourceRef],
                     model: ThreatModel) -> None:
    labels = a.labels or {}
    f["ns.pss_enforce"] = labels.get("pod-security.kubernetes.io/enforce")
    f["ns.pss_audit"] = labels.get("pod-security.kubernetes.io/audit")
    f["ns.has_pss"] = bool(f["ns.pss_enforce"])
    f["ns.pss_is_restricted"] = f["ns.pss_enforce"] == "restricted"
    f["ns.has_quota"] = any(x.kind == "ResourceQuota" and x.namespace == a.name
                            for x in model.assets.values())
    f["ns.has_limit_range"] = any(x.kind == "LimitRange" and x.namespace == a.name
                                  for x in model.assets.values())
    ev["ns.pss_enforce"] = SourceRef(file=a.source.file, line=a.source.line,
                                     pointer="metadata.labels")


def _namespace_netpol_index(model: ThreatModel) -> Dict[str, Dict[str, bool]]:
    """Which namespaces have a default-deny NetworkPolicy?"""
    out: Dict[str, Dict[str, bool]] = {}
    for np in model.assets.values():
        if np.kind != "NetworkPolicy":
            continue
        spec = np.spec.get("spec") or {}
        if spec.get("podSelector") != {}:
            continue
        ptypes = [str(p) for p in (spec.get("policyTypes") or [])]
        entry = out.setdefault(np.namespace or "default", {})
        if "Ingress" in ptypes and not spec.get("ingress"):
            entry["default_deny_ingress"] = True
        if "Egress" in ptypes and not spec.get("egress"):
            entry["default_deny_egress"] = True
    return out


# ---------------------------------------------------------------------------
# Terraform / Docker / Compose
# ---------------------------------------------------------------------------

_OPEN_CIDR = {"0.0.0.0/0", "::/0"}


def _terraform_facts(a: Asset, f: Dict[str, Any], ev: Dict[str, SourceRef]) -> None:
    v = a.spec.get("values") or {}
    rtype = a.kind
    ptr = SourceRef(file=a.source.file, line=a.source.line, pointer=f"resource.{rtype}.{a.name}")

    def put(k: str, val: Any) -> None:
        f[k] = val
        ev[k] = ptr

    put("tf.type", rtype)
    put("tf.public_acl", str(v.get("acl", "")).lower() in
        ("public-read", "public-read-write", "authenticated-read"))
    put("tf.publicly_accessible", bool(v.get("publicly_accessible")))
    put("tf.encrypted", _tf_encrypted(v))
    put("tf.encryption_unknown", _tf_encrypted(v) is None)
    put("tf.versioning", bool(v.get("versioning")))
    put("tf.logging_enabled", bool(v.get("logging") or v.get("access_logs")
                                   or v.get("enable_logging")))
    put("tf.deletion_protection", bool(v.get("deletion_protection")))
    put("tf.skip_final_snapshot", bool(v.get("skip_final_snapshot")))
    put("tf.open_cidr", bool(set(map(str, v.get("cidr_blocks") or [])) & _OPEN_CIDR))
    put("tf.open_ports", v.get("from_port_list") or
        ([v.get("from_port")] if v.get("from_port") is not None else []))
    put("tf.iam_wildcard", _iam_wildcard(v))
    put("tf.possible_hardcoded_secret", "possible_hardcoded_secret" in a.tags)
    # metadata_options is a nested block in plan JSON but flattened by the HCL
    # fallback scraper, so look in both places.
    http_tokens = None
    mo = v.get("metadata_options")
    if isinstance(mo, dict):
        http_tokens = mo.get("http_tokens")
    elif isinstance(mo, list) and mo and isinstance(mo[0], dict):
        http_tokens = mo[0].get("http_tokens")
    if http_tokens is None:
        http_tokens = v.get("http_tokens")
    put("tf.imdsv2_required",
        None if http_tokens is None else str(http_tokens).lower() == "required")
    put("tf.tls_min_version", v.get("minimum_protocol_version") or v.get("min_tls_version"))
    put("tf.is_data_store", "cloud_data_store" in a.tags)
    put("tf.is_edge", "cloud_edge" in a.tags)


def _tf_encrypted(v: Dict[str, Any]) -> Optional[bool]:
    for key in ("storage_encrypted", "encrypted", "encryption", "kms_key_id",
                "kms_master_key_id", "server_side_encryption_configuration",
                "sse_algorithm", "encryption_configuration"):
        if key in v and v[key]:
            return True
    for key in ("storage_encrypted", "encrypted"):
        if key in v and v[key] is False:
            return False
    return None


def _iam_wildcard(v: Dict[str, Any]) -> bool:
    blob = str(v.get("policy") or v.get("__raw__") or "")
    if not blob:
        return False
    return bool(re.search(r'"Action"\s*:\s*"\*"', blob) or
                re.search(r'"Resource"\s*:\s*"\*"', blob) or
                re.search(r'Action\s*=\s*\["?\*', blob))


def _dockerfile_facts(a: Asset, f: Dict[str, Any], ev: Dict[str, SourceRef]) -> None:
    s = a.spec
    ptr = SourceRef(file=a.source.file, line=a.source.line)
    f["df.base_image"] = s.get("base_image")
    f["df.base_is_latest"] = str(s.get("base_image", "")).endswith(":latest") or \
        ":" not in str(s.get("base_image", "")).split("/")[-1]
    f["df.base_unpinned"] = "@sha256:" not in str(s.get("base_image", ""))
    f["df.user"] = s.get("user")
    f["df.runs_as_root"] = s.get("user") in (None, "", "root", "0")
    f["df.exposed_ports"] = s.get("exposed_ports") or []
    f["df.add_remote"] = s.get("add_remote") or []
    f["df.pipe_to_shell"] = s.get("pipe_to_shell") or []
    f["df.hardcoded_secret_refs"] = s.get("hardcoded_secret_refs") or []
    f["df.healthcheck"] = bool(s.get("healthcheck"))
    f["df.final_stage"] = bool(s.get("final"))
    ev["df.runs_as_root"] = SourceRef(file=a.source.file, line=s.get("user_line")
                                      or s.get("from_line"))
    ev["df.base_is_latest"] = SourceRef(file=a.source.file, line=s.get("from_line"))
    for k in ("df.add_remote", "df.pipe_to_shell", "df.hardcoded_secret_refs"):
        items = f.get(k) or []
        if items and isinstance(items[0], dict) and items[0].get("line"):
            ev[k] = SourceRef(file=a.source.file, line=items[0]["line"])


def _compose_facts(a: Asset, f: Dict[str, Any], ev: Dict[str, SourceRef]) -> None:
    svc = a.spec.get("service") or {}
    ptr = SourceRef(file=a.source.file, line=a.source.line)
    f["compose.privileged"] = bool(svc.get("privileged"))
    f["compose.host_network"] = str(svc.get("network_mode", "")).lower() == "host"
    f["compose.cap_add"] = [str(c).upper() for c in (svc.get("cap_add") or [])]
    f["compose.dangerous_caps"] = [c for c in f["compose.cap_add"] if c in DANGEROUS_CAPS]
    f["compose.docker_socket"] = "docker_socket_mount" in a.tags
    f["compose.host_path_mount"] = "host_path_mount" in a.tags
    f["compose.published_ports"] = svc.get("ports") or []
    f["compose.plaintext_secret_env"] = "plaintext_secret_env" in a.tags
    f["compose.no_limits"] = not ((svc.get("deploy") or {}).get("resources", {}).get("limits"))
    f["compose.restart_policy"] = svc.get("restart")
    f["compose.read_only"] = bool(svc.get("read_only"))
    f["compose.user"] = svc.get("user")
    for k in list(f):
        if k.startswith("compose."):
            ev.setdefault(k, ptr)


# ---------------------------------------------------------------------------
# Flow-level facts
# ---------------------------------------------------------------------------

def _flow_facts(model: ThreatModel) -> None:
    for fl in model.flows:
        src = model.assets.get(fl.source)
        tgt = model.assets.get(fl.target)
        if src and tgt:
            if src.element == Element.EXTERNAL_ENTITY and fl.encrypted is False:
                fl.details["plaintext_from_untrusted"] = True
            if tgt.element == Element.DATA_STORE and tgt.sensitivity >= 4:
                fl.data_classes |= tgt.data_classes
        fl.details.setdefault("sensitive",
                              any(dc.value in ("secret", "credential", "pii", "phi", "pci")
                                  for dc in fl.data_classes))


def _coverage_summary(model: ThreatModel) -> None:
    """What fraction of the estate actually has each control? Shown in the report."""
    workloads = [a for a in model.assets.values() if "workload" in a.tags]
    if not workloads:
        model.metadata["control_coverage"] = {}
        return
    n = len(workloads)

    def pct(pred) -> int:
        return round(100 * sum(1 for w in workloads if pred(w)) / n)

    model.metadata["control_coverage"] = {
        "workloads": n,
        "network_policy_ingress": pct(lambda w: w.facts.get("net.has_ingress_policy")),
        "network_policy_egress": pct(lambda w: w.facts.get("net.has_egress_policy")),
        "non_root": pct(lambda w: not w.facts.get("pod.run_as_root", True)),
        "read_only_root_fs": pct(lambda w: w.facts.get("pod.read_only_root_fs")),
        "resource_limits": pct(lambda w: not w.facts.get("pod.no_limits", True)),
        "no_privilege_escalation": pct(lambda w: not w.facts.get("pod.allow_priv_esc", True)),
        "seccomp": pct(lambda w: w.facts.get("pod.has_seccomp")),
        "pinned_images": pct(lambda w: not w.facts.get("pod.unpinned_image", True)),
        "dedicated_service_account": pct(lambda w: not w.facts.get("pod.uses_default_sa", True)),
        "probes": pct(lambda w: not w.facts.get("pod.no_probes", True)),
    }
