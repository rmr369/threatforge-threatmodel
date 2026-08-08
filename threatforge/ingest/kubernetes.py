"""
Kubernetes ingestor: raw manifests, Helm charts, and Kustomize overlays.

Produces one Asset per Kubernetes object, plus one Asset per container (a
container is a distinct process with its own security posture, so it deserves
its own node in the DFD).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

from ..model import Asset, DataClass, Element, SourceRef, ThreatModel
from .base import Ingestor, load_yaml_with_lines, ref, register, walk_files


# ---------------------------------------------------------------------------
# Kind classification
# ---------------------------------------------------------------------------

WORKLOAD_KINDS = {
    "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController",
    "Job", "CronJob", "Pod", "Rollout", "DeploymentConfig",
}

DATA_STORE_KINDS = {
    "Secret", "ConfigMap", "PersistentVolume", "PersistentVolumeClaim",
    "StorageClass", "VolumeSnapshot", "SealedSecret", "ExternalSecret",
}

NETWORK_KINDS = {
    "Service", "Ingress", "IngressClass", "Gateway", "HTTPRoute", "VirtualService",
    "NetworkPolicy", "Endpoints", "EndpointSlice", "IngressRoute",
}

IDENTITY_KINDS = {
    "ServiceAccount", "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding",
    "PodSecurityPolicy", "SecurityContextConstraints",
}

POLICY_KINDS = {
    "LimitRange", "ResourceQuota", "PodDisruptionBudget", "HorizontalPodAutoscaler",
    "VerticalPodAutoscaler", "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration",
    "Namespace", "PriorityClass", "RuntimeClass",
}


def classify(kind: str) -> Element:
    if kind in DATA_STORE_KINDS:
        return Element.DATA_STORE
    return Element.PROCESS


# Naming heuristics used to attach data classifications.
_SENSITIVE_NAME = re.compile(
    r"(secret|credential|passwd|password|token|apikey|api-key|privatekey|private-key|"
    r"tls|cert|keystore|oauth|jwt|ssh|kubeconfig)", re.I)
_PII_NAME = re.compile(r"(user|customer|patient|member|account|profile|person|identity)", re.I)
_DB_NAME = re.compile(
    r"(postgres|mysql|mariadb|mongo|redis|cassandra|elastic|opensearch|clickhouse|"
    r"cockroach|neo4j|couch|dynamo|etcd|kafka|rabbit|minio|s3|db\b|database)", re.I)


def infer_data_classes(kind: str, name: str, spec: Dict[str, Any]) -> set:
    out = set()
    blob = f"{name} {kind}"
    if kind in ("Secret", "SealedSecret", "ExternalSecret"):
        out.add(DataClass.SECRET)
        stype = (spec.get("type") or "")
        if "tls" in str(stype).lower() or "dockerconfig" in str(stype).lower():
            out.add(DataClass.CREDENTIAL)
    if kind == "ConfigMap":
        out.add(DataClass.CONFIG)
    if _SENSITIVE_NAME.search(blob):
        out.add(DataClass.CREDENTIAL)
    if _PII_NAME.search(blob):
        out.add(DataClass.PII)
    if _DB_NAME.search(blob):
        out.add(DataClass.PII)
    return out


# ---------------------------------------------------------------------------
# Spec navigation helpers (shared with the relationship engine)
# ---------------------------------------------------------------------------

def pod_spec_of(doc: Dict[str, Any]) -> (Optional[Dict[str, Any]], str):
    """Return (podSpec, pointer_prefix) for any workload kind."""
    kind = doc.get("kind")
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return spec, "spec"
    if kind == "CronJob":
        job = (spec.get("jobTemplate") or {}).get("spec") or {}
        tmpl = (job.get("template") or {}).get("spec")
        return tmpl, "spec.jobTemplate.spec.template.spec"
    tmpl = (spec.get("template") or {}).get("spec")
    if tmpl is not None:
        return tmpl, "spec.template.spec"
    return None, "spec"


def pod_labels_of(doc: Dict[str, Any]) -> Dict[str, str]:
    kind = doc.get("kind")
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return (doc.get("metadata") or {}).get("labels") or {}
    if kind == "CronJob":
        job = (spec.get("jobTemplate") or {}).get("spec") or {}
        return ((job.get("template") or {}).get("metadata") or {}).get("labels") or {}
    return ((spec.get("template") or {}).get("metadata") or {}).get("labels") or {}


def all_containers(pod_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """initContainers + containers + ephemeralContainers, tagged with their role."""
    out = []
    for key, role in (("initContainers", "init"),
                      ("containers", "main"),
                      ("ephemeralContainers", "ephemeral")):
        for i, c in enumerate(pod_spec.get(key) or []):
            if isinstance(c, dict):
                out.append({"_role": role, "_key": key, "_index": i, **c})
    return out


def k8s_id(kind: str, namespace: Optional[str], name: str) -> str:
    return f"k8s:{kind}:{namespace or 'default'}/{name}"


def container_id(namespace: Optional[str], workload: str, container: str) -> str:
    return f"k8s:Container:{namespace or 'default'}/{workload}/{container}"


# ---------------------------------------------------------------------------
# Ingestor
# ---------------------------------------------------------------------------

@register
class KubernetesIngestor(Ingestor):
    name = "kubernetes"
    provider = "kubernetes"

    SKIP_FILENAMES = {
        "chart.yaml", "chart.lock", "values.yaml", "values.schema.json",
        ".pre-commit-config.yaml", "docker-compose.yaml", "docker-compose.yml",
        "compose.yaml", "compose.yml", "skaffold.yaml", ".gitlab-ci.yml",
    }

    def detect(self, root: str) -> bool:
        files = walk_files(root, (".yaml", ".yml"))
        return bool(files)

    # -- main ------------------------------------------------------------
    def ingest(self, root: str, model: ThreatModel) -> None:
        rendered_dirs: List[str] = []
        if self.config.get("render_helm", True):
            rendered_dirs += self._render_helm_charts(root, model)
        if self.config.get("render_kustomize", True):
            rendered_dirs += self._render_kustomize(root, model)

        targets = [(root, False)] + [(d, True) for d in rendered_dirs]
        for base, is_rendered in targets:
            for path in walk_files(base, (".yaml", ".yml")):
                if os.path.basename(path).lower() in self.SKIP_FILENAMES:
                    continue
                self._ingest_file(path, model, root, is_rendered)

        for tmp in rendered_dirs:
            shutil.rmtree(tmp, ignore_errors=True)

    def _ingest_file(self, path: str, model: ThreatModel, root: str, rendered: bool) -> None:
        rel = os.path.relpath(path, root) if not rendered else f"<rendered>/{os.path.basename(path)}"
        try:
            docs = load_yaml_with_lines(path)
        except Exception as exc:
            model.error("ingest.kubernetes", f"parse failed: {exc}", file=rel)
            self.stats["skipped"] += 1
            return

        self.stats["files"] += 1
        for doc, lines in docs:
            if not isinstance(doc, dict):
                continue
            kind = doc.get("kind")
            meta = doc.get("metadata") or {}
            name = meta.get("name")
            if not kind or not name or not isinstance(name, str):
                continue
            if kind in ("List", "Kustomization"):
                for item in doc.get("items") or []:
                    if isinstance(item, dict):
                        self._emit_object(item, {}, rel, model)
                continue
            self._emit_object(doc, lines, rel, model)

    # -- object -> assets -------------------------------------------------
    def _emit_object(self, doc: Dict[str, Any], lines: Dict[str, int],
                     rel: str, model: ThreatModel) -> None:
        kind = doc.get("kind")
        meta = doc.get("metadata") or {}
        name = meta.get("name")
        namespace = meta.get("namespace") or "default"
        if kind in ("Namespace", "ClusterRole", "ClusterRoleBinding",
                    "PersistentVolume", "StorageClass", "IngressClass",
                    "PodSecurityPolicy", "PriorityClass", "RuntimeClass"):
            namespace = None  # cluster-scoped

        asset = Asset(
            id=k8s_id(kind, namespace, name),
            kind=kind,
            name=name,
            provider="kubernetes",
            namespace=namespace,
            element=classify(kind),
            labels=meta.get("labels") or {},
            annotations=meta.get("annotations") or {},
            spec=doc,
            source=ref(rel, lines, ""),
        )
        asset.data_classes |= infer_data_classes(kind, name, doc.get("spec") or doc)

        if kind in NETWORK_KINDS:
            asset.tag("network")
        if kind in IDENTITY_KINDS:
            asset.tag("identity")
        if kind in POLICY_KINDS:
            asset.tag("policy")
        if kind in WORKLOAD_KINDS:
            asset.tag("workload")
        if kind not in (WORKLOAD_KINDS | DATA_STORE_KINDS | NETWORK_KINDS
                        | IDENTITY_KINDS | POLICY_KINDS):
            asset.tag("custom_resource")

        self.emit(model, asset)

        if kind in WORKLOAD_KINDS:
            self._emit_containers(doc, lines, rel, model, namespace, name)

    def _emit_containers(self, doc: Dict[str, Any], lines: Dict[str, int], rel: str,
                         model: ThreatModel, namespace: Optional[str], workload: str) -> None:
        pod_spec, prefix = pod_spec_of(doc)
        if not pod_spec:
            return
        for c in all_containers(pod_spec):
            cname = c.get("name")
            if not cname:
                continue
            pointer = f"{prefix}.{c['_key']}[{c['_index']}]"
            casset = Asset(
                id=container_id(namespace, workload, cname),
                kind="Container",
                name=cname,
                provider="kubernetes",
                namespace=namespace,
                element=Element.PROCESS,
                spec={
                    "container": {k: v for k, v in c.items() if not k.startswith("_")},
                    "pod_spec": pod_spec,
                    "pointer": pointer,
                    "role": c["_role"],
                    "owner_kind": doc.get("kind"),
                    "owner_name": workload,
                },
                source=ref(rel, lines, pointer),
            )
            casset.tag("container", f"container_role:{c['_role']}")
            image = str(c.get("image") or "")
            if image:
                casset.tag(f"image:{image}")
                if _DB_NAME.search(image):
                    casset.classify(DataClass.PII)
                    casset.tag("datastore_workload")
            self.emit(model, casset)

    # -- Helm -------------------------------------------------------------
    def _render_helm_charts(self, root: str, model: ThreatModel) -> List[str]:
        charts = [os.path.dirname(p) for p in walk_files(root, (), filenames=["Chart.yaml"])]
        if not charts:
            return []
        if not shutil.which("helm"):
            model.error("ingest.kubernetes",
                        f"{len(charts)} Helm chart(s) found but `helm` is not installed; "
                        "templates parsed best-effort with placeholders.",
                        charts=[os.path.relpath(c, root) for c in charts])
            return []
        out = []
        for chart in charts:
            tmp = tempfile.mkdtemp(prefix="tf-helm-")
            try:
                res = subprocess.run(
                    ["helm", "template", os.path.basename(chart) or "release", chart,
                     "--output-dir", tmp],
                    capture_output=True, text=True, timeout=120,
                )
                if res.returncode != 0:
                    model.error("ingest.kubernetes", f"helm template failed: {res.stderr[:400]}",
                                chart=os.path.relpath(chart, root))
                    shutil.rmtree(tmp, ignore_errors=True)
                    continue
                out.append(tmp)
            except Exception as exc:
                model.error("ingest.kubernetes", f"helm error: {exc}",
                            chart=os.path.relpath(chart, root))
                shutil.rmtree(tmp, ignore_errors=True)
        return out

    # -- Kustomize --------------------------------------------------------
    def _render_kustomize(self, root: str, model: ThreatModel) -> List[str]:
        kdirs = [os.path.dirname(p) for p in
                 walk_files(root, (), filenames=["kustomization.yaml", "kustomization.yml"])]
        if not kdirs:
            return []
        exe = shutil.which("kustomize")
        use_kubectl = False
        if not exe:
            if shutil.which("kubectl"):
                use_kubectl = True
            else:
                model.error("ingest.kubernetes",
                            f"{len(kdirs)} kustomization(s) found but neither `kustomize` nor "
                            "`kubectl` is installed; base manifests parsed directly.")
                return []
        out = []
        for kdir in kdirs:
            tmp = tempfile.mkdtemp(prefix="tf-kustomize-")
            cmd = (["kubectl", "kustomize", kdir] if use_kubectl else [exe, "build", kdir])
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if res.returncode != 0 or not res.stdout.strip():
                    shutil.rmtree(tmp, ignore_errors=True)
                    continue
                dest = os.path.join(tmp, "kustomized.yaml")
                with open(dest, "w", encoding="utf-8") as fh:
                    fh.write(res.stdout)
                out.append(tmp)
            except Exception:
                shutil.rmtree(tmp, ignore_errors=True)
        return out


# ---------------------------------------------------------------------------
# Live cluster collector
# ---------------------------------------------------------------------------

@register
class LiveClusterIngestor(Ingestor):
    """Threat-model a *running* cluster via kubectl. Opt-in only."""

    name = "live"
    provider = "live"

    KINDS = [
        "deployments", "statefulsets", "daemonsets", "cronjobs", "jobs", "pods",
        "services", "ingresses", "networkpolicies", "serviceaccounts",
        "roles", "rolebindings", "clusterroles", "clusterrolebindings",
        "configmaps", "secrets", "persistentvolumeclaims", "persistentvolumes",
        "namespaces", "resourcequotas", "limitranges",
    ]

    def detect(self, root: str) -> bool:
        return bool(self.config.get("enabled")) and shutil.which("kubectl") is not None

    def ingest(self, root: str, model: ThreatModel) -> None:
        import json as _json
        ns_args = []
        if self.config.get("namespace"):
            ns_args = ["-n", self.config["namespace"]]
        else:
            ns_args = ["--all-namespaces"]

        k8s = KubernetesIngestor()
        for kind in self.KINDS:
            cmd = ["kubectl", "get", kind, "-o", "json"] + ns_args
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
                if res.returncode != 0:
                    continue
                payload = _json.loads(res.stdout)
            except Exception as exc:
                model.error("ingest.live", f"{kind}: {exc}")
                continue

            for item in payload.get("items", []):
                # secrets: never pull the actual data, only the shape
                if item.get("kind") == "Secret":
                    item["data"] = {k: "<redacted>" for k in (item.get("data") or {})}
                item.setdefault("kind", kind[:-1].title())
                k8s._emit_object(item, {}, f"<live-cluster>/{kind}", model)
                self.stats["assets"] += 1
        model.metadata["live_cluster"] = True
