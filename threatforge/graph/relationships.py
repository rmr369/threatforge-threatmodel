# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Relationship engine.

Turns a bag of Assets into a connected graph.  Correctness here is what makes
the difference between a picture and a threat model: if the engine does not
know that Service X selects Deployment Y, it cannot know that Y is internet
reachable, and every downstream risk score is wrong.

Resolution strategies, strongest first:
  1. explicit references   (ingress backend, PVC claimName, secretKeyRef, roleRef)
  2. label selectors       (Service -> pods, NetworkPolicy -> pods)
  3. annotation bindings   (IRSA role ARN, cloud load balancer hints)
  4. name/image heuristics (Dockerfile -> image, env value -> cloud endpoint)
Heuristic edges are tagged `confidence: possible` so reports can show or hide them.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from ..ingest.kubernetes import (all_containers, container_id, k8s_id,
                                 pod_labels_of, pod_spec_of)
from ..model import Asset, DataClass, Element, Flow, SourceRef, ThreatModel

INTERNET = "ext:internet"
INTERNAL_USER = "ext:internal-user"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_relationships(model: ThreatModel) -> None:
    ctx = _Context(model)
    ctx.external_entities()
    ctx.workload_containers()
    ctx.service_to_workload()
    ctx.ingress_to_service()
    ctx.gateway_routes()
    ctx.storage()
    ctx.config_and_secrets()
    ctx.service_accounts()
    ctx.rbac()
    ctx.network_policies()
    ctx.internet_exposure()
    ctx.cross_provider()
    ctx.compose_links()
    ctx.dockerfile_links()
    ctx.reclassify_datastore_workloads()
    model.metadata["relationship_strategies"] = ctx.strategy_counts


class _Context:
    def __init__(self, model: ThreatModel) -> None:
        self.m = model
        self.strategy_counts: Dict[str, int] = {}
        # indexes
        self.by_kind: Dict[str, List[Asset]] = {}
        for a in model.assets.values():
            self.by_kind.setdefault(a.kind, []).append(a)

    # -- helpers ----------------------------------------------------------
    def kind(self, *kinds: str) -> List[Asset]:
        out: List[Asset] = []
        for k in kinds:
            out += self.by_kind.get(k, [])
        return out

    def link(self, src: str, tgt: str, kind: str, *, protocol: Optional[str] = None,
             encrypted: Optional[bool] = None, authenticated: Optional[bool] = None,
             confidence: str = "confirmed", data_classes: Optional[Set[DataClass]] = None,
             source_ref: Optional[SourceRef] = None, **details: Any) -> Optional[Flow]:
        if src not in self.m.assets or tgt not in self.m.assets:
            return None
        self.strategy_counts[kind] = self.strategy_counts.get(kind, 0) + 1
        return self.m.add_flow(Flow(
            source=src, target=tgt, kind=kind, protocol=protocol,
            encrypted=encrypted, authenticated=authenticated,
            data_classes=set(data_classes or ()),
            details={"confidence": confidence, **details},
            source_ref=source_ref or SourceRef(),
        ))

    @staticmethod
    def _selector_matches(selector: Dict[str, Any], labels: Dict[str, str]) -> bool:
        if not selector or not labels:
            return False
        match_labels = selector.get("matchLabels", selector if "matchExpressions" not in selector else {})
        if isinstance(match_labels, dict) and match_labels:
            for k, v in match_labels.items():
                if k in ("matchLabels", "matchExpressions"):
                    continue
                if str(labels.get(k)) != str(v):
                    return False
        for expr in selector.get("matchExpressions") or []:
            key, op = expr.get("key"), expr.get("operator")
            vals = [str(v) for v in (expr.get("values") or [])]
            actual = labels.get(key)
            if op == "In" and str(actual) not in vals:
                return False
            if op == "NotIn" and str(actual) in vals:
                return False
            if op == "Exists" and key not in labels:
                return False
            if op == "DoesNotExist" and key in labels:
                return False
        return True

    def workloads(self) -> List[Asset]:
        return [a for a in self.m.assets.values() if "workload" in a.tags]

    # -- 0. external entities --------------------------------------------
    def external_entities(self) -> None:
        for eid, name, desc in (
            (INTERNET, "Internet", "Anonymous untrusted traffic from the public internet."),
            (INTERNAL_USER, "Internal user / operator",
             "Authenticated humans and CI systems with cluster or console access."),
        ):
            self.m.add_asset(Asset(
                id=eid, kind="ExternalEntity", name=name, provider="external",
                element=Element.EXTERNAL_ENTITY,
                spec={"description": desc},
            )).tag("external", "untrusted" if eid == INTERNET else "semi_trusted")

    # -- 1. workload -> container ----------------------------------------
    def workload_containers(self) -> None:
        for wl in self.workloads():
            pod_spec, _ = pod_spec_of(wl.spec)
            if not pod_spec:
                continue
            for c in all_containers(pod_spec):
                cid = container_id(wl.namespace, wl.name, c.get("name"))
                self.link(wl.id, cid, "runs", source_ref=wl.source)

    # -- 2. service -> workload ------------------------------------------
    def service_to_workload(self) -> None:
        for svc in self.kind("Service"):
            selector = (svc.spec.get("spec") or {}).get("selector") or {}
            if not selector:
                continue
            matched = False
            for wl in self.workloads():
                if wl.namespace != svc.namespace:
                    continue
                labels = pod_labels_of(wl.spec)
                if self._selector_matches(selector, labels):
                    matched = True
                    ports = (svc.spec.get("spec") or {}).get("ports") or []
                    proto = _port_summary(ports)
                    self.link(svc.id, wl.id, "routes-to", protocol=proto,
                              encrypted=_is_tls_port(ports), source_ref=svc.source,
                              selector=selector)
            if not matched:
                svc.tag("selector_matches_nothing")

    # -- 3. ingress -> service -------------------------------------------
    def ingress_to_service(self) -> None:
        for ing in self.kind("Ingress", "IngressRoute"):
            spec = ing.spec.get("spec") or {}
            tls = bool(spec.get("tls"))
            if tls:
                ing.tag("tls_configured")
            hosts = []
            backends: List[Tuple[str, Optional[int]]] = []

            default = spec.get("defaultBackend") or spec.get("backend") or {}
            b = _backend_service(default)
            if b:
                backends.append(b)

            for rule in spec.get("rules") or []:
                if rule.get("host"):
                    hosts.append(rule["host"])
                http = rule.get("http") or {}
                for path in http.get("paths") or []:
                    b = _backend_service(path.get("backend") or {})
                    if b:
                        backends.append(b)

            # Traefik IngressRoute
            for route in spec.get("routes") or []:
                for svc in route.get("services") or []:
                    if svc.get("name"):
                        backends.append((svc["name"], svc.get("port")))

            ing.spec.setdefault("_derived", {})["hosts"] = hosts
            for svc_name, port in backends:
                target = k8s_id("Service", ing.namespace, svc_name)
                self.link(ing.id, target, "routes-to",
                          protocol=f"https:{port}" if tls else f"http:{port}",
                          encrypted=tls, source_ref=ing.source, hosts=hosts)

    def gateway_routes(self) -> None:
        for rt in self.kind("HTTPRoute", "TCPRoute", "GRPCRoute", "VirtualService"):
            spec = rt.spec.get("spec") or {}
            for rule in (spec.get("rules") or []) + (spec.get("http") or []):
                refs = (rule.get("backendRefs") or [])
                for r in rule.get("route") or []:                 # Istio VirtualService
                    dest = r.get("destination") or {}
                    if dest.get("host"):
                        refs.append({"name": str(dest["host"]).split(".")[0],
                                     "port": (dest.get("port") or {}).get("number")})
                for bref in refs:
                    if not isinstance(bref, dict) or not bref.get("name"):
                        continue
                    self.link(rt.id, k8s_id("Service", rt.namespace, bref["name"]),
                              "routes-to", protocol=f"http:{bref.get('port')}",
                              source_ref=rt.source)
            for pref in spec.get("parentRefs") or []:
                if isinstance(pref, dict) and pref.get("name"):
                    self.link(k8s_id("Gateway", rt.namespace, pref["name"]), rt.id,
                              "routes-to", source_ref=rt.source)

    # -- 4. storage -------------------------------------------------------
    def storage(self) -> None:
        for wl in self.workloads():
            pod_spec, prefix = pod_spec_of(wl.spec)
            if not pod_spec:
                continue
            for i, vol in enumerate(pod_spec.get("volumes") or []):
                if not isinstance(vol, dict):
                    continue
                ptr = f"{prefix}.volumes[{i}]"
                pvc = (vol.get("persistentVolumeClaim") or {}).get("claimName")
                if pvc:
                    self.link(wl.id, k8s_id("PersistentVolumeClaim", wl.namespace, pvc),
                              "mounts", source_ref=wl.source, pointer=ptr,
                              read_only=bool((vol.get("persistentVolumeClaim") or {}).get("readOnly")))
                if vol.get("hostPath"):
                    wl.tag("host_path_mount")
                    host_id = f"k8s:HostPath:{wl.namespace}/{vol['hostPath'].get('path','/')}"
                    self.m.add_asset(Asset(
                        id=host_id, kind="HostPath", name=vol["hostPath"].get("path", "/"),
                        namespace=wl.namespace, element=Element.DATA_STORE,
                        spec={"hostPath": vol["hostPath"]}, source=wl.source,
                    )).tag("node_filesystem", "outside_container_boundary")
                    self.link(wl.id, host_id, "mounts", source_ref=wl.source, pointer=ptr)

        for pvc in self.kind("PersistentVolumeClaim"):
            spec = pvc.spec.get("spec") or {}
            if spec.get("volumeName"):
                self.link(pvc.id, k8s_id("PersistentVolume", None, spec["volumeName"]),
                          "bound-to", source_ref=pvc.source)
            if spec.get("storageClassName"):
                self.link(pvc.id, k8s_id("StorageClass", None, spec["storageClassName"]),
                          "provisioned-by", source_ref=pvc.source)

    # -- 5. config & secrets ---------------------------------------------
    def config_and_secrets(self) -> None:
        for wl in self.workloads():
            pod_spec, prefix = pod_spec_of(wl.spec)
            if not pod_spec:
                continue

            # volume-mounted secrets/configmaps
            for i, vol in enumerate(pod_spec.get("volumes") or []):
                if not isinstance(vol, dict):
                    continue
                ptr = f"{prefix}.volumes[{i}]"
                if (vol.get("secret") or {}).get("secretName"):
                    self._ref_data(wl, "Secret", vol["secret"]["secretName"], "mounts", ptr)
                if (vol.get("configMap") or {}).get("name"):
                    self._ref_data(wl, "ConfigMap", vol["configMap"]["name"], "mounts", ptr)
                for src in (vol.get("projected") or {}).get("sources") or []:
                    if (src.get("secret") or {}).get("name"):
                        self._ref_data(wl, "Secret", src["secret"]["name"], "mounts", ptr)
                    if (src.get("configMap") or {}).get("name"):
                        self._ref_data(wl, "ConfigMap", src["configMap"]["name"], "mounts", ptr)

            # env references, per container
            for c in all_containers(pod_spec):
                cid = container_id(wl.namespace, wl.name, c.get("name"))
                cptr = f"{prefix}.{c['_key']}[{c['_index']}]"
                for j, env in enumerate(c.get("env") or []):
                    if not isinstance(env, dict):
                        continue
                    vf = env.get("valueFrom") or {}
                    ptr = f"{cptr}.env[{j}]"
                    if (vf.get("secretKeyRef") or {}).get("name"):
                        self._ref_data(wl, "Secret", vf["secretKeyRef"]["name"], "reads", ptr, cid)
                    if (vf.get("configMapKeyRef") or {}).get("name"):
                        self._ref_data(wl, "ConfigMap", vf["configMapKeyRef"]["name"], "reads", ptr, cid)
                for j, ef in enumerate(c.get("envFrom") or []):
                    if not isinstance(ef, dict):
                        continue
                    ptr = f"{cptr}.envFrom[{j}]"
                    if (ef.get("secretRef") or {}).get("name"):
                        self._ref_data(wl, "Secret", ef["secretRef"]["name"], "reads", ptr, cid)
                    if (ef.get("configMapRef") or {}).get("name"):
                        self._ref_data(wl, "ConfigMap", ef["configMapRef"]["name"], "reads", ptr, cid)

            for ips in pod_spec.get("imagePullSecrets") or []:
                if isinstance(ips, dict) and ips.get("name"):
                    self._ref_data(wl, "Secret", ips["name"], "reads", f"{prefix}.imagePullSecrets")

    def _ref_data(self, wl: Asset, kind: str, name: str, rel: str,
                  pointer: str, from_id: Optional[str] = None) -> None:
        target = k8s_id(kind, wl.namespace, name)
        if target not in self.m.assets:
            # referenced but never defined in this repo -- still a real dependency
            self.m.add_asset(Asset(
                id=target, kind=kind, name=name, namespace=wl.namespace,
                element=Element.DATA_STORE, spec={},
                source=SourceRef(file="<undeclared>"),
            )).tag("undeclared_reference",
                   *(("sensitive",) if kind == "Secret" else ()))
            if kind == "Secret":
                self.m.assets[target].classify(DataClass.SECRET)
        dcs = {DataClass.SECRET} if kind == "Secret" else {DataClass.CONFIG}
        self.link(from_id or wl.id, target, rel, data_classes=dcs,
                  source_ref=SourceRef(file=wl.source.file, pointer=pointer),
                  pointer=pointer)

    # -- 6. service accounts ---------------------------------------------
    def service_accounts(self) -> None:
        for wl in self.workloads():
            pod_spec, prefix = pod_spec_of(wl.spec)
            if not pod_spec:
                continue
            sa = pod_spec.get("serviceAccountName") or pod_spec.get("serviceAccount") or "default"
            target = k8s_id("ServiceAccount", wl.namespace, sa)
            if target not in self.m.assets:
                self.m.add_asset(Asset(
                    id=target, kind="ServiceAccount", name=sa, namespace=wl.namespace,
                    element=Element.PROCESS, spec={}, source=SourceRef(file="<implicit>"),
                )).tag("identity", "implicit" if sa == "default" else "declared")
            if sa == "default":
                wl.tag("uses_default_service_account")
            self.link(wl.id, target, "assumes",
                      source_ref=SourceRef(file=wl.source.file,
                                           pointer=f"{prefix}.serviceAccountName"))

    # -- 7. RBAC ----------------------------------------------------------
    def rbac(self) -> None:
        for rb in self.kind("RoleBinding", "ClusterRoleBinding"):
            role_ref = rb.spec.get("roleRef") or {}
            role_kind = role_ref.get("kind", "Role")
            role_ns = None if role_kind == "ClusterRole" else rb.namespace
            role_id = k8s_id(role_kind, role_ns, role_ref.get("name", ""))
            if role_ref.get("name") and role_id not in self.m.assets:
                self.m.add_asset(Asset(
                    id=role_id, kind=role_kind, name=role_ref["name"], namespace=role_ns,
                    element=Element.PROCESS, spec={}, source=SourceRef(file="<builtin-or-external>"),
                )).tag("identity", "builtin_role")
                if role_ref.get("name") in ("cluster-admin", "admin", "edit"):
                    self.m.assets[role_id].tag("privileged_role")

            for subj in rb.spec.get("subjects") or []:
                if not isinstance(subj, dict):
                    continue
                skind = subj.get("kind")
                sname = subj.get("name")
                if not sname:
                    continue
                if skind == "ServiceAccount":
                    sid = k8s_id("ServiceAccount", subj.get("namespace") or rb.namespace, sname)
                    if sid not in self.m.assets:
                        self.m.add_asset(Asset(
                            id=sid, kind="ServiceAccount", name=sname,
                            namespace=subj.get("namespace") or rb.namespace,
                            element=Element.PROCESS, spec={},
                            source=SourceRef(file="<implicit>"))).tag("identity")
                elif skind in ("User", "Group"):
                    sid = f"ext:{skind.lower()}:{sname}"
                    if sid not in self.m.assets:
                        self.m.add_asset(Asset(
                            id=sid, kind=f"RBAC{skind}", name=sname, provider="external",
                            element=Element.EXTERNAL_ENTITY, spec={},
                            source=rb.source)).tag("external", "identity")
                        if sname in ("system:anonymous", "system:unauthenticated"):
                            self.m.assets[sid].tag("anonymous")
                    self.link(INTERNET if "anonymous" in sname else INTERNAL_USER,
                              sid, "authenticates-as", source_ref=rb.source)
                else:
                    continue
                self.link(sid, role_id, "granted", source_ref=rb.source, binding=rb.name)

    # -- 8. network policies ----------------------------------------------
    def network_policies(self) -> None:
        for np in self.kind("NetworkPolicy"):
            spec = np.spec.get("spec") or {}
            selector = spec.get("podSelector")
            ptypes = spec.get("policyTypes") or []
            has_ingress = "Ingress" in ptypes or "ingress" in spec
            has_egress = "Egress" in ptypes or "egress" in spec
            for wl in self.workloads():
                if wl.namespace != np.namespace:
                    continue
                labels = pod_labels_of(wl.spec)
                # empty podSelector {} selects ALL pods in the namespace
                selects_all = selector is not None and selector == {}
                if selects_all or self._selector_matches(selector or {}, labels):
                    self.link(np.id, wl.id, "protects", source_ref=np.source,
                              ingress=has_ingress, egress=has_egress)
                    if has_ingress:
                        wl.tag("netpol_ingress")
                    if has_egress:
                        wl.tag("netpol_egress")
            # allow-from-anywhere rules widen exposure
            for rule in spec.get("ingress") or []:
                for peer in rule.get("from") or []:
                    cidr = (peer.get("ipBlock") or {}).get("cidr")
                    if cidr in ("0.0.0.0/0", "::/0"):
                        np.tag("allows_all_ingress")
                if not rule.get("from"):
                    np.tag("allows_all_ingress")

    # -- 9. internet exposure ---------------------------------------------
    def internet_exposure(self) -> None:
        for ing in self.kind("Ingress", "IngressRoute", "Gateway", "HTTPRoute"):
            ing.tag("internet_facing")
            spec = ing.spec.get("spec") or {}
            self.link(INTERNET, ing.id, "external-access",
                      protocol="https" if spec.get("tls") else "http",
                      encrypted=bool(spec.get("tls")), authenticated=None,
                      source_ref=ing.source)

        for svc in self.kind("Service"):
            spec = svc.spec.get("spec") or {}
            stype = spec.get("type", "ClusterIP")
            if stype == "LoadBalancer":
                internal = any(
                    "internal" in str(k).lower() and str(v).lower() in ("true", "0.0.0.0/0")
                    for k, v in (svc.annotations or {}).items())
                svc.tag("load_balancer", "internet_facing" if not internal else "internal_lb")
                if not internal:
                    self.link(INTERNET, svc.id, "external-access",
                              protocol=_port_summary(spec.get("ports") or []),
                              encrypted=_is_tls_port(spec.get("ports") or []),
                              source_ref=svc.source)
            elif stype == "NodePort":
                svc.tag("node_port", "internet_facing_candidate")
                self.link(INTERNET, svc.id, "external-access",
                          protocol=_port_summary(spec.get("ports") or []),
                          confidence="likely", source_ref=svc.source,
                          note="NodePort reachability depends on node firewall rules")
            if spec.get("externalIPs"):
                svc.tag("external_ip", "internet_facing")
                self.link(INTERNET, svc.id, "external-access", source_ref=svc.source)

        for a in self.m.assets.values():
            if a.provider == "terraform" and "cloud_edge" in a.tags:
                a.tag("internet_facing")
                self.link(INTERNET, a.id, "external-access", source_ref=a.source)
            if a.provider == "compose" and "internet_facing_candidate" in a.tags:
                self.link(INTERNET, a.id, "external-access", confidence="likely",
                          source_ref=a.source)

    # -- 10. cross-provider ------------------------------------------------
    _ARN = re.compile(r"arn:aws[a-z\-]*:iam::\d+:role/([\w+=,.@\-/]+)")
    _ENDPOINT = re.compile(r"([a-z0-9][a-z0-9\-\.]{2,})\.(?:amazonaws\.com|windows\.net|googleapis\.com)")

    def cross_provider(self) -> None:
        tf_by_name = {}
        for a in self.m.assets.values():
            if a.provider == "terraform":
                tf_by_name.setdefault(a.name.lower(), []).append(a)
                bucket = (a.spec.get("values") or {}).get("bucket") or \
                         (a.spec.get("values") or {}).get("name")
                if isinstance(bucket, str):
                    tf_by_name.setdefault(bucket.lower(), []).append(a)

        for sa in self.kind("ServiceAccount"):
            for k, v in (sa.annotations or {}).items():
                m = self._ARN.search(str(v))
                if m:
                    sa.tag("irsa", "cloud_identity")
                    role_name = m.group(1).split("/")[-1].lower()
                    for cand in tf_by_name.get(role_name, []):
                        self.link(sa.id, cand.id, "assumes", confidence="likely",
                                  source_ref=sa.source, via=k)

        for wl in self.workloads():
            pod_spec, _ = pod_spec_of(wl.spec)
            if not pod_spec:
                continue
            for c in all_containers(pod_spec):
                for env in c.get("env") or []:
                    if not isinstance(env, dict):
                        continue
                    val = str(env.get("value") or "")
                    if not val:
                        continue
                    m = self._ENDPOINT.search(val)
                    if m:
                        stem = m.group(1).split(".")[0].lower()
                        for cand in tf_by_name.get(stem, []):
                            self.link(wl.id, cand.id, "calls", confidence="possible",
                                      protocol="https", source_ref=wl.source,
                                      via_env=env.get("name"))

    # -- 11. compose -------------------------------------------------------
    def compose_links(self) -> None:
        for svc in self.by_kind.get("ComposeService", []):
            body = svc.spec.get("service") or {}
            for dep in _depends_on(body):
                self.link(svc.id, f"compose:service:{dep}", "calls", source_ref=svc.source)
            for vol in body.get("volumes") or []:
                name = vol.split(":")[0] if isinstance(vol, str) else str(vol.get("source", ""))
                target = f"compose:volume:{name}"
                if target in self.m.assets:
                    self.link(svc.id, target, "mounts", source_ref=svc.source)

    # -- 12. dockerfile -> runtime image ----------------------------------
    def dockerfile_links(self) -> None:
        images = self.by_kind.get("DockerImage", [])
        if not images:
            return
        for img in images:
            if "final_stage" not in img.tags:
                continue
            df_dir = (img.source.file or "").replace("\\", "/").rsplit("/", 1)[0].lower()
            hint = df_dir.rsplit("/", 1)[-1] if df_dir else ""
            if not hint or hint in (".", ""):
                continue
            for a in self.m.assets.values():
                if a.kind != "Container":
                    continue
                image_ref = str((a.spec.get("container") or {}).get("image") or "").lower()
                repo = image_ref.split(":")[0].split("/")[-1]
                if repo and (repo == hint or hint in repo or repo in hint):
                    self.link(img.id, a.id, "built-from", confidence="possible",
                              source_ref=img.source, matched_on=hint)

    # -- 13. reclassify ----------------------------------------------------
    def reclassify_datastore_workloads(self) -> None:
        """A Postgres Deployment is a data store, not just a process."""
        for a in self.m.assets.values():
            if "datastore_workload" in a.tags and a.element == Element.PROCESS:
                a.element = Element.DATA_STORE
            if a.kind == "Container":
                continue
            # a workload whose containers are all databases is a data store
            if "workload" in a.tags:
                runs = [f.target for f in self.m.outgoing(a.id) if f.kind == "runs"]
                if runs and all("datastore_workload" in self.m.assets[r].tags
                                for r in runs if r in self.m.assets):
                    a.element = Element.DATA_STORE
                    a.tag("datastore_workload")


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def _backend_service(backend: Dict[str, Any]) -> Optional[Tuple[str, Optional[int]]]:
    if not isinstance(backend, dict):
        return None
    svc = backend.get("service")
    if isinstance(svc, dict) and svc.get("name"):                    # networking.k8s.io/v1
        port = (svc.get("port") or {})
        return svc["name"], port.get("number") or port.get("name")
    if backend.get("serviceName"):                                   # extensions/v1beta1
        return backend["serviceName"], backend.get("servicePort")
    return None


TLS_PORTS = {443, 8443, 6443, 9443, 5671, 636}


def _port_summary(ports: List[Dict[str, Any]]) -> Optional[str]:
    if not ports:
        return None
    bits = []
    for p in ports[:4]:
        if not isinstance(p, dict):
            continue
        bits.append(f"{str(p.get('protocol', 'TCP')).lower()}:{p.get('port')}")
    return ",".join(bits) or None


def _is_tls_port(ports: List[Dict[str, Any]]) -> Optional[bool]:
    if not ports:
        return None
    nums = {p.get("port") for p in ports if isinstance(p, dict)}
    names = {str(p.get("name", "")).lower() for p in ports if isinstance(p, dict)}
    if nums & TLS_PORTS or any("https" in n or "tls" in n for n in names):
        return True
    return False


def _depends_on(body: Dict[str, Any]) -> List[str]:
    dep = body.get("depends_on")
    if isinstance(dep, list):
        return [str(d) for d in dep]
    if isinstance(dep, dict):
        return list(dep.keys())
    return []
