# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Terraform ingestor.

Three input modes, in order of fidelity:
  1. `terraform show -json plan.out`  -> planned values (best: interpolations resolved)
  2. `terraform.tfstate`              -> actual deployed state
  3. `*.tf` HCL source                -> parsed with python-hcl2 if available,
                                         otherwise a bounded regex block reader

Cloud resources land in the same Asset model as Kubernetes objects, so a flow
from a pod to an RDS instance is a first-class edge rather than a footnote.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from ..model import Asset, DataClass, Element, SourceRef, ThreatModel
from .base import Ingestor, register, walk_files

try:                                    # optional, much better fidelity
    import hcl2                         # type: ignore
    HAVE_HCL2 = True
except Exception:                       # pragma: no cover
    hcl2 = None
    HAVE_HCL2 = False


# Resource types that hold data at rest -> data stores in the DFD.
DATA_STORE_TYPES = {
    "aws_s3_bucket", "aws_db_instance", "aws_rds_cluster", "aws_dynamodb_table",
    "aws_elasticache_cluster", "aws_efs_file_system", "aws_ebs_volume",
    "aws_secretsmanager_secret", "aws_ssm_parameter", "aws_kms_key",
    "aws_redshift_cluster", "aws_docdb_cluster", "aws_sqs_queue", "aws_sns_topic",
    "azurerm_storage_account", "azurerm_sql_database", "azurerm_key_vault",
    "azurerm_cosmosdb_account", "azurerm_postgresql_server",
    "google_storage_bucket", "google_sql_database_instance", "google_bigquery_dataset",
    "google_secret_manager_secret", "google_spanner_database", "google_pubsub_topic",
}

# Resource types that are network entry points -> potential external exposure.
EDGE_TYPES = {
    "aws_lb", "aws_alb", "aws_elb", "aws_api_gateway_rest_api", "aws_apigatewayv2_api",
    "aws_cloudfront_distribution", "aws_route53_record", "aws_globalaccelerator_accelerator",
    "azurerm_public_ip", "azurerm_application_gateway", "azurerm_lb",
    "google_compute_global_forwarding_rule", "google_compute_forwarding_rule",
}

COMPUTE_TYPES = {
    "aws_instance", "aws_ecs_service", "aws_ecs_task_definition", "aws_lambda_function",
    "aws_eks_cluster", "aws_eks_node_group", "aws_autoscaling_group", "aws_batch_job_definition",
    "azurerm_virtual_machine", "azurerm_linux_virtual_machine", "azurerm_kubernetes_cluster",
    "azurerm_function_app", "azurerm_container_group",
    "google_compute_instance", "google_cloud_run_service", "google_container_cluster",
    "google_cloudfunctions_function",
}

IDENTITY_TYPES = {
    "aws_iam_role", "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user",
    "aws_iam_group", "aws_iam_role_policy_attachment", "aws_iam_instance_profile",
    "azurerm_role_assignment", "azurerm_role_definition",
    "google_project_iam_binding", "google_project_iam_member", "google_service_account",
}

NETWORK_TYPES = {
    "aws_security_group", "aws_security_group_rule", "aws_vpc", "aws_subnet",
    "aws_network_acl", "aws_route_table", "aws_vpc_endpoint",
    "azurerm_network_security_group", "azurerm_network_security_rule",
    "azurerm_virtual_network", "azurerm_subnet",
    "google_compute_firewall", "google_compute_network", "google_compute_subnetwork",
}


_SENSITIVE = re.compile(r"(secret|password|passwd|token|key|credential|private)", re.I)


def tf_element(rtype: str) -> Element:
    if rtype in DATA_STORE_TYPES:
        return Element.DATA_STORE
    return Element.PROCESS


def tf_id(rtype: str, rname: str, module: str = "") -> str:
    prefix = f"{module}." if module and module != "root" else ""
    return f"tf:{prefix}{rtype}.{rname}"


@register
class TerraformIngestor(Ingestor):
    name = "terraform"
    provider = "terraform"

    def detect(self, root: str) -> bool:
        return bool(walk_files(root, (".tf", ".tfstate"),
                               filenames=["terraform.tfstate", "tfplan.json", "plan.json"]))

    def ingest(self, root: str, model: ThreatModel) -> None:
        handled_dirs = set()

        # 1. plan / state JSON (highest fidelity)
        for path in walk_files(root, (".tfstate",),
                               filenames=["tfplan.json", "plan.json", "terraform.tfstate"]):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    payload = json.load(fh)
            except Exception as exc:
                model.error("ingest.terraform", f"{path}: {exc}")
                continue
            rel = os.path.relpath(path, root)
            self.stats["files"] += 1
            handled_dirs.add(os.path.dirname(path))
            if "planned_values" in payload or "values" in payload:
                self._from_plan(payload, rel, model)
            elif "resources" in payload:
                self._from_state(payload, rel, model)

        # 2. raw HCL for anything not covered by a plan
        for path in walk_files(root, (".tf",)):
            if os.path.dirname(path) in handled_dirs:
                continue
            self._from_hcl(path, root, model)

    # -- plan JSON --------------------------------------------------------
    def _from_plan(self, payload: Dict[str, Any], rel: str, model: ThreatModel) -> None:
        root_module = ((payload.get("planned_values") or payload.get("values") or {})
                       .get("root_module") or {})
        self._walk_module(root_module, rel, model, "root")

    def _walk_module(self, module: Dict[str, Any], rel: str,
                     model: ThreatModel, addr: str) -> None:
        for res in module.get("resources") or []:
            self._emit(
                rtype=res.get("type", "unknown"),
                rname=res.get("name", "unnamed"),
                values=res.get("values") or {},
                rel=rel, model=model, module=addr,
                provider=res.get("provider_name", ""),
            )
        for child in module.get("child_modules") or []:
            self._walk_module(child, rel, model, child.get("address", addr))

    # -- state JSON -------------------------------------------------------
    def _from_state(self, payload: Dict[str, Any], rel: str, model: ThreatModel) -> None:
        for res in payload.get("resources") or []:
            if res.get("mode") == "data":
                continue
            for inst in res.get("instances") or []:
                self._emit(
                    rtype=res.get("type", "unknown"),
                    rname=res.get("name", "unnamed"),
                    values=inst.get("attributes") or {},
                    rel=rel, model=model,
                    module=res.get("module", "root"),
                    provider=res.get("provider", ""),
                )

    # -- HCL --------------------------------------------------------------
    _BLOCK = re.compile(
        r'^\s*resource\s+"([A-Za-z0-9_\-]+)"\s+"([A-Za-z0-9_\-]+)"\s*\{', re.M)

    def _from_hcl(self, path: str, root: str, model: ThreatModel) -> None:
        rel = os.path.relpath(path, root)
        self.stats["files"] += 1
        try:
            text = open(path, "r", encoding="utf-8", errors="replace").read()
        except Exception as exc:
            model.error("ingest.terraform", f"{rel}: {exc}")
            return

        if HAVE_HCL2:
            try:
                parsed = hcl2.loads(text)
                for block in parsed.get("resource", []):
                    for rtype, bodies in block.items():
                        for rname, values in bodies.items():
                            self._emit(rtype, rname, values if isinstance(values, dict) else {},
                                       rel, model, "root", "", line=self._line_of(text, rtype, rname))
                return
            except Exception as exc:
                model.error("ingest.terraform", f"hcl2 parse failed, using fallback: {exc}",
                            file=rel)

        # Fallback: brace-balanced block extraction + flat attribute scrape.
        for m in self._BLOCK.finditer(text):
            rtype, rname = m.group(1), m.group(2)
            body = _balanced_body(text, m.end() - 1)
            values = _scrape_attrs(body)
            values["__raw__"] = body[:4000]
            line = text[:m.start()].count("\n") + 1
            self._emit(rtype, rname, values, rel, model, "root", "", line=line)

    @staticmethod
    def _line_of(text: str, rtype: str, rname: str) -> Optional[int]:
        m = re.search(rf'resource\s+"{re.escape(rtype)}"\s+"{re.escape(rname)}"', text)
        return text[:m.start()].count("\n") + 1 if m else None

    # -- emit -------------------------------------------------------------
    def _emit(self, rtype: str, rname: str, values: Dict[str, Any], rel: str,
              model: ThreatModel, module: str, provider: str,
              line: Optional[int] = None) -> None:
        asset = Asset(
            id=tf_id(rtype, rname, module),
            kind=rtype,
            name=rname,
            provider="terraform",
            namespace=module if module and module != "root" else None,
            element=tf_element(rtype),
            spec={"values": values, "resource_type": rtype, "tf_provider": provider},
            source=SourceRef(file=rel, line=line, pointer=f"resource.{rtype}.{rname}"),
        )
        cloud = rtype.split("_", 1)[0]
        asset.tag(f"cloud:{cloud}")
        if rtype in DATA_STORE_TYPES:
            asset.tag("cloud_data_store")
            asset.classify(DataClass.PII)
        if rtype in EDGE_TYPES:
            asset.tag("cloud_edge", "internet_facing_candidate")
        if rtype in COMPUTE_TYPES:
            asset.tag("cloud_compute")
        if rtype in IDENTITY_TYPES:
            asset.tag("cloud_identity", "identity")
        if rtype in NETWORK_TYPES:
            asset.tag("cloud_network", "network")
        if "secret" in rtype or "kms" in rtype or "key_vault" in rtype:
            asset.classify(DataClass.SECRET)

        # Any literal-looking credential in the attributes is worth flagging later.
        for k, v in (values or {}).items():
            if _SENSITIVE.search(str(k)) and isinstance(v, str) and v and "${" not in v:
                asset.tag("possible_hardcoded_secret")
                break

        self.emit(model, asset)


# ---------------------------------------------------------------------------
# HCL fallback helpers
# ---------------------------------------------------------------------------

def _balanced_body(text: str, open_brace_idx: int) -> str:
    depth = 0
    for i in range(open_brace_idx, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace_idx + 1:i]
    return text[open_brace_idx + 1:]


_ATTR = re.compile(r'^\s*([A-Za-z0-9_]+)\s*=\s*(.+?)\s*$', re.M)


def _scrape_attrs(body: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for m in _ATTR.finditer(body):
        key, raw = m.group(1), m.group(2).strip()
        if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
            out[key] = raw[1:-1]
        elif raw in ("true", "false"):
            out[key] = raw == "true"
        elif re.fullmatch(r"-?\d+", raw):
            out[key] = int(raw)
        elif raw.startswith("["):
            items = re.findall(r'"([^"]*)"', raw)
            out[key] = items or raw
        else:
            out[key] = raw
    # capture nested ingress/egress cidr blocks for security-group rules
    cidrs = re.findall(r'cidr_blocks\s*=\s*\[([^\]]*)\]', body)
    if cidrs:
        out["cidr_blocks"] = re.findall(r'"([^"]*)"', " ".join(cidrs))
    ports = re.findall(r'from_port\s*=\s*(\d+)', body)
    if ports:
        out["from_port_list"] = [int(p) for p in ports]
    return out
