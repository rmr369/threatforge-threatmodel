"""
Docker ingestor: Dockerfiles (build-time posture) and docker-compose (runtime topology).

Build-time matters because a container that runs as root in the image will run
as root at runtime unless the orchestrator overrides it -- and most don't.
"""

from __future__ import annotations

import os
import re
import shlex
from typing import Any, Dict, List, Optional

from ..model import Asset, DataClass, Element, SourceRef, ThreatModel
from .base import Ingestor, load_yaml_with_lines, ref, register, walk_files


COMPOSE_FILES = ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]

_SECRET_ARG = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)",
    re.I)
_LOOKS_LIKE_VALUE = re.compile(r"=[^\s\"']{8,}|=\"[^\"]{8,}\"|='[^']{8,}'")


# ---------------------------------------------------------------------------
# Dockerfile
# ---------------------------------------------------------------------------

@register
class DockerfileIngestor(Ingestor):
    name = "dockerfile"
    provider = "docker"

    def detect(self, root: str) -> bool:
        return bool(self._find(root))

    @staticmethod
    def _find(root: str) -> List[str]:
        hits = walk_files(root, (".dockerfile",), filenames=["dockerfile"])
        # also catch Dockerfile.prod / Dockerfile.api
        for dirpath, dirnames, files in os.walk(root):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            for f in files:
                if f.lower().startswith("dockerfile") and os.path.join(dirpath, f) not in hits:
                    hits.append(os.path.join(dirpath, f))
        return sorted(set(hits))

    def ingest(self, root: str, model: ThreatModel) -> None:
        for path in self._find(root):
            rel = os.path.relpath(path, root)
            try:
                lines = open(path, "r", encoding="utf-8", errors="replace").read().splitlines()
            except Exception as exc:
                model.error("ingest.dockerfile", f"{rel}: {exc}")
                continue
            self.stats["files"] += 1
            for stage in self._parse(lines, rel):
                asset = Asset(
                    id=f"docker:image:{rel}#{stage['stage_name']}",
                    kind="DockerImage",
                    name=stage["stage_name"],
                    provider="docker",
                    element=Element.PROCESS,
                    spec=stage,
                    source=SourceRef(file=rel, line=stage.get("from_line")),
                )
                asset.tag("container_image", "build_time")
                if stage.get("hardcoded_secret_refs"):
                    asset.tag("possible_hardcoded_secret")
                    asset.classify(DataClass.CREDENTIAL)
                if stage.get("final"):
                    asset.tag("final_stage")
                self.emit(model, asset)

    # -- parse ------------------------------------------------------------
    def _parse(self, lines: List[str], rel: str) -> List[Dict[str, Any]]:
        stages: List[Dict[str, Any]] = []
        current: Optional[Dict[str, Any]] = None
        buffer = ""
        for idx, raw in enumerate(lines, start=1):
            line = raw.rstrip()
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if line.endswith("\\"):
                buffer += line[:-1] + " "
                continue
            stmt = (buffer + line).strip()
            buffer = ""
            parts = stmt.split(None, 1)
            if not parts:
                continue
            instr = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            if instr == "FROM":
                toks = arg.split()
                base = toks[0] if toks else "scratch"
                alias = toks[2] if len(toks) >= 3 and toks[1].lower() == "as" else base
                current = {
                    "stage_name": alias,
                    "base_image": base,
                    "from_line": idx,
                    "file": rel,
                    "user": None,
                    "user_line": None,
                    "exposed_ports": [],
                    "add_remote": [],
                    "run_commands": [],
                    "env": {},
                    "build_args": [],
                    "healthcheck": False,
                    "copy_chown": [],
                    "hardcoded_secret_refs": [],
                    "final": False,
                }
                stages.append(current)
                continue
            if current is None:
                continue

            if instr == "USER":
                current["user"] = arg.strip()
                current["user_line"] = idx
            elif instr == "EXPOSE":
                current["exposed_ports"] += [p for p in arg.split()]
            elif instr == "ADD":
                toks = shlex.split(arg) if arg else []
                if any(t.startswith(("http://", "https://", "git@")) for t in toks):
                    current["add_remote"].append({"value": arg, "line": idx})
            elif instr == "RUN":
                current["run_commands"].append({"value": arg, "line": idx})
                if _SECRET_ARG.search(arg) and _LOOKS_LIKE_VALUE.search(arg):
                    current["hardcoded_secret_refs"].append({"value": arg[:200], "line": idx})
                if re.search(r"curl[^|]*\|\s*(ba)?sh", arg) or re.search(r"wget[^|]*\|\s*(ba)?sh", arg):
                    current.setdefault("pipe_to_shell", []).append({"value": arg[:200], "line": idx})
            elif instr in ("ENV", "ARG"):
                m = re.match(r"([A-Za-z0-9_]+)[ =](.*)", arg)
                if m:
                    current["env"][m.group(1)] = m.group(2).strip().strip('"')
                    if _SECRET_ARG.search(m.group(1)) and len(m.group(2).strip()) > 4:
                        current["hardcoded_secret_refs"].append(
                            {"value": f"{instr} {m.group(1)}=***", "line": idx})
                if instr == "ARG":
                    current["build_args"].append(arg.split("=")[0])
            elif instr == "HEALTHCHECK":
                current["healthcheck"] = "NONE" not in arg.upper()
            elif instr == "COPY" and "--chown" in arg:
                current["copy_chown"].append(arg)

        if stages:
            stages[-1]["final"] = True
        return stages


# ---------------------------------------------------------------------------
# docker-compose
# ---------------------------------------------------------------------------

@register
class ComposeIngestor(Ingestor):
    name = "compose"
    provider = "compose"

    def detect(self, root: str) -> bool:
        return bool(walk_files(root, (), filenames=COMPOSE_FILES))

    def ingest(self, root: str, model: ThreatModel) -> None:
        for path in walk_files(root, (), filenames=COMPOSE_FILES):
            rel = os.path.relpath(path, root)
            try:
                docs = load_yaml_with_lines(path)
            except Exception as exc:
                model.error("ingest.compose", f"{rel}: {exc}")
                continue
            self.stats["files"] += 1
            for doc, lines in docs:
                if not isinstance(doc, dict):
                    continue
                for svc_name, svc in (doc.get("services") or {}).items():
                    if not isinstance(svc, dict):
                        continue
                    ptr = f"services.{svc_name}"
                    asset = Asset(
                        id=f"compose:service:{svc_name}",
                        kind="ComposeService",
                        name=svc_name,
                        provider="compose",
                        element=Element.PROCESS,
                        spec={"service": svc, "compose_file": rel},
                        source=ref(rel, lines, ptr),
                    )
                    asset.tag("container")
                    if svc.get("ports"):
                        asset.tag("host_port_published")
                        if any(_binds_all_interfaces(p) for p in svc["ports"]):
                            asset.tag("internet_facing_candidate")
                    if svc.get("privileged"):
                        asset.tag("privileged")
                    if str(svc.get("network_mode", "")).lower() == "host":
                        asset.tag("host_network")
                    for env_key in _compose_env_keys(svc):
                        if _SECRET_ARG.search(env_key):
                            asset.tag("plaintext_secret_env")
                            asset.classify(DataClass.CREDENTIAL)
                            break
                    for vol in svc.get("volumes") or []:
                        s = vol if isinstance(vol, str) else str(vol.get("source", ""))
                        if s.startswith("/var/run/docker.sock"):
                            asset.tag("docker_socket_mount")
                        if s.startswith("/") and not s.startswith("/var/lib/docker"):
                            asset.tag("host_path_mount")
                    self.emit(model, asset)

                for vol_name, vol in (doc.get("volumes") or {}).items():
                    self.emit(model, Asset(
                        id=f"compose:volume:{vol_name}",
                        kind="ComposeVolume",
                        name=vol_name,
                        provider="compose",
                        element=Element.DATA_STORE,
                        spec={"volume": vol or {}},
                        source=ref(rel, lines, f"volumes.{vol_name}"),
                    ))


def _binds_all_interfaces(port_entry: Any) -> bool:
    if isinstance(port_entry, dict):
        return not port_entry.get("host_ip") or port_entry.get("host_ip") == "0.0.0.0"
    s = str(port_entry)
    if s.count(":") >= 2:
        return s.startswith("0.0.0.0:")
    return ":" in s          # "8080:80" publishes on all interfaces


def _compose_env_keys(svc: Dict[str, Any]) -> List[str]:
    env = svc.get("environment")
    if isinstance(env, dict):
        return [k for k, v in env.items() if v not in (None, "")]
    if isinstance(env, list):
        return [str(e).split("=")[0] for e in env if "=" in str(e)]
    return []
