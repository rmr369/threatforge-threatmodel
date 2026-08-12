# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Ingestor base class, registry, and shared YAML utilities.

The one non-obvious thing here is `load_yaml_with_lines`: it parses a YAML file
twice -- once for values, once for node positions -- so every fact we later
report can point at a real file:line.  Findings without provenance are opinions;
findings with provenance are actionable.
"""

from __future__ import annotations

import os
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

from ..model import Asset, SourceRef, ThreatModel


# ---------------------------------------------------------------------------
# YAML loading with position tracking
# ---------------------------------------------------------------------------

class _SafeLoaderNoDup(yaml.SafeLoader):
    """SafeLoader that tolerates duplicate keys and unknown tags (Helm output)."""


def _unknown_tag(loader, tag_suffix, node):          # pragma: no cover - defensive
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


_SafeLoaderNoDup.add_multi_constructor("!", _unknown_tag)
_SafeLoaderNoDup.add_multi_constructor("tag:", _unknown_tag)


def _index_node(node: yaml.Node, prefix: str, out: Dict[str, int]) -> None:
    """Recursively record `pointer -> line number` for every YAML node."""
    if isinstance(node, yaml.MappingNode):
        if prefix:
            out.setdefault(prefix, node.start_mark.line + 1)
        for key_node, value_node in node.value:
            key = getattr(key_node, "value", None)
            if not isinstance(key, str):
                continue
            child = f"{prefix}.{key}" if prefix else key
            out[child] = key_node.start_mark.line + 1
            _index_node(value_node, child, out)
    elif isinstance(node, yaml.SequenceNode):
        for i, item in enumerate(node.value):
            child = f"{prefix}[{i}]"
            out[child] = item.start_mark.line + 1
            _index_node(item, child, out)
    else:
        if prefix:
            out.setdefault(prefix, node.start_mark.line + 1)


def load_yaml_with_lines(path: str) -> List[Tuple[Any, Dict[str, int]]]:
    """Return [(document, {pointer: line}), ...] for a multi-doc YAML file."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()

    # Helm/Go-template leftovers make the file unparseable; blank those lines out
    # rather than dropping the whole file.
    if "{{" in text and "}}" in text:
        text = _neutralise_go_templates(text)

    docs = list(yaml.load_all(text, Loader=_SafeLoaderNoDup))
    try:
        nodes = list(yaml.compose_all(text, Loader=_SafeLoaderNoDup))
    except Exception:
        nodes = []

    results: List[Tuple[Any, Dict[str, int]]] = []
    for i, doc in enumerate(docs):
        lines: Dict[str, int] = {}
        if i < len(nodes) and nodes[i] is not None:
            _index_node(nodes[i], "", lines)
        results.append((doc, lines))
    return results


_TPL_BLOCK = re.compile(r"\{\{-?.*?-?\}\}", re.DOTALL)


def _neutralise_go_templates(text: str) -> str:
    """Replace {{ ... }} with a placeholder so PyYAML can still parse structure."""
    out_lines = []
    for line in text.splitlines():
        stripped = line.strip()
        # A line that is *only* a template directive (if/range/end) becomes a comment.
        if stripped.startswith("{{") and stripped.endswith("}}"):
            out_lines.append("")
            continue
        out_lines.append(_TPL_BLOCK.sub("TF_TEMPLATED", line))
    return "\n".join(out_lines)


def ref(file: str, lines: Dict[str, int], pointer: str = "") -> SourceRef:
    """Build a SourceRef for a pointer inside a parsed document.

    Falls back up the pointer path, then to the document header, so a finding
    always lands somewhere useful in the file rather than on line 1.
    """
    line = lines.get(pointer)
    if line is None and pointer:
        parts = re.split(r"\.|(?=\[)", pointer)
        while parts and line is None:
            parts.pop()
            candidate = "".join(p if p.startswith("[") else ("." + p if i else p)
                                for i, p in enumerate(parts))
            line = lines.get(candidate)
    if line is None:
        for anchor in ("kind", "metadata.name", "apiVersion", "metadata"):
            line = lines.get(anchor)
            if line is not None:
                break
    return SourceRef(file=file, line=line, pointer=pointer or None)


# ---------------------------------------------------------------------------
# Discovery helpers
# ---------------------------------------------------------------------------

DEFAULT_EXCLUDES = {
    ".git", ".github/workflows", "node_modules", "vendor", ".venv", "venv",
    "__pycache__", ".terraform", "dist", "build", ".idea", ".vscode",
    # Our own output. The .thf export is a valid input format, so without this
    # a second scan re-ingests the first scan's report and the numbers change.
    "threatforge-out",
}

# Absolute paths the current run must not read, set by the pipeline from the
# resolved output directory. A module-level set is used because `walk_files` is
# a free function called from every ingestor; a run is single-threaded.
_OUTPUT_EXCLUSIONS: set = set()


def set_output_exclusions(paths: Iterable[str]) -> None:
    """Register directories written by this run so they are never read by it.

    Scans must be idempotent. Reports are written inside the scanned repository
    by default, and several of our output formats are also valid input formats,
    so without this a repeat scan silently analyses its own previous output.
    """
    _OUTPUT_EXCLUSIONS.clear()
    for p in paths:
        if p:
            _OUTPUT_EXCLUSIONS.add(os.path.abspath(p))


def _is_excluded_path(dirpath: str) -> bool:
    if not _OUTPUT_EXCLUSIONS:
        return False
    absolute = os.path.abspath(dirpath)
    return any(absolute == x or absolute.startswith(x + os.sep)
               for x in _OUTPUT_EXCLUSIONS)


def walk_files(root: str, extensions: Iterable[str], excludes: Optional[Iterable[str]] = None,
               filenames: Optional[Iterable[str]] = None) -> List[str]:
    """Find files by extension or exact filename, skipping noise directories."""
    exts = tuple(e.lower() for e in extensions)
    names = {n.lower() for n in (filenames or [])}
    skip = set(excludes) if excludes is not None else set(DEFAULT_EXCLUDES)
    found: List[str] = []
    for dirpath, dirnames, files in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in skip
                       and not d.startswith(".git")
                       and not _is_excluded_path(os.path.join(dirpath, d))]
        if _is_excluded_path(dirpath):
            continue
        for fname in files:
            low = fname.lower()
            if low in names or (exts and low.endswith(exts)):
                found.append(os.path.join(dirpath, fname))
    return sorted(found)


# ---------------------------------------------------------------------------
# Ingestor contract
# ---------------------------------------------------------------------------

class Ingestor(ABC):
    """Turns some source of truth into Assets on the ThreatModel.

    Ingestors MUST NOT create relationships or findings -- that is the job of
    later stages.  They only produce nodes plus enough raw spec for the rest of
    the pipeline to reason about.
    """

    name: str = "base"
    provider: str = "unknown"

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}
        self.stats: Dict[str, Any] = {"files": 0, "assets": 0, "skipped": 0}

    @abstractmethod
    def detect(self, root: str) -> bool:
        """Cheap check: is there anything here for me to do?"""

    @abstractmethod
    def ingest(self, root: str, model: ThreatModel) -> None:
        """Populate `model.assets`."""

    # -- helper for subclasses -------------------------------------------
    def emit(self, model: ThreatModel, asset: Asset) -> Asset:
        self.stats["assets"] += 1
        return model.add_asset(asset)


_REGISTRY: Dict[str, type] = {}


def register(cls: type) -> type:
    _REGISTRY[cls.name] = cls
    return cls


def available() -> Dict[str, type]:
    return dict(_REGISTRY)


def build(names: Optional[Iterable[str]] = None,
          config: Optional[Dict[str, Any]] = None) -> List[Ingestor]:
    """Instantiate ingestors by name (or all of them)."""
    cfg = config or {}
    wanted = list(names) if names else list(_REGISTRY)
    out = []
    for n in wanted:
        cls = _REGISTRY.get(n)
        if cls:
            out.append(cls(cfg.get(n, {})))
    return out
