# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Local web application: `threatforge serve`.

A single-user app on localhost, backed by the SQLite store. No framework, no
build step, no new dependencies -- `http.server` and `sqlite3` are both in the
standard library. That is a deliberate trade: a security tool that needs npm
install and a Flask stack before it runs is a security tool people don't run.

Security, even on localhost
---------------------------
A server on 127.0.0.1 is not automatically safe. Three attacks apply and all
are cheap to close:

* **DNS rebinding.** A page on the internet resolves its own hostname to
  127.0.0.1 and then talks to this server with the browser's cooperation. The
  defence is to reject any request whose `Host` header is not literally
  localhost -- rebinding cannot forge that.
* **Cross-origin state change.** Any website can POST to localhost. It cannot
  *read* the response, but a blind POST that reassigns findings or clones a
  repository is still bad. Mutating routes require a per-session token that is
  only present in the served page.
* **Analysing untrusted code.** Helm and Kustomize rendering execute logic from
  the repository being scanned. Sources fetched from git or uploaded are marked
  untrusted and both are disabled for them. See `sources.py`.

The socket binds to 127.0.0.1, never 0.0.0.0.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

from . import config as cfgmod
from . import pipeline, sources
from .sla import ALL_STATUSES, OPEN_STATUSES, Policy, summarise
from .sources import Source, SourceError
from .store import Store, default_db_path
from .webui import PAGE

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}

# A fingerprint of the served page. Two people looking at the same screenshot
# cannot otherwise tell a stale process from a stale install, and both of those
# look exactly like "the change did not work".
BUILD = hashlib.sha1(PAGE.encode("utf-8")).hexdigest()[:8]
MAX_UPLOAD_BYTES = 96 * 1024 * 1024

OVERLAY_KEY = "overlay"


class AppState:
    """Everything a request handler needs, without globals."""

    def __init__(self, root: str, store: Store, cfg: Dict[str, Any]) -> None:
        self.base_root = os.path.abspath(root)
        self.store = store
        self.cfg = cfg
        self.policy = Policy.from_config(cfg)
        self.token = secrets.token_urlsafe(24)
        self.source: Source = sources.Source(
            root=self.base_root, kind="path",
            label=cfg.get("project") or os.path.basename(self.base_root),
            trusted=True, detail={"path": self.base_root})
        self.workspace = os.path.join(
            os.path.dirname(store.path), "workspace")
        os.makedirs(self.workspace, exist_ok=True)
        self._model = None
        self._lock = threading.Lock()
        self.scanning = False
        self.last_error: Optional[str] = None

    # -- overlay (what the diagram editor writes) -------------------------
    @property
    def overlay_path(self) -> str:
        d = os.path.join(self.workspace, "overlay")
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, "threatforge-overlay.yml")

    def read_overlay(self) -> str:
        if os.path.exists(self.overlay_path):
            return open(self.overlay_path, encoding="utf-8").read()
        return ""

    def write_overlay(self, text: str) -> None:
        with open(self.overlay_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text or "")

    # -- documentation -----------------------------------------------------
    @property
    def doc_path(self) -> str:
        d = os.path.join(self.workspace, "overlay")
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, "document.json")

    def read_doc(self) -> Dict[str, Any]:
        if os.path.exists(self.doc_path):
            try:
                with open(self.doc_path, encoding="utf-8") as fh:
                    data = json.load(fh)
                return data if isinstance(data, dict) else {}
            except Exception:
                return {}
        return {}

    def write_doc(self, data: Dict[str, Any]) -> None:
        with open(self.doc_path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(data if isinstance(data, dict) else {}, fh, indent=1)

    # -- layout ------------------------------------------------------------
    # Geometry lives beside the overlay rather than inside it. The overlay is
    # semantic YAML a human edits and commits; where the boxes sit is not, and
    # mixing them would make every nudge of a shape a diff on the model.
    @property
    def layout_path(self) -> str:
        d = os.path.join(self.workspace, "overlay")
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, "layout.json")

    def read_layout(self) -> Dict[str, Any]:
        if os.path.exists(self.layout_path):
            try:
                with open(self.layout_path, encoding="utf-8") as fh:
                    data = json.load(fh)
                return data if isinstance(data, dict) else {}
            except Exception:
                return {}
        return {}

    def write_layout(self, data: Dict[str, Any]) -> None:
        with open(self.layout_path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(data if isinstance(data, dict) else {}, fh, indent=1)

    # -- scanning ----------------------------------------------------------
    def set_source(self, spec: Dict[str, Any]) -> Source:
        kind = (spec.get("kind") or "path").lower()
        ws = self.workspace
        if kind == "path":
            return sources.from_path(spec.get("path") or self.base_root)
        if kind == "git":
            git_cfg = (self.cfg.get("serve", {}) or {}).get("git", {}) or {}
            return sources.from_git(
                spec.get("url", ""), spec.get("ref") or None, workspace=ws,
                allow_any_host=bool(git_cfg.get("allow_any_host", False)),
                extra_hosts=git_cfg.get("extra_hosts") or [])
        if kind == "upload":
            raw = spec.get("data") or ""
            try:
                blob = base64.b64decode(raw, validate=True)
            except Exception:
                raise SourceError("upload was not valid base64")
            if len(blob) > MAX_UPLOAD_BYTES:
                raise SourceError(
                    f"upload is {len(blob) // (1024*1024)} MB; the limit is "
                    f"{MAX_UPLOAD_BYTES // (1024*1024)} MB")
            return sources.from_zip_bytes(blob, spec.get("name") or "upload",
                                          workspace=ws)
        raise SourceError(f"unknown source kind: {kind}")

    def rescan(self, spec: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        with self._lock:
            if self.scanning:
                return {"error": "a scan is already running"}
            self.scanning = True
        previous = self.source
        try:
            source = self.set_source(spec) if spec else self.source
            cfg = sources.config_for(source, self.cfg)

            # The editor's overlay and anything imported through the UI are
            # merged into every scan. They live in the workspace, not in the
            # repository, so each reader is pointed at them explicitly.
            overlay_dir = os.path.dirname(self.overlay_path)
            cfg = dict(cfg)
            if os.path.exists(self.overlay_path):
                cfg["manual"] = {"paths": [self.overlay_path]}
            if os.path.isdir(overlay_dir):
                for reader in ("tmt", "drawio"):
                    opts = dict(cfg.get(reader) or {})
                    opts["paths"] = list(opts.get("paths") or []) + [overlay_dir]
                    cfg[reader] = opts

            model = pipeline.run(source.root, cfg)
            self._model = model
            self.source = source
            self.cfg_effective = cfg
            if spec and previous is not source and previous.cleanup:
                previous.dispose()

            delta = self.store.record_scan(model, source.root)
            self.last_error = None
            return {
                "ok": True,
                "source": sources.describe(source),
                "summary": model.to_dict()["summary"],
                "delta": {k: (len(v) if isinstance(v, list) else v)
                          for k, v in delta.items()},
                "warnings": [e.get("message", "")[:200] for e in model.errors[:10]],
                # Threats carried in an imported .tm7 or .drawio. Kept as
                # context rather than converted into findings -- they were
                # generated by a template, not by evidence, and folding them in
                # would undo the thing this engine exists to fix. Reported so
                # nothing arrives silently discarded.
                "imported_threats": len(model.metadata.get("manual_threats") or []),
                "untrusted": not source.trusted,
            }
        except SourceError as exc:
            self.last_error = str(exc)
            return {"error": str(exc)}
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            return {"error": self.last_error}
        finally:
            self.scanning = False

    @property
    def model(self):
        return self._model

    @property
    def project(self) -> str:
        return self.source.label


def _json(handler: BaseHTTPRequestHandler, payload: Any, status: int = 200) -> None:
    body = json.dumps(payload, default=str).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-ThreatForge-Build", BUILD)
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def _download_bytes(handler: BaseHTTPRequestHandler, body: bytes,
                    filename: str, mime: str) -> None:
    handler.send_response(200)
    handler.send_header("Content-Type", mime)
    handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.end_headers()
    handler.wfile.write(body)


def _download(handler: BaseHTTPRequestHandler, text: str, filename: str,
              mime: str) -> None:
    body = text.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", f"{mime}; charset=utf-8")
    handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-ThreatForge-Build", BUILD)
    handler.end_headers()
    handler.wfile.write(body)


EXPORTS = {
    "tm7": ("threat-model.tm7", "application/xml"),
    "drawio": ("threat-model.drawio", "application/xml"),
    "thf": ("threat-model.thf", "application/yaml"),
    "json": ("threat-model.json", "application/json"),
    "sarif": ("threatforge.sarif", "application/json"),
    "markdown": ("threat-model.md", "text/markdown"),
    "html": ("security-report.html", "text/html"),
    "mermaid": ("dfd.mmd", "text/plain"),
    # The whole workspace in one file: diagram, attributes, layout and triage
    # state. `.thf` is an interchange document; `.tfm` is a save file.
    "tfm": ("threat-model.tfm", "application/json"),
    "xlsx": ("threat-model.xlsx",
             "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    "executive": ("executive-summary.html", "text/html"),
}

TFM_VERSION = 1


def workspace_document(state: "AppState") -> Dict[str, Any]:
    """Everything a person would be upset to lose, in one JSON document.

    Deliberately not a zip: a save format you cannot read in a text editor or
    diff in a pull request is a save format you cannot trust. It is also not the
    scanned model -- that is regenerated from the manifests on every scan, and
    freezing a copy would create two sources of truth that quietly disagree.
    """
    rows = state.store.findings(policy=state.policy)
    return {
        "format": "threatforge-model",
        "version": TFM_VERSION,
        "generated": _now_iso(),
        "project": state.project,
        "source": sources.describe(state.source),
        "overlay": state.read_overlay(),
        "layout": state.read_layout(),
        "document": state.read_doc(),
        # Only the human decisions. Everything else is derivable by re-scanning,
        # and a stale copy of a derived thing is worse than no copy.
        "triage": [
            {"id": r["id"], "rule_id": r["rule_id"], "component": r["component"],
             "status": r["status"], "owner": r["owner"], "notes": r["notes"],
             "first_seen": r["first_seen"], "due_override": r.get("due_override")}
            for r in rows
            if r.get("status") not in (None, "open") or r.get("owner")
            or r.get("notes")
        ],
        "summary": (state.model.to_dict()["summary"] if state.model else {}),
    }


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def make_handler(state: AppState):

    class Handler(BaseHTTPRequestHandler):
        server_version = "ThreatForge"
        sys_version = ""

        # -- guards -------------------------------------------------------
        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
            return host in {h.strip("[]") for h in ALLOWED_HOSTS}

        def _token_ok(self) -> bool:
            supplied = self.headers.get("X-ThreatForge-Token", "")
            return secrets.compare_digest(supplied, state.token)

        def log_message(self, fmt: str, *args) -> None:
            return

        # -- routing ------------------------------------------------------
        def do_GET(self) -> None:                            # noqa: N802
            if not self._host_ok():
                return _json(self, {"error": "host not allowed"}, 403)
            url = urlparse(self.path)
            query = {k: v[0] for k, v in parse_qs(url.query).items()}
            try:
                self._get(url.path, query)
            except Exception as exc:
                _json(self, {"error": f"{type(exc).__name__}: {exc}"}, 500)

        def do_POST(self) -> None:                           # noqa: N802
            if not self._host_ok():
                return _json(self, {"error": "host not allowed"}, 403)
            if not self._token_ok():
                return _json(self, {"error": "missing or invalid session token"}, 403)
            url = urlparse(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_UPLOAD_BYTES + (2 * 1024 * 1024):
                return _json(self, {"error": "request body too large"}, 413)
            raw = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                return _json(self, {"error": "body is not valid JSON"}, 400)
            try:
                self._post(url.path, body)
            except SourceError as exc:
                _json(self, {"error": str(exc)}, 400)
            except KeyError as exc:
                _json(self, {"error": str(exc)}, 404)
            except ValueError as exc:
                _json(self, {"error": str(exc)}, 400)
            except Exception as exc:
                _json(self, {"error": f"{type(exc).__name__}: {exc}"}, 500)

        # -- GET ----------------------------------------------------------
        def _get(self, path: str, q: Dict[str, str]) -> None:
            if path in ("/", "/index.html"):
                page = (PAGE.replace("__TOKEN__", state.token)
                            .replace("__PROJECT__", state.project)
                            .replace("__ROOT__", state.source.root.replace("\\", "/")))
                body = page.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                # The page is generated per request and changes whenever the
                # code does. Without this the browser caches it heuristically
                # and keeps serving yesterday's app after a restart -- which
                # looks exactly like a change that did not work, and cost this
                # project several rounds of confusion.
                self.send_header("Cache-Control",
                                 "no-store, no-cache, must-revalidate, max-age=0")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.send_header("ETag", f'"{BUILD}"')
                self.end_headers()
                self.wfile.write(body)
                return

            if path == "/api/bootstrap":
                return _json(self, {
                    "project": state.project,
                    "source": sources.describe(state.source),
                    "base_root": state.base_root,
                    "projects": state.store.projects(),
                    "owners": state.store.owners(),
                    "statuses": ALL_STATUSES,
                    "policy": state.policy.windows,
                    "stats": state.store.stats(),
                    "has_model": state.model is not None,
                    "scans": state.store.scans(30),
                    "exports": sorted(EXPORTS),
                    "allowed_git_hosts": sorted(sources.DEFAULT_GIT_HOSTS),
                    "build": BUILD,
                })

            if path == "/api/findings":
                statuses = ([s for s in q["status"].split(",") if s]
                            if q.get("status") else None)
                rows = state.store.findings(q.get("project") or None,
                                            statuses, state.policy)
                return _json(self, {"findings": rows, "count": len(rows)})

            if path.startswith("/api/findings/") and path.endswith("/events"):
                fid = unquote(path.split("/")[3])
                return _json(self, {"events": state.store.events(fid)})

            if path == "/api/sla":
                rows = state.store.findings(q.get("project") or None,
                                            policy=state.policy)
                return _json(self, summarise(state.policy, rows))

            if path == "/api/scans":
                return _json(self, {"scans": state.store.scans()})

            if path == "/api/overlay":
                return _json(self, {"overlay": state.read_overlay(),
                                    "layout": state.read_layout()})

            if path == "/api/layout":
                return _json(self, {"layout": state.read_layout()})

            if path == "/api/version":
                import threatforge
                return _json(self, {
                    "version": threatforge.__version__,
                    "build": BUILD,
                    "module": os.path.dirname(os.path.abspath(__file__)),
                })

            if path == "/api/catalog":
                from . import library
                cat = library.catalog()
                cat["doc_fields"] = library.DOC_FIELDS
                cat["security_questions"] = library.SECURITY_QUESTIONS
                return _json(self, cat)

            if path == "/api/doc":
                return _json(self, {"doc": state.read_doc()})

            if path == "/api/graph":
                if state.model is None:
                    return _json(self, {"error": "no scan yet"}, 409)
                m = state.model
                # Risk and finding counts per component, so the canvas can be a
                # heat map rather than a box drawing.
                worst: Dict[str, str] = {}
                counts: Dict[str, int] = {}
                rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
                for f in m.active_findings:
                    counts[f.component] = counts.get(f.component, 0) + 1
                    lvl = f.risk_level.value
                    if rank.get(lvl, 0) > rank.get(worst.get(f.component, "info"), 0):
                        worst[f.component] = lvl
                return _json(self, {
                    "elements": [
                        {"id": a.id, "name": a.name, "kind": a.kind,
                         "type": a.element.value, "provider": a.provider,
                         "namespace": a.namespace,
                         "hops": a.facts.get("exposure_hops"),
                         "blast": a.facts.get("blast_radius"),
                         "hand": "hand_authored" in a.tags,
                         # Hand-authored assets echo back the fields the editor
                         # wrote, not the derived ones -- otherwise a save/reload
                         # cycle would quietly rewrite the user's own input.
                         "zone": (a.spec.get("manual") or {}).get("trust_zone")
                                 or next((t.split(":", 1)[1] for t in sorted(a.tags)
                                          if t.startswith("trust_zone:")), None),
                         "desc": (a.spec.get("manual") or {}).get("description")
                                 or a.facts.get("manual.description"),
                         "own_data": (a.spec.get("manual") or {}).get("data"),
                         "tech": sorted(x.split(":", 1)[1] for x in a.tags
                                        if x.startswith("tech:")),
                         "lib_type": a.facts.get("library.type"),
                         # Answered design attributes, back out the way they
                         # went in, so the properties panel round-trips.
                         "attrs": {k[5:]: v for k, v in a.facts.items()
                                   if k.startswith("attr.")
                                   and not k.startswith("attr._")},
                         "custom": {k[7:]: v for k, v in a.facts.items()
                                    if k.startswith("custom.")},
                         "unanswered": a.facts.get("attr._unanswered") or [],
                         "risk": worst.get(a.id),
                         "findings": counts.get(a.id, 0),
                         "boundaries": sorted(a.boundaries),
                         "tags": sorted(t for t in a.tags if ":" not in t)[:6],
                         "data": sorted(dc.value for dc in a.data_classes)}
                        for a in m.assets.values()
                        if a.element.value in ("process", "data_store",
                                               "external_entity")
                        and a.kind != "Container"],
                    "flows": [
                        {"id": f.id, "source": f.source, "target": f.target,
                         "kind": f.kind, "protocol": f.protocol,
                         "encrypted": f.encrypted, "authenticated": f.authenticated,
                         "name": f.details.get("name"),
                         "hand": bool(f.details.get("hand_authored")),
                         "attrs": f.details.get("attributes") or {},
                         "crosses": f.crosses_boundary}
                        for f in m.flows if f.kind not in ("runs", "protects")],
                    "boundaries": [b.to_dict() for b in m.boundaries.values()],
                })

            if path == "/api/dfd":
                if state.model is None:
                    return _json(self, {"error": "no scan in this session yet"}, 409)
                from .render import mermaid
                return _json(self, {
                    "dfd": mermaid.render_dfd(state.model, max_nodes=80),
                    "boundaries": mermaid.render_boundary_map(state.model),
                    "attack_paths": [
                        {**p.to_dict(),
                         "mermaid": mermaid.render_attack_path(state.model, i),
                         "hop_labels": [state.model.assets[h].display
                                        if h in state.model.assets else h
                                        for h in p.hops]}
                        for i, p in enumerate(state.model.attack_paths[:8])],
                })

            if path.startswith("/api/export/"):
                fmt = path.split("/")[3]
                if fmt not in EXPORTS:
                    return _json(self, {"error": f"unknown format: {fmt}"}, 404)
                if state.model is None and fmt != "tfm":
                    return _json(self, {"error": "run a scan first"}, 409)
                filename, mime = EXPORTS[fmt]
                from .render import (drawio, executive, html, markdown,
                                     mermaid, sarif, thf, tmt)
                text = {
                    "tm7": lambda: tmt.render(state.model, document=state.read_doc()),
                    "drawio": lambda: drawio.render(state.model),
                    "thf": lambda: thf.render(state.model),
                    "json": lambda: state.model.to_json(),
                    "sarif": lambda: sarif.render(state.model),
                    "markdown": lambda: markdown.render(state.model),
                    "html": lambda: html.render(state.model),
                    "mermaid": lambda: mermaid.render_dfd(state.model),
                    "tfm": lambda: json.dumps(workspace_document(state), indent=1),
                    "executive": lambda: executive.render(
                        state.model, state.read_doc()),
                }.get(fmt, lambda: None)()
                if fmt == "xlsx":
                    # Binary, so it does not go through the text writer.
                    from .render import xlsx as xlsx_render
                    blob = xlsx_render.render_bytes(state.model, state.read_doc())
                    return _download_bytes(self, blob, filename, mime)
                return _download(self, text, filename, mime)

            if path == "/api/model":
                if state.model is None:
                    return _json(self, {"error": "no scan in this session yet"}, 409)
                return _json(self, state.model.to_dict())

            _json(self, {"error": "not found"}, 404)

        # -- POST ---------------------------------------------------------
        def _post(self, path: str, body: Dict[str, Any]) -> None:
            if path == "/api/scan":
                result = state.rescan(body.get("source"))
                # A bad path or a blocked host is the caller's mistake, not a
                # success carrying an error field.
                return _json(self, result, 400 if result.get("error") else 200)

            if path == "/api/layout":
                state.write_layout(body.get("layout") or {})
                return _json(self, {"ok": True})

            if path == "/api/doc":
                state.write_doc(body.get("doc") or {})
                return _json(self, {"ok": True})

            if path == "/api/reset":
                # Clears the analysis, not the model. The diagram, overlay and
                # document survive; what goes is every finding, scan and audit
                # event, so the next STRIDE run starts from nothing.
                cleared = state.store.clear()
                if body.get("rescan"):
                    scan = state.rescan()
                    if scan.get("error"):
                        return _json(self, {"error": scan["error"]}, 400)
                    return _json(self, {"ok": True, "cleared": cleared,
                                        "scan": scan})
                state._model = None
                return _json(self, {"ok": True, "cleared": cleared})

            if path == "/api/ingest":
                # Drop a .tm7, .drawio or .thf straight onto the model. Written
                # into the workspace and picked up by the normal ingestors, so
                # an imported diagram is analysed by the same rules as a scanned
                # one rather than through a second, divergent path.
                name = os.path.basename(str(body.get("name") or "import"))
                text = body.get("text") or ""
                if len(text) > 24 * 1024 * 1024:
                    return _json(self, {"error": "file is too large"}, 400)
                ext = os.path.splitext(name)[1].lower()
                if ext not in (".tm7", ".drawio", ".xml", ".thf", ".yml", ".yaml"):
                    return _json(self, {"error": f"cannot import {ext or name}"}, 400)
                target = os.path.join(state.workspace, "overlay", name)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(text)
                before = len(state.model.assets) if state.model else 0
                scan = state.rescan()
                if scan.get("error"):
                    return _json(self, {"error": scan["error"]}, 400)
                after = len(state.model.assets) if state.model else 0
                return _json(self, {"ok": True, "added": max(0, after - before),
                                    "scan": scan})

            if path == "/api/import":
                doc = body.get("document")
                if not isinstance(doc, dict):
                    return _json(self, {"error": "no document supplied"}, 400)
                if doc.get("format") != "threatforge-model":
                    return _json(self, {"error": "not a ThreatForge model file"}, 400)
                if int(doc.get("version") or 0) > TFM_VERSION:
                    return _json(self, {
                        "error": f"file is version {doc.get('version')}; this "
                                 f"build understands up to {TFM_VERSION}"}, 400)
                state.write_overlay(doc.get("overlay") or "")
                state.write_layout(doc.get("layout") or {})
                state.write_doc(doc.get("document") or {})
                scan = state.rescan()
                if scan.get("error"):
                    return _json(self, {"error": scan["error"]}, 400)
                # Triage is restored after the scan, because a finding has to
                # exist before a status can be attached to it. Ids that no
                # longer occur are reported rather than dropped in silence --
                # they usually mean the code moved on since the file was saved.
                restored, missing = 0, []
                known = {r["id"] for r in state.store.findings(policy=state.policy)}
                for row in doc.get("triage") or []:
                    fid = row.get("id")
                    if fid not in known:
                        missing.append(fid)
                        continue
                    state.store.update_finding(
                        fid, status=row.get("status"), owner=row.get("owner"),
                        notes=row.get("notes"),
                        due_override=row.get("due_override"),
                        actor="import")
                    restored += 1
                return _json(self, {"ok": True, "scan": scan,
                                    "restored": restored,
                                    "not_found": missing[:25],
                                    "not_found_count": len(missing)})

            if path == "/api/overlay":
                state.write_overlay(body.get("overlay", ""))
                if body.get("layout") is not None:
                    state.write_layout(body["layout"])
                if body.get("rescan", True):
                    scan = state.rescan()
                    return _json(self, {"ok": not scan.get("error"), "scan": scan},
                                 400 if scan.get("error") else 200)
                return _json(self, {"ok": True})

            if path.startswith("/api/findings/"):
                fid = unquote(path.split("/")[3])
                row = state.store.update_finding(
                    fid,
                    status=body.get("status"),
                    owner=body.get("owner"),
                    notes=body.get("notes"),
                    due_override=body.get("due_override"),
                    actor=body.get("actor") or "user",
                )
                fresh = [r for r in state.store.findings(policy=state.policy)
                         if r["id"] == fid]
                return _json(self, {"ok": True, "finding": fresh[0] if fresh else row})

            if path == "/api/bulk":
                ids = body.get("ids") or []
                if not isinstance(ids, list):
                    raise ValueError("ids must be a list")
                for fid in ids:
                    state.store.update_finding(
                        fid, status=body.get("status"), owner=body.get("owner"),
                        actor=body.get("actor") or "user")
                return _json(self, {"ok": True, "updated": len(ids)})

            _json(self, {"error": "not found"}, 404)

    return Handler


def serve(root: str = ".", port: int = 8787, db: Optional[str] = None,
          config: Optional[Dict[str, Any]] = None, open_browser: bool = True,
          scan_on_start: bool = True, fresh: bool = False) -> None:
    """Run the local app until interrupted."""
    root = os.path.abspath(root)
    cfg = config or cfgmod.load(root)
    store = Store(db or default_db_path(root))
    if fresh:
        cleared = store.clear()
        print(f"\n  cleared {cleared['findings']} finding(s), "
              f"{cleared['scans']} scan(s), {cleared['events']} event(s)")
    state = AppState(root, store, cfg)

    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state))
    url = f"http://127.0.0.1:{port}/"

    import threatforge
    here = os.path.dirname(os.path.abspath(__file__))
    print(f"\n  ThreatForge  {url}")
    print(f"  version      {threatforge.__version__}  build {BUILD}")
    # The single most common way a change appears not to work: `threatforge` on
    # PATH resolves to an old non-editable copy in site-packages, so the code
    # being served is not the code that was just edited. Printing the directory
    # makes that visible in one line instead of an afternoon.
    print(f"  serving code {here}")
    if "site-packages" in here:
        print("  NOTE         this is an installed copy, not your working tree.")
        print("               pip install -e . --force-reinstall --no-deps")
    print(f"  project      {state.project}")
    print(f"  database     {store.path}")
    print(f"  scanning     {root}")

    if scan_on_start:
        print("\n  running initial scan…", end="", flush=True)
        result = state.rescan()
        if result.get("error"):
            print(f" failed: {result['error']}")
        else:
            s = result.get("summary", {})
            d = result.get("delta", {})
            print(f" {s.get('findings', 0)} findings "
                  f"({d.get('new', 0)} new, {d.get('resolved', 0)} resolved)")

    print("\n  Ctrl-C to stop\n")
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped")
    finally:
        httpd.server_close()
        state.source.dispose()
        store.close()
