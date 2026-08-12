# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Getting code to scan: local path, git clone, or uploaded archive.

Every function here takes attacker-influenced input, so the security notes are
not decoration. A tool that analyses other people's infrastructure is a tool
people will point at repositories they do not control.

Three real risks, all handled:

* **Command injection.** A URL like ``https://x/y --upload-pack=evil`` becomes an
  argument to git. Never a shell string; always an argument list, always with
  ``--`` before user input, and the URL is validated before it gets near a
  subprocess.
* **Zip slip.** An archive member named ``../../../.ssh/authorized_keys``
  escapes the extraction directory. Every member path is resolved and rejected
  if it lands outside.
* **Code execution during analysis.** `helm template` and `kustomize build`
  execute logic from the repository being scanned. That is fine for your own
  code and unacceptable for a stranger's, so **untrusted sources disable both
  by default**.

Everything lands under a workspace directory that the caller owns and can wipe.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Hosts we will clone from without further thought. Anything else is allowed
# only when the caller explicitly opts in, because "clone any URL" is a request
# forgery primitive against internal git servers.
DEFAULT_GIT_HOSTS = {
    "github.com", "www.github.com", "gitlab.com", "www.gitlab.com",
    "bitbucket.org", "dev.azure.com", "ssh.dev.azure.com",
    "codeberg.org", "git.sr.ht",
}

MAX_ARCHIVE_BYTES = 256 * 1024 * 1024      # 256 MB uncompressed
MAX_ARCHIVE_MEMBERS = 20_000
MAX_COMPRESSION_RATIO = 200                # crude zip-bomb guard
CLONE_TIMEOUT_S = 180

# Files worth keeping from an upload. Everything else is noise that slows the
# scan and, in the case of binaries, is never going to be parsed anyway.
KEEP_SUFFIXES = (
    ".yaml", ".yml", ".json", ".tf", ".tfstate", ".hcl", ".tm7", ".thf",
    ".drawio", ".dio", ".xml", ".toml", ".ini", ".env", ".properties",
    ".md", ".txt",
)
KEEP_NAMES = {
    "dockerfile", "containerfile", "makefile", "chart.yaml", "values.yaml",
    "kustomization.yaml", "kustomization.yml", "docker-compose.yml",
    "docker-compose.yaml", "compose.yml", "compose.yaml",
}


class SourceError(Exception):
    """A problem with the requested source, safe to show a user."""


@dataclass
class Source:
    """Somewhere to scan, plus how much we trust it."""
    root: str
    kind: str                       # path | git | upload
    label: str
    trusted: bool = True
    detail: Dict[str, Any] = field(default_factory=dict)
    cleanup: Optional[str] = None   # directory to delete when finished

    def dispose(self) -> None:
        if self.cleanup and os.path.isdir(self.cleanup):
            shutil.rmtree(self.cleanup, ignore_errors=True)


# ---------------------------------------------------------------------------
# Local path
# ---------------------------------------------------------------------------

def from_path(path: str) -> Source:
    expanded = os.path.abspath(os.path.expanduser(str(path).strip().strip('"')))
    if not os.path.exists(expanded):
        raise SourceError(f"path does not exist: {expanded}")
    if not os.path.isdir(expanded):
        raise SourceError(f"not a directory: {expanded}")
    return Source(root=expanded, kind="path", label=os.path.basename(expanded) or expanded,
                  trusted=True, detail={"path": expanded})


# ---------------------------------------------------------------------------
# Git
# ---------------------------------------------------------------------------

_REPO_SHORTHAND = re.compile(r"^[\w.\-]+/[\w.\-]+$")
_SAFE_REF = re.compile(r"^[\w./\-]{1,200}$")


def normalise_git_url(raw: str) -> str:
    """Accept `owner/repo`, a browser URL, or a clone URL. Return a clone URL."""
    text = str(raw or "").strip()
    if not text:
        raise SourceError("no repository given")
    if _REPO_SHORTHAND.match(text):
        return f"https://github.com/{text}.git"
    # Strip the things people paste from a browser.
    text = re.sub(r"/(tree|blob)/[^\s]*$", "", text)
    if text.endswith("/"):
        text = text[:-1]
    return text


def validate_git_url(url: str, allow_any_host: bool = False,
                     extra_hosts: Optional[List[str]] = None) -> Tuple[str, str]:
    """Return (url, host) or raise. Rejects anything that could reach a shell."""
    if url.startswith("-"):
        raise SourceError("repository URL may not start with '-' "
                          "(it would be read as a git option)")
    parsed = urlparse(url)
    if parsed.scheme in ("http", "https"):
        host = (parsed.hostname or "").lower()
    elif parsed.scheme in ("git", "ssh"):
        host = (parsed.hostname or "").lower()
    elif re.match(r"^[\w.\-]+@[\w.\-]+:", url):          # scp-style git@host:path
        host = url.split("@", 1)[1].split(":", 1)[0].lower()
    elif parsed.scheme == "file" or os.path.isdir(url):
        raise SourceError("local paths should use the path option, not the git option")
    else:
        raise SourceError(f"unsupported URL scheme: {parsed.scheme or 'none'}")

    if not host:
        raise SourceError("could not determine the host from that URL")

    allowed = set(DEFAULT_GIT_HOSTS) | {h.lower() for h in (extra_hosts or [])}
    if not allow_any_host and host not in allowed:
        raise SourceError(
            f"host '{host}' is not in the allowed list. Cloning arbitrary hosts "
            f"can be used to probe internal servers, so it is off by default. "
            f"Allowed: {', '.join(sorted(allowed))}")
    return url, host


def from_git(url: str, ref: Optional[str] = None, workspace: Optional[str] = None,
             allow_any_host: bool = False,
             extra_hosts: Optional[List[str]] = None,
             depth: int = 1) -> Source:
    """Shallow-clone a repository into a scratch directory."""
    if shutil.which("git") is None:
        raise SourceError("git is not installed or not on PATH")

    clone_url = normalise_git_url(url)
    clone_url, host = validate_git_url(clone_url, allow_any_host, extra_hosts)

    if ref is not None:
        ref = str(ref).strip()
        if ref and not _SAFE_REF.match(ref):
            raise SourceError("branch/tag contains characters that are not allowed")

    base = workspace or tempfile.mkdtemp(prefix="threatforge-git-")
    os.makedirs(base, exist_ok=True)
    target = tempfile.mkdtemp(prefix="repo-", dir=base)

    cmd = ["git", "clone", "--depth", str(int(depth)), "--single-branch",
           "--no-tags", "--config", "core.symlinks=false"]
    if ref:
        cmd += ["--branch", ref]
    cmd += ["--", clone_url, target]          # '--' stops option injection

    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"          # never block waiting for a password
    env["GIT_ASKPASS"] = "echo"
    env.pop("GIT_CONFIG_PARAMETERS", None)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=CLONE_TIMEOUT_S, env=env, shell=False)
    except subprocess.TimeoutExpired:
        shutil.rmtree(base, ignore_errors=True)
        raise SourceError(f"clone timed out after {CLONE_TIMEOUT_S}s")

    if result.returncode != 0:
        shutil.rmtree(base, ignore_errors=True)
        stderr = (result.stderr or "").strip().splitlines()
        detail = stderr[-1] if stderr else f"git exited {result.returncode}"
        raise SourceError(f"clone failed: {detail}")

    commit = ""
    try:
        commit = subprocess.run(["git", "-C", target, "rev-parse", "--short", "HEAD"],
                                capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception:
        pass

    name = re.sub(r"\.git$", "", clone_url.rstrip("/").split("/")[-1]) or host
    return Source(
        root=target, kind="git", label=name, trusted=False,
        detail={"url": clone_url, "host": host, "ref": ref or "default",
                "commit": commit},
        cleanup=base)


# ---------------------------------------------------------------------------
# Uploaded archive
# ---------------------------------------------------------------------------

def _is_interesting(name: str) -> bool:
    low = os.path.basename(name).lower()
    return low in KEEP_NAMES or low.startswith("dockerfile") or low.endswith(KEEP_SUFFIXES)


def from_zip_bytes(data: bytes, label: str = "upload",
                   workspace: Optional[str] = None) -> Source:
    """Extract an uploaded zip, refusing anything that tries to escape."""
    base = workspace or tempfile.mkdtemp(prefix="threatforge-upload-")
    target = tempfile.mkdtemp(prefix="src-", dir=base)
    target_real = os.path.realpath(target)

    archive = os.path.join(base, "upload.zip")
    with open(archive, "wb") as fh:
        fh.write(data)

    kept = skipped = 0
    total = 0
    try:
        with zipfile.ZipFile(archive) as zf:
            members = zf.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise SourceError(f"archive has {len(members)} entries; "
                                  f"the limit is {MAX_ARCHIVE_MEMBERS}")

            for info in members:
                if info.is_dir():
                    continue
                total += info.file_size
                if total > MAX_ARCHIVE_BYTES:
                    raise SourceError("archive expands beyond the size limit "
                                      f"({MAX_ARCHIVE_BYTES // (1024*1024)} MB)")
                if info.compress_size and \
                        info.file_size / max(info.compress_size, 1) > MAX_COMPRESSION_RATIO:
                    raise SourceError(f"entry '{info.filename}' has a suspicious "
                                      "compression ratio; refusing to extract")

                name = info.filename.replace("\\", "/")
                if not _is_interesting(name):
                    skipped += 1
                    continue

                # Zip slip: resolve and confirm the result stays inside.
                dest = os.path.realpath(os.path.join(target, name))
                if not (dest == target_real or dest.startswith(target_real + os.sep)):
                    raise SourceError(
                        f"archive entry tries to escape the extraction directory: "
                        f"{info.filename}")

                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with zf.open(info) as src, open(dest, "wb") as out:
                    shutil.copyfileobj(src, out, length=1024 * 64)
                kept += 1
    except zipfile.BadZipFile:
        shutil.rmtree(base, ignore_errors=True)
        raise SourceError("that file is not a valid zip archive")
    except SourceError:
        shutil.rmtree(base, ignore_errors=True)
        raise
    finally:
        if os.path.exists(archive):
            os.remove(archive)

    if kept == 0:
        shutil.rmtree(base, ignore_errors=True)
        raise SourceError(
            "no scannable files in that archive. ThreatForge reads Kubernetes "
            "YAML, Terraform, Dockerfiles, Compose, .tm7 and .drawio files.")

    # A zip of a repository usually has one top-level folder; scan that instead
    # of the wrapper so paths in findings look sensible.
    entries = [e for e in os.listdir(target) if not e.startswith(".")]
    root = target
    if len(entries) == 1 and os.path.isdir(os.path.join(target, entries[0])):
        root = os.path.join(target, entries[0])

    return Source(root=root, kind="upload", label=label, trusted=False,
                  detail={"files": kept, "skipped": skipped,
                          "bytes": total, "name": label},
                  cleanup=base)


# ---------------------------------------------------------------------------

def config_for(source: Source, base_config: Dict[str, Any]) -> Dict[str, Any]:
    """Config adjusted for how much we trust the source.

    Helm and Kustomize rendering execute logic from the scanned repository. For
    your own code that is what you want. For a stranger's it is remote code
    execution with extra steps, so it is disabled unless the source is trusted.
    """
    cfg = dict(base_config)
    cfg["project"] = source.label
    if not source.trusted:
        cfg = dict(cfg)
        cfg["helm"] = {"render": False}
        cfg["kustomize"] = {"render": False}
        cfg["live"] = {"enabled": False}
        cfg["_untrusted_source"] = True
    return cfg


def describe(source: Source) -> Dict[str, Any]:
    return {
        "kind": source.kind,
        "label": source.label,
        "root": source.root,
        "trusted": source.trusted,
        **source.detail,
    }
