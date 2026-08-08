"""Ingestion layer: source of truth -> canonical Assets."""

from .base import Ingestor, available, build, register, walk_files, load_yaml_with_lines, ref  # noqa: F401
from . import kubernetes  # noqa: F401  (registers KubernetesIngestor, LiveClusterIngestor)
from . import terraform   # noqa: F401  (registers TerraformIngestor)
from . import docker      # noqa: F401  (registers DockerfileIngestor, ComposeIngestor)
from . import legacy      # noqa: F401  (registers LegacyStage7Ingestor)

__all__ = ["Ingestor", "available", "build", "register", "walk_files",
           "load_yaml_with_lines", "ref"]
