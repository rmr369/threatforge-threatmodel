# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Ingestion layer: source of truth -> canonical Assets."""

from .base import (Ingestor, available, build, register, walk_files,  # noqa: F401
                   load_yaml_with_lines, ref, set_output_exclusions)
from . import kubernetes  # noqa: F401  (registers KubernetesIngestor, LiveClusterIngestor)
from . import terraform   # noqa: F401  (registers TerraformIngestor)
from . import docker      # noqa: F401  (registers DockerfileIngestor, ComposeIngestor)
from . import legacy      # noqa: F401  (registers LegacyStage7Ingestor)
from . import manual      # noqa: F401  (registers ManualModelIngestor)
from . import tmt         # noqa: F401  (registers TmtIngestor)
from . import drawio      # noqa: F401  (registers DrawioIngestor)

__all__ = ["Ingestor", "available", "build", "register", "walk_files",
           "load_yaml_with_lines", "ref", "set_output_exclusions"]
