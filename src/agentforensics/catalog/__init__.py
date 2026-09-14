"""Load and validate the artifact catalogue.

The catalogue is the single source of truth for where each agent stores its data (ADR
0003). Both collectors embed it, five collection-rule exporters render it, the parsers key
off it and the documentation is generated from it, so this module is the one place that
decides what a valid entry is.

It deliberately does not import anything from the rest of the package: the catalogue has
to be loadable by a build script that runs before, and independently of, the analyzer.
"""

from agentforensics.catalog.model import (
    COLLECT_PRIORITY_ORDER,
    AgentCatalog,
    Artifact,
    Catalogue,
    CatalogueError,
    EnvOverride,
    Text,
    load_catalogue,
    load_file,
    resolve_text,
)

__all__ = [
    "COLLECT_PRIORITY_ORDER",
    "AgentCatalog",
    "Artifact",
    "Catalogue",
    "CatalogueError",
    "EnvOverride",
    "Text",
    "load_catalogue",
    "load_file",
    "resolve_text",
]
