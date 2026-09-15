"""Collection-rule generators.

The catalogue is the single source of truth for where each agent keeps its data, and most
organizations already have tooling that can go and get files: Velociraptor, KAPE, a
Defender live response session, Advanced Hunting, osquery. This package renders the
catalogue into each of their formats so that using the catalogue does not require adopting
this suite's collector.

The output is committed under `exporters/generated/` and CI fails if it drifts from the
catalogue, for the same reason the embedded catalogue inside the collectors is checked: a
rule that quietly lags the catalogue searches last month's locations and reports a clean
host.

Every exporter returns its skipped artifacts with a reason and every generated file lists
them in its own header. That is the rule this package exists to keep: a target with a
narrower path language than the catalogue must say what it cannot express, because a
collection rule that runs clean and finds nothing is indistinguishable from a clean host.
"""

from __future__ import annotations

from collections.abc import Callable

from agentforensics.catalog import Catalogue
from agentforensics.exporters import kape, kql, mde, osquery, velociraptor
from agentforensics.exporters.common import Rendered, Skip

FORMATS: dict[str, Callable[[Catalogue], list[Rendered]]] = {
    "kape": kape.render,
    "kql": kql.render,
    "mde": mde.render,
    "osquery": osquery.render,
    "velociraptor": velociraptor.render,
}


def render(catalogue: Catalogue, formats: list[str] | None = None) -> list[Rendered]:
    """Render the requested formats, or all of them, in a stable order."""
    names = sorted(FORMATS) if formats is None else formats
    unknown = [name for name in names if name not in FORMATS]
    if unknown:
        raise ValueError("unknown format(s): " + ", ".join(sorted(unknown)))
    out: list[Rendered] = []
    for name in names:
        out.extend(FORMATS[name](catalogue))
    return sorted(out, key=lambda r: r.path)


__all__ = ["FORMATS", "Rendered", "Skip", "render"]
