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
from agentforensics.exporters import (
    kape,
    kql,
    mde,
    osquery,
    velociraptor,
    velociraptor_unified,
)
from agentforensics.exporters.common import Rendered, Skip


def _velociraptor(catalogue: Catalogue) -> list[Rendered]:
    """Every Velociraptor artifact, in one format.

    Three files rather than one because they answer three different questions, and a hunt
    that asked the wrong one either takes gigabytes off every endpoint or comes back with
    nothing. Presence says which hosts are worth looking at, Collect takes the files away
    to be read later, and UnifiedLog reads them where they are and returns the
    conversation.

    Combined here rather than inside one module so that the artifact which parses can
    import the path translation from the artifact which collects, and the two can never
    look in different places.
    """
    return velociraptor.render(catalogue) + velociraptor_unified.render(catalogue)


FORMATS: dict[str, Callable[[Catalogue], list[Rendered]]] = {
    "kape": kape.render,
    "kql": kql.render,
    "mde": mde.render,
    "osquery": osquery.render,
    "velociraptor": _velociraptor,
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
