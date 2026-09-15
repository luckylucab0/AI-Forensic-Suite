"""The catalogue's in-memory model, its loader and its validator.

Design constraint served: everything downstream must be able to trust that a loaded
catalogue is well formed and honestly labelled, so validation happens once here, against
the published JSON Schema, and a failure is an exception with the file and the offending
entry rather than a silently skipped artifact.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, cast

import fastjsonschema
import yaml

# Free text in the catalogue is either a plain string, which means English, or a mapping of
# language code to string. See ADR 0007: a contributor must be able to add an artifact
# without writing German, and the generator marks the gap rather than hiding it.
Text = str | Mapping[str, str]

# What a path is anchored to. Profile and system paths the collector can resolve on its
# own; project, repo and plugin paths need a list of roots discovered from the agent's own
# state, so an artifact that is mis-labelled here is simply never collected.
PathRoot = Literal["user_profile", "system", "project", "repo_root", "plugin", "registry"]

Sensitivity = Literal["normal", "secret"]
Status = Literal["verified", "unverified"]
CollectPriority = Literal["live_only", "first", "normal", "durable"]

# Collection order on a live endpoint. live_only artifacts cannot be recovered from a
# powered-off image at all, so they come first however small they are.
COLLECT_PRIORITY_ORDER: tuple[CollectPriority, ...] = ("live_only", "first", "normal", "durable")

_SCHEMA_NAME = "catalog.schema.json"


class CatalogueError(Exception):
    """A catalogue file is missing, unreadable, or does not satisfy the schema."""


@dataclass(frozen=True, slots=True)
class EnvOverride:
    """An environment variable that relocates an agent's data tree.

    Forensically load-bearing: a collection keyed on the default path finds nothing on a
    host where the tree was moved, and that is indistinguishable from the agent never
    having run unless the collector knows to look.
    """

    name: str
    effect: Text
    source: str | None = None


@dataclass(frozen=True, slots=True)
class Artifact:
    id: str
    category: str
    os: tuple[str, ...]
    paths: tuple[str, ...]
    format: str
    sensitivity: Sensitivity
    status: Status
    source: str
    source_kind: str
    # Defaults from here on, so this block has to stay after every required field.
    root: PathRoot = "user_profile"
    title: str | None = None
    parser: str | None = None
    collect_priority: CollectPriority = "normal"
    legacy: bool = False
    unsourced_paths: tuple[str, ...] = ()
    record_types: tuple[str, ...] = ()
    tables: tuple[str, ...] = ()
    contains_credentials: tuple[str, ...] = ()
    volatility: Text | None = None
    notes: Text | None = None

    @property
    def agent(self) -> str:
        """The agent key, which is the part of the id before the dot."""
        return self.id.split(".", 1)[0]

    @property
    def is_verified(self) -> bool:
        return self.status == "verified"

    def path_is_sourced(self, path: str) -> bool:
        """Whether the cited source states this particular path.

        False for a verified artifact's unsourced leaf as well as for every path of an
        unverified one, because an analyst needs the same warning in both cases: an empty
        result here is inconclusive rather than proof of absence.
        """
        return self.is_verified and path not in self.unsourced_paths

    @property
    def content_collected_by_default(self) -> bool:
        """Whether the collector copies the bytes without --include-secrets.

        False only for credential stores. Everything else is copied however personal it
        is, because it is the evidence the suite exists to collect.
        """
        return self.sensitivity != "secret"

    @property
    def needs_project_roots(self) -> bool:
        """Whether the collector must be told where the user's working copies are.

        Project and repository paths cannot be found by expanding a profile. For Claude
        Code the roots come from the projects key of ~/.claude.json and from the encoded
        directory names under projects/, both of which have to be read before these
        artifacts can be collected at all.
        """
        return self.root in ("project", "repo_root", "plugin")

    @property
    def holds_credentials_inside(self) -> bool:
        """Whether this artifact is evidence that also contains credential material.

        Such a file is collected in full. The names in contains_credentials are what an
        exporter redacts, so a finding can leave the case without carrying a live token.
        """
        return bool(self.contains_credentials)

    @property
    def is_registry(self) -> bool:
        """Windows registry keys rather than files, readable only by the PowerShell collector."""
        return self.root == "registry"

    def applies_to(self, os_name: str) -> bool:
        return os_name in self.os


@dataclass(frozen=True, slots=True)
class AgentCatalog:
    agent: str
    title: str
    artifacts: tuple[Artifact, ...]
    vendor: str | None = None
    vendor_sources: tuple[str, ...] = ()
    description: Text | None = None
    references: tuple[str, ...] = ()
    env_overrides: tuple[EnvOverride, ...] = ()

    def for_os(self, os_name: str) -> tuple[Artifact, ...]:
        return tuple(a for a in self.artifacts if a.applies_to(os_name))

    def is_vendor_source(self, url: str) -> bool:
        """Whether this URL is the agent's own vendor speaking about its own product.

        The honesty rule needs this because a third party who reverse-engineered a path
        writes it down just as confidently as the vendor does, and an analyst reading the
        catalogue cannot tell the two apart from the path alone. Matching is a plain
        prefix test on purpose: a host test alone would accept any repository on a code
        hosting site, which is where most of the third-party research lives.
        """
        return any(url.startswith(prefix) for prefix in self.vendor_sources)


@dataclass(frozen=True, slots=True)
class Catalogue:
    """Every agent catalogue that was loaded, plus the lookups callers actually need."""

    agents: tuple[AgentCatalog, ...] = field(default_factory=tuple)

    def __iter__(self) -> Iterator[AgentCatalog]:
        return iter(self.agents)

    def __len__(self) -> int:
        return len(self.agents)

    @property
    def artifacts(self) -> tuple[Artifact, ...]:
        return tuple(a for agent in self.agents for a in agent.artifacts)

    def agent(self, key: str) -> AgentCatalog:
        for agent in self.agents:
            if agent.agent == key:
                return agent
        raise KeyError(key)

    def artifact(self, artifact_id: str) -> Artifact:
        for a in self.artifacts:
            if a.id == artifact_id:
                return a
        raise KeyError(artifact_id)

    def for_os(self, os_name: str) -> tuple[Artifact, ...]:
        """Artifacts that exist on one operating system, in collection order.

        Sorted by collect_priority first, then by id for a stable result, so two runs of a
        collector queue the same work in the same order (a determinism requirement, and
        the reason a collection interrupted halfway is still comparable).
        """
        return tuple(
            sorted(
                (a for a in self.artifacts if a.applies_to(os_name)),
                key=lambda a: (COLLECT_PRIORITY_ORDER.index(a.collect_priority), a.id),
            )
        )

    def by_priority(self, os_name: str) -> dict[CollectPriority, tuple[Artifact, ...]]:
        groups: dict[CollectPriority, list[Artifact]] = {p: [] for p in COLLECT_PRIORITY_ORDER}
        for a in self.for_os(os_name):
            groups[a.collect_priority].append(a)
        return {p: tuple(v) for p, v in groups.items()}


def resolve_text(value: Text | None, lang: str = "en") -> tuple[str, bool]:
    """Return (text, is_translated) for a free-text field.

    is_translated is False when the requested language is missing and English was used
    instead. Callers surface that rather than passing off English as a translation, which
    is the difference between a documented gap and a quiet lie.
    """
    if value is None:
        return "", True
    if isinstance(value, str):
        return value, lang == "en"
    text = value.get(lang)
    if text is not None:
        return text, True
    return value.get("en", ""), False


@lru_cache(maxsize=4)
def _validator(schema_path: Path) -> Any:
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CatalogueError(f"cannot read the catalogue schema at {schema_path}: {exc}") from exc
    return fastjsonschema.compile(schema)


def _tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    return tuple(cast(Sequence[str], value))


def _artifact(data: Mapping[str, Any]) -> Artifact:
    return Artifact(
        id=data["id"],
        category=data["category"],
        os=_tuple(data["os"]),
        paths=_tuple(data["paths"]),
        format=data["format"],
        sensitivity=cast(Sensitivity, data["sensitivity"]),
        root=cast(PathRoot, data.get("root", "user_profile")),
        status=cast(Status, data["status"]),
        source=data["source"],
        source_kind=data["source_kind"],
        title=data.get("title"),
        parser=data.get("parser"),
        collect_priority=cast(CollectPriority, data.get("collect_priority", "normal")),
        legacy=bool(data.get("legacy", False)),
        unsourced_paths=_tuple(data.get("unsourced_paths")),
        record_types=_tuple(data.get("record_types")),
        tables=_tuple(data.get("tables")),
        contains_credentials=_tuple(data.get("contains_credentials")),
        volatility=data.get("volatility"),
        notes=data.get("notes"),
    )


def load_file(path: Path, schema_path: Path | None = None) -> AgentCatalog:
    """Load and validate one agent catalogue file."""
    if schema_path is None:
        schema_path = path.parent / "schema" / _SCHEMA_NAME
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CatalogueError(f"cannot read {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise CatalogueError(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise CatalogueError(f"{path} does not contain a mapping at the top level")

    try:
        _validator(schema_path)(data)
    except fastjsonschema.JsonSchemaException as exc:
        raise CatalogueError(f"{path} does not satisfy the schema: {exc.message}") from exc

    agent_key = data["agent"]
    artifacts = [_artifact(a) for a in data["artifacts"]]

    # The schema can require the id to look like <something>.<something>, but only the
    # loader knows which file it came from, so the prefix check lives here. A mismatch
    # would make --agents silently filter an artifact out of its own agent's collection.
    wrong = [a.id for a in artifacts if a.agent != agent_key]
    if wrong:
        raise CatalogueError(
            f"{path}: artifact ids must start with the agent key {agent_key!r}: {wrong}"
        )
    duplicates = sorted({a.id for a in artifacts if [x.id for x in artifacts].count(a.id) > 1})
    if duplicates:
        raise CatalogueError(f"{path}: duplicate artifact ids: {duplicates}")

    return AgentCatalog(
        agent=agent_key,
        title=data["title"],
        artifacts=tuple(artifacts),
        vendor=data.get("vendor"),
        vendor_sources=_tuple(data.get("vendor_sources")),
        description=data.get("description"),
        references=_tuple(data.get("references")),
        env_overrides=tuple(
            EnvOverride(name=e["name"], effect=e["effect"], source=e.get("source"))
            for e in data.get("env_overrides", [])
        ),
    )


def load_catalogue(root: Path, files: Iterable[Path] | None = None) -> Catalogue:
    """Load every agent catalogue under root, in a stable order."""
    if files is None:
        files = sorted(root.glob("*.yaml"))
    schema_path = root / "schema" / _SCHEMA_NAME
    agents = [load_file(p, schema_path) for p in sorted(files)]

    seen: dict[str, Path] = {}
    for agent, path in zip(agents, sorted(files), strict=True):
        if agent.agent in seen:
            raise CatalogueError(
                f"agent key {agent.agent!r} appears in both {seen[agent.agent]} and {path}"
            )
        seen[agent.agent] = path

    if not agents:
        raise CatalogueError(f"no catalogue files found in {root}")
    return Catalogue(agents=tuple(sorted(agents, key=lambda a: a.agent)))
