"""Shared machinery for the collection-rule exporters.

Each exporter renders the same catalogue into a different tool's format. What they share
is not formatting but the two hard parts: deciding which artifacts a given target can
express at all, and translating a catalogue path into that target's path language without
quietly losing the paths it cannot say.

The second half is the whole risk of this package. Every one of these tools has a narrower
path language than the catalogue: KAPE addresses a drive and a file mask, osquery has a
single wildcard depth per segment, Advanced Hunting has no user-profile placeholder at all.
A translation that silently drops what it cannot express produces a collection rule that
runs clean and finds nothing, which is the failure this project exists to avoid. So every
exporter returns its skipped artifacts with a reason, every generated file lists them in
its own header, and a test fails if a skip has no reason.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field

from agentforensics.catalog import AgentCatalog, Artifact, Catalogue

# Roots whose location the collector discovers at run time by reading an agent's own state
# file. No collection-rule format can express "the directories this user has open in their
# editor", so every exporter reports them as skipped rather than guessing a location.
DISCOVERED_ROOTS = ("project", "repo_root", "plugin")


@dataclass(frozen=True, slots=True)
class Skip:
    """One artifact a target cannot express, with the reason it could not."""

    artifact_id: str
    reason: str


def dedupe(skipped: Sequence[Skip]) -> list[Skip]:
    """One entry per artifact and reason.

    An exporter that walks three operating systems records the same skip three times, and a
    header that says so three times is noise that hides the ones that matter.
    """
    seen: dict[tuple[str, str], Skip] = {}
    for skip in skipped:
        seen.setdefault((skip.artifact_id, skip.reason), skip)
    return [seen[key] for key in sorted(seen)]


@dataclass
class Rendered:
    """One generated file, plus what did not make it in.

    The skips travel with the file rather than being logged, because they belong in the
    file's own header: whoever runs the rule is the person who needs to know what it does
    not cover.
    """

    path: str
    text: str
    skipped: list[Skip] = field(default_factory=list)


def catalogue_digest(catalogue: Catalogue) -> str:
    """A short digest of everything an exporter reads, for the generated headers.

    Only the fields that reach a generated file are hashed, so reordering a note or fixing
    a typo in prose does not churn every output file and make a review diff useless.
    """
    payload = [
        {
            "id": a.id,
            "os": list(a.os),
            "paths": list(a.paths),
            "root": a.root,
            "format": a.format,
            "sensitivity": a.sensitivity,
            "collect_priority": a.collect_priority,
            "status": a.status,
            "legacy": a.legacy,
        }
        for a in catalogue.artifacts
    ]
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]


def agents(catalogue: Catalogue) -> list[AgentCatalog]:
    """Every agent in a stable order, so two runs produce identical bytes."""
    return sorted(catalogue.agents, key=lambda a: a.agent)


def artifacts_for(agent: AgentCatalog, os_name: str) -> list[Artifact]:
    """The agent's artifacts for one operating system, in a stable order."""
    return sorted((a for a in agent.artifacts if a.applies_to(os_name)), key=lambda a: a.id)


def is_registry(artifact: Artifact) -> bool:
    return artifact.root == "registry"


# Why a registry key is in none of these rules, said the same way in all of them.
#
# The text each exporter carried before this said, in three different ways, that something
# else picks the key up: that this artifact reads it through a separate source, that it is a
# KAPE registry target, that osquery has a registry table. The first was simply untrue, and
# the other two were true about the tool and read as true about the generated file. None of
# these five exporters emits anything that addresses the registry, and six catalogue entries
# across four products are registry keys. Two of them are the managed policy that says what
# an agent was allowed to do, and on Windows that policy can exist only there, with no file
# at all. A reader who believed any of the three sentences would conclude that no policy was
# in force, when the truth is that nobody looked. That is the one confusion this project
# exists to prevent.
#
# The collectors do read four of those entries now, on a live Windows host, and write each
# key as a document in the bundle (ADR 0033). That is said here too, because a reader of a
# generated rule is deciding what else they have to go and get.
#
# `tool` names what the person running the rule has to reach for, since each of these
# formats can address the registry even though the generator writes nothing that does.
def registry_reason(tool: str) -> str:
    """The reason line for a registry key, naming what the reader has to do instead."""
    return (
        f"a registry key, and this rule addresses files. No rule generated here covers one: "
        f"query these keys with {tool}. The suite's own collectors read four of the "
        f"catalogue's registry entries on a live Windows host and write each as a document "
        f"in the bundle, so a collection from a live host already carries those; this is "
        f"the answer for a rule and for the entries the collectors decline. "
        f"docs/ARTIFACTS.md names them"
    )


def needs_discovery(artifact: Artifact) -> bool:
    return artifact.root in DISCOVERED_ROOTS


def bare_variable(path: str) -> bool:
    """Whether a path is a relocation variable and nothing else.

    Such a path is wherever the operator pointed the variable, so no static rule can find
    it. It is in the catalogue to tell an analyst to read the variable off the endpoint,
    and every exporter has to say out loud that it cannot cover it.
    """
    return bool(re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", path))


def has_variable(path: str) -> bool:
    """Whether a path contains an agent relocation variable anywhere in it."""
    return bool(re.search(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", path))


# Placeholders the catalogue uses for a segment whose value varies per session, per
# workspace or per version. Every target can express these as a wildcard, so they are the
# one class of placeholder that translates cleanly.
_VARIABLE_SEGMENT = re.compile(r"<[^>]+>")


def wildcard_segments(path: str) -> str:
    """Turn every variable segment into a wildcard, leaving the rest of the path alone."""
    return _VARIABLE_SEGMENT.sub("*", path)


# The user directory of the editor and of every fork that inherits its storage layout. Kept
# in step with the collector's own list: an agentic extension's conversations live under one
# of these, so a target that cannot expand the placeholder loses the transcripts.
VSCODE_PRODUCTS = (
    "Code",
    "Code - Insiders",
    "VSCodium",
    "Cursor",
    "Windsurf",
    "Kiro",
    "Trae",
    "Positron",
)

VSCODE_USER_RELATIVE = {
    "macos": "Library/Application Support/{product}/User",
    "linux": ".config/{product}/User",
    "windows": "AppData/Roaming/{product}/User",
}


def expand_vscode_user(path: str, os_name: str) -> list[str]:
    """Turn one <vscode-user> path into one profile-relative path per editor product."""
    if not path.startswith("<vscode-user>"):
        return []
    tail = path[len("<vscode-user>") :].lstrip("/\\").replace("\\", "/")
    template = VSCODE_USER_RELATIVE[os_name]
    return [
        "~/" + "/".join(x for x in (template.format(product=product), tail) if x)
        for product in VSCODE_PRODUCTS
    ]


def header(lines: Sequence[str], comment: str = "#") -> str:
    """A generated-file header in the target's comment syntax."""
    return "\n".join(f"{comment} {line}".rstrip() for line in lines)


def generated_note(digest: str, extra: Iterable[str] = ()) -> list[str]:
    """The standing warning every generated file carries.

    It says where the file comes from and, more importantly for whoever is about to run it,
    what it is not: a collection rule generated from a catalogue inherits every gap in that
    catalogue, and an empty result from any of these is inconclusive rather than clean.
    """
    return [
        "Generated from the artifact catalogue. Do not edit by hand:",
        "run `afx export-collection` and commit the result.",
        f"Catalogue digest: {digest}",
        "",
        "An empty result from this rule means the paths it searched held nothing. It does",
        "not mean the host is clean. Unverified catalogue entries, relocated data trees and",
        "the paths listed as not covered below are all reasons a used agent leaves no hit",
        "here. Where this matters, run the suite's own collector instead: it reads the",
        "relocation variables and the agents' own state files, which no static rule can.",
        *extra,
    ]


def skip_lines(skipped: Sequence[Skip]) -> list[str]:
    """The not-covered section of a generated header, grouped by reason."""
    if not skipped:
        return ["", "Every catalogue artifact for this target is covered."]
    by_reason: dict[str, list[str]] = {}
    for skip in dedupe(skipped):
        by_reason.setdefault(skip.reason, []).append(skip.artifact_id)
    out = ["", "Not covered by this rule:"]
    for reason in sorted(by_reason):
        ids = sorted(set(by_reason[reason]))
        out.append(f"  {reason}")
        for artifact_id in ids:
            out.append(f"    {artifact_id}")
    return out


# Directories that exist only on a POSIX host. A catalogue path anchored at ~ is otherwise
# platform-neutral, and the collector expands ~ on Windows too, so most of them are worth
# searching there. These are not: a Windows rule carrying ~/Library/Application Support
# runs without error, matches nothing, and pads the rule with rows that look like coverage.
_POSIX_ONLY_SEGMENTS = frozenset(
    {"library", ".config", ".local", ".cache", "documents", "applications"}
)


def iter_paths(artifact: Artifact, os_name: str) -> Iterator[str]:
    """The artifact's paths that belong to one operating system.

    The catalogue keeps every platform's spelling of a path in one artifact, which is what
    makes it one entry per logical thing. An exporter targets one platform at a time, so it
    has to pick, and picking wrongly is invisible: a Windows rule carrying POSIX paths runs
    without error and matches nothing.
    """
    for path in artifact.paths:
        # The editor user directory expands here rather than in each exporter, so that no
        # caller has to know the placeholder exists. Expanding it is not optional: a dozen
        # agentic extensions keep their conversations under it, and a target that passes it
        # through as a literal searches for a directory named "<vscode-user>".
        if path.startswith("<vscode-user>"):
            yield from expand_vscode_user(path, os_name)
            continue
        windows = bool(re.match(r"^%[A-Za-z_()]+%|^[A-Za-z]:\\|^HKEY_|^HKLM|^HKCU", path))
        if os_name == "windows":
            if windows or has_variable(path):
                yield path
            elif path.startswith("~/"):
                first = path[2:].split("/", 1)[0].lower()
                if first not in _POSIX_ONLY_SEGMENTS:
                    yield path
        elif not windows:
            yield path
