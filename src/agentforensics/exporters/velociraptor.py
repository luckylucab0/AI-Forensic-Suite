"""Velociraptor artifact YAML, generated from the catalogue.

Two artifacts per run. A collection artifact that globs the catalogue paths and uploads
what it finds, and a presence artifact that reports only which agents exist on a host,
because a fleet sweep asking "who has used an AI coding agent" must not pull gigabytes of
transcripts off every endpoint to answer it.

Velociraptor's glob language is the closest of any target to the catalogue's own: it has a
recursive wildcard, it expands a home directory per profile if the pattern says so, and it
addresses the filesystem rather than a drive. That makes this the exporter with the fewest
skips, which is also why it is the one to reach for when another format cannot express an
artifact.
"""

from __future__ import annotations

from agentforensics.catalog import Artifact, Catalogue
from agentforensics.exporters.common import (
    ANCHORED_REASON,
    Rendered,
    Skip,
    agents,
    artifacts_for,
    bare_variable,
    catalogue_digest,
    dedupe,
    generated_note,
    has_variable,
    header,
    is_registry,
    iter_paths,
    needs_discovery,
    partly_discovered,
    registry_reason,
    skip_lines,
    wildcard_segments,
)

NAMESPACE = "Custom.Forensics.AIAgents"

# Where a profile-anchored path lands on each platform. Velociraptor globs the filesystem,
# so the profile has to be spelled out as a wildcard over the profile directories rather
# than left as a tilde: a literal ~ matches a directory named "~" and nothing else.
_PROFILE_GLOBS = {
    "windows": ("C:/Users/*",),
    # Two roots on macOS because a service account's home is not under /Users, and one
    # extra on Linux for the same reason. A collection that only globs the usual root
    # misses exactly the accounts an agent is most likely to have been automated under.
    "macos": ("/Users/*", "/var/root"),
    "linux": ("/home/*", "/root"),
}

_WINDOWS_PLACEHOLDERS = {
    "%USERPROFILE%": "",
    "%APPDATA%": "AppData/Roaming",
    "%LOCALAPPDATA%": "AppData/Local",
    "%TEMP%": "AppData/Local/Temp",
    "%TMP%": "AppData/Local/Temp",
}

_WINDOWS_ABSOLUTE = {
    "%PROGRAMDATA%": "C:/ProgramData",
    "%ALLUSERSPROFILE%": "C:/ProgramData",
    "%PROGRAMFILES%": "C:/Program Files",
    "%PROGRAMFILES(X86)%": "C:/Program Files (x86)",
    "%SYSTEMROOT%": "C:/Windows",
    "%WINDIR%": "C:/Windows",
    "%PUBLIC%": "C:/Users/Public",
}


def _translate(path: str, os_name: str) -> list[str]:
    """One catalogue path as one or more Velociraptor globs, or an empty list.

    Empty means the caller must record a skip. Returning an empty list rather than a
    best-effort glob is deliberate: a glob that is nearly right is worse than none, because
    it produces a result that looks like an answer.
    """
    text = wildcard_segments(path).replace("\\", "/")
    upper = text.upper()

    for placeholder, absolute in _WINDOWS_ABSOLUTE.items():
        if upper.startswith(placeholder):
            return [_recurse(absolute + text[len(placeholder) :])]

    profiles = _PROFILE_GLOBS[os_name]
    for placeholder, relative in _WINDOWS_PLACEHOLDERS.items():
        if upper.startswith(placeholder):
            if os_name != "windows":
                return []
            tail = text[len(placeholder) :].lstrip("/")
            return [
                _recurse("/".join(x for x in (profile, relative, tail) if x))
                for profile in profiles
            ]

    if text.startswith("~/"):
        tail = _recurse(text[2:])
        return [f"{profile}/{tail}" for profile in profiles]
    if text.startswith("/"):
        return [] if os_name == "windows" else [_recurse(text)]
    return []


def _recurse(glob: str) -> str:
    """Make a directory target recurse.

    A catalogue path ending in a separator means the directory and what is under it, which
    is how the collector reads it. Velociraptor's glob would match only the directory entry
    itself, so a transcript store spelled as a directory would come back as one row and no
    files.
    """
    return glob.rstrip("/") + "/**" if glob.endswith("/") else glob


def _partial(artifact: Artifact) -> str | None:
    """The header line for the working-copy half of an entry whose other half is here.

    A mixed entry used to be reported as covered by nothing at all, so its profile and
    system paths were in no rule and nothing said so. Now the paths are rendered and the
    part that needs a working copy is what the header names.
    """
    return ANCHORED_REASON if partly_discovered(artifact) else None


def _covered(artifact: Artifact, os_name: str) -> tuple[list[str], str | None]:
    """The globs for one artifact, or the reason there are none."""
    if is_registry(artifact):
        return [], registry_reason("Velociraptor's own registry accessor")
    if needs_discovery(artifact):
        return [], (
            "anchored at a working copy, whose location only the agent's own state file "
            "gives: run the suite's collector, which reads it"
        )
    globs: list[str] = []
    saw_variable = False
    for path in iter_paths(artifact, os_name):
        if bare_variable(path):
            saw_variable = True
            continue
        if has_variable(path):
            saw_variable = True
            continue
        globs.extend(_translate(path, os_name))
    if globs:
        return sorted(set(globs)), _partial(artifact)
    if saw_variable:
        return [], (
            "reachable only through a relocation variable, which a static glob cannot "
            "resolve: read the variable off the endpoint"
        )
    return [], "no path for this operating system that this target can express"


def _registry_keys(catalogue: Catalogue) -> list[str]:
    """Every registry key in the catalogue, as Velociraptor registry glob paths."""
    keys = []
    for agent in agents(catalogue):
        for artifact in agent.artifacts:
            if not is_registry(artifact):
                continue
            for path in artifact.paths:
                keys.append(wildcard_segments(path).replace("\\", "/"))
    return sorted(set(keys))


def render(catalogue: Catalogue) -> list[Rendered]:
    digest = catalogue_digest(catalogue)
    return [_collection(catalogue, digest), _presence(catalogue, digest)]


def _collection(catalogue: Catalogue, digest: str) -> Rendered:
    skipped: list[Skip] = []
    sources: list[str] = []
    for os_name, precondition in (
        ("windows", "SELECT OS From info() where OS = 'windows'"),
        ("macos", "SELECT OS From info() where OS = 'darwin'"),
        ("linux", "SELECT OS From info() where OS = 'linux'"),
    ):
        rows: list[tuple[str, str, str]] = []
        for agent in agents(catalogue):
            for artifact in artifacts_for(agent, os_name):
                globs, reason = _covered(artifact, os_name)
                if reason:
                    skipped.append(Skip(artifact.id, reason))
                if not globs:
                    continue
                for glob in globs:
                    rows.append((agent.agent, artifact.id, glob))
        if not rows:
            continue
        sources.append(_source(os_name, precondition, sorted(set(rows))))

    text = "\n".join(
        [
            header(
                generated_note(
                    digest,
                    [
                        "",
                        "This artifact uploads file contents. Credential stores are excluded:",
                        "the catalogue marks them, and a hunt that pulls an agent's tokens off",
                        "every endpoint creates a worse problem than the one it investigates.",
                    ],
                )
                + skip_lines(dedupe(skipped))
            ),
            f"name: {NAMESPACE}.Collect",
            "description: |",
            "  Collect the on-disk history of AI coding agents from this host.",
            "",
            "  One row per file found, with the artifact id that claimed it, so a finding",
            "  can be traced back to the catalogue entry that predicted the location.",
            "type: CLIENT",
            "parameters:",
            "- name: UploadFiles",
            "  description: Upload file contents as well as metadata.",
            "  type: bool",
            "  default: 'Y'",
            "- name: MaxFileSize",
            "  description: Skip a file larger than this, in bytes. Transcripts are text and",
            "    rarely large; a multi-gigabyte database is usually a cache.",
            "  default: '268435456'",
            "sources:",
            *sources,
            "",
        ]
    )
    return Rendered(f"velociraptor/{NAMESPACE}.Collect.yaml", text, dedupe(skipped))



def _source(os_name: str, precondition: str, rows: list[tuple[str, str, str]]) -> str:
    """One per-OS source: the glob rows as data, then one query over them."""
    lines = [
        f"- name: {os_name}",
        f"  precondition: {precondition}",
        "  query: |",
        "    LET targets <= SELECT * FROM parse_csv(",
        "      accessor='data',",
        "      filename='''agent,artifact_id,glob",
    ]
    for agent, artifact_id, glob in rows:
        lines.append(f"    {agent},{artifact_id},{glob}")
    lines.extend(
        [
            "    ''')",
            # No column= here. That parameter iterates a column holding a *list*;
            # glob holds one string per row, so the loop body never ran and the
            # artifact returned nothing at all, on every host. The column names are
            # the CSV's own, lowercase, and aliased to the names the output has
            # always used: VQL does not fold case, so selecting Agent against a
            # column named agent bound null and lost the attribution silently.
            "    LET hits = SELECT * FROM foreach(row=targets, query={",
            "        SELECT agent AS Agent, artifact_id AS ArtifactId,",
            "               OSPath, Size, Mode.String AS Mode,",
            "               Mtime, Atime, Ctime, Btime",
            "        FROM glob(globs=glob)",
            "        WHERE NOT IsDir",
            "      })",
            "    SELECT *, if(condition=UploadFiles AND Size < atoi(string=MaxFileSize),",
            "                 then=upload(file=OSPath), else=NULL) AS Upload",
            "    FROM hits",
        ]
    )
    return "\n".join(lines)


def _presence(catalogue: Catalogue, digest: str) -> Rendered:
    """A metadata-only artifact for a fleet sweep.

    Separate from the collection artifact because the question "which of these ten thousand
    machines has used an agent" is answerable from directory existence alone, and answering
    it by uploading every transcript in the estate is both slow and a data-protection
    problem of its own making.
    """
    skipped: list[Skip] = []
    rows: list[tuple[str, str]] = []
    for agent in agents(catalogue):
        for os_name in ("windows", "macos", "linux"):
            for artifact in artifacts_for(agent, os_name):
                if artifact.collect_priority != "first":
                    continue
                globs, _ = _covered(artifact, os_name)
                if not globs:
                    continue
                for glob in globs:
                    rows.append((agent.agent, glob))
    if not rows:
        skipped.append(Skip("(all)", "no artifact is marked as a first-priority target"))

    lines = [
        header(
            generated_note(
                digest,
                [
                    "",
                    "Metadata only: this artifact reports which agents left a trace and",
                    "uploads nothing. Use it to pick the hosts worth collecting from.",
                    "",
                    "It looks only at the artifacts the catalogue marks as collect first,",
                    "which are the transcript and session stores. An agent used once and",
                    "then cleaned up may be visible in a log or an install trace and not",
                    "here, so a negative result narrows a fleet rather than clearing a host.",
                ],
            )
            + skip_lines(dedupe(skipped))
        ),
        f"name: {NAMESPACE}.Presence",
        "description: |",
        "  Report which AI coding agents have left on-disk traces on this host.",
        "type: CLIENT",
        "sources:",
        "- query: |",
        "    LET targets <= SELECT * FROM parse_csv(",
        "      accessor='data',",
        "      filename='''agent,glob",
    ]
    for agent_name, glob in sorted(set(rows)):
        lines.append(f"    {agent_name},{glob}")
    lines.extend(
        [
            "    ''')",
            # Same two defects as the collection artifact above, same fix.
            "    LET hits = SELECT * FROM foreach(row=targets, query={",
            "        SELECT agent AS Agent, OSPath, Mtime FROM glob(globs=glob)",
            "      })",
            "    SELECT Agent, count() AS Files, max(item=Mtime) AS LastSeen",
            "    FROM hits GROUP BY Agent ORDER BY Agent",
            "",
        ]
    )
    return Rendered(f"velociraptor/{NAMESPACE}.Presence.yaml", "\n".join(lines), dedupe(skipped))


__all__ = ["NAMESPACE", "render"]
