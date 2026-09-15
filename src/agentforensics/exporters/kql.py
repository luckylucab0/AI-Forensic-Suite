"""Advanced Hunting KQL, generated from the catalogue.

Two queries. One over file events, to find the devices in an estate that have an agent's
data on disk. One over process events, to find the devices where an agent binary actually
ran, which is a different and often stronger signal: a file can arrive by profile sync,
while a process start means somebody used the thing here.

The honest limits of this exporter, stated in the generated file as well as here because
whoever runs the query is the person they matter to.

Advanced Hunting sees events, not the filesystem. It answers "was this path written or read
while the sensor was recording", which is not the same question as "is this path there
now", and its retention is finite. A device that used an agent before the retention window
leaves no row. That makes these queries a way to narrow a fleet, never a way to clear a
device.

There is no user-profile placeholder in the data, so a profile-anchored path becomes a
match on the part below the profile. That is wider than the catalogue asked for: it will
also match the same relative path under a directory that is not a profile. The alternative,
enumerating profile names, cannot be generated from a catalogue.

The catalogue records no network destinations, so this exporter generates no network query.
The brief asked for one over connections to model-provider endpoints, and a list of those
hosts would have to be invented here or copied from somewhere unsourced, which is the same
defect as an invented path: it would look authoritative and quietly answer the wrong
question. It is left out until the catalogue can carry sourced hostnames.
"""

from __future__ import annotations

import re

from agentforensics.catalog import Artifact, Catalogue
from agentforensics.exporters.common import (
    Rendered,
    Skip,
    agents,
    bare_variable,
    catalogue_digest,
    dedupe,
    generated_note,
    has_variable,
    header,
    is_registry,
    needs_discovery,
    skip_lines,
    wildcard_segments,
)

_STRIP_PREFIXES = (
    "%USERPROFILE%\\",
    "%APPDATA%\\",
    "%LOCALAPPDATA%\\",
    "%TEMP%\\",
    "%TMP%\\",
    "~/",
)


def _fragment(path: str, separator: str = "\\") -> str | None:
    """The part of a path that identifies it in an event row, or None.

    An event row carries an absolute folder path, so the fragment has to be distinctive on
    its own. A fragment with fewer than two segments is not: matching on a single directory
    name would light up on unrelated software that happens to share it.
    """
    text = wildcard_segments(path).replace("/", "\\")
    for prefix in _STRIP_PREFIXES:
        candidate = prefix.replace("/", "\\")
        if text.upper().startswith(candidate.upper()):
            text = text[len(candidate) :]
            break
    else:
        if not re.match(r"^[A-Za-z]:\\|^\\", text):
            return None
    # Everything from the first wildcard on is unusable in a substring match.
    text = text.split("*", 1)[0].rstrip("\\")
    if text.count("\\") < 1:
        return None
    return text if separator == "\\" else text.replace("\\", separator)


def _fragments(artifact: Artifact, separator: str = "\\") -> tuple[list[str], str | None]:
    if is_registry(artifact):
        return [], "a registry key, which is a different Advanced Hunting table"
    if needs_discovery(artifact):
        return [], (
            "anchored at a working copy, so its absolute path is not knowable in advance: "
            "hunt on the filename instead, or run the suite's collector"
        )
    fragments: list[str] = []
    saw_variable = False
    for path in artifact.paths:
        if bare_variable(path) or has_variable(path):
            saw_variable = True
            continue
        fragment = _fragment(path, separator)
        if fragment:
            fragments.append(fragment)
    if fragments:
        return sorted(set(fragments)), None
    if saw_variable:
        return [], (
            "reachable only through a relocation variable, which is not in the event data: "
            "read the variable off the endpoint"
        )
    return [], (
        "no path distinctive enough to match on: after removing the profile and everything "
        "from the first wildcard, less than two path segments were left"
    )


def _binaries(catalogue: Catalogue) -> list[tuple[str, str]]:
    """Agent executables the catalogue names, as (agent, filename).

    Derived from the install-evidence entries rather than listed here, so a new agent's
    binary appears in the process query as soon as its catalogue entry does. A name is only
    taken when the catalogue spells out a file with an executable extension: guessing that
    an agent's binary is named after the agent would produce a query that matches whatever
    else on the estate happens to share the name.
    """
    out: list[tuple[str, str]] = []
    for agent in agents(catalogue):
        for artifact in agent.artifacts:
            if artifact.category != "install_evidence":
                continue
            for path in artifact.paths:
                segments = wildcard_segments(path).replace("\\", "/").rstrip("/").split("/")
                name = segments[-1]
                if not name or "*" in name or "%" in name or "<" in name:
                    continue
                if name.lower().endswith((".exe", ".cmd", ".bat", ".ps1")):
                    out.append((agent.agent, name))
                    continue
                # A POSIX executable has no extension, which leaves nothing in the name
                # itself to tell it from a directory. The first attempt at this took the
                # last segment of any binary-formatted install path and produced process
                # names like Packages and local: a query matching those would return noise
                # and look authoritative doing it. So the only dotless names taken are
                # those the catalogue puts directly inside a bin directory, which is the
                # one convention that actually means executable.
                if "." not in name and len(segments) > 1 and segments[-2] in ("bin", "sbin"):
                    out.append((agent.agent, name))
    return sorted(set(out))


def render(catalogue: Catalogue) -> list[Rendered]:
    digest = catalogue_digest(catalogue)
    return [_file_query(catalogue, digest), _process_query(catalogue, digest)]


def _file_query(catalogue: Catalogue, digest: str) -> Rendered:
    skipped: list[Skip] = []
    rows: list[tuple[str, str, str]] = []
    for agent in agents(catalogue):
        for artifact in sorted(agent.artifacts, key=lambda a: a.id):
            # Both separators, because the sensor runs on macOS and Linux as well and their
            # event rows carry forward slashes. Walking only the Windows artifacts, which is
            # what this did first, quietly turned a cross-platform hunt into a Windows one.
            separators = []
            if "windows" in artifact.os:
                separators.append("\\")
            if {"macos", "linux"} & set(artifact.os):
                separators.append("/")
            covered = False
            reasons: list[str] = []
            for separator in separators:
                fragments, reason = _fragments(artifact, separator)
                if reason:
                    reasons.append(reason)
                    continue
                covered = True
                for fragment in fragments:
                    rows.append((agent.agent, artifact.id, fragment))
            if not covered:
                skipped.append(Skip(artifact.id, reasons[0] if reasons else "no usable path"))

    lines = [
        header(
            generated_note(
                digest,
                [
                    "",
                    "Advanced Hunting sees events, not the filesystem. This finds devices",
                    "where an agent path was touched while the sensor was recording and",
                    "inside the retention window, which is narrower than which devices have",
                    "the file now. Use it to pick hosts, never to clear one.",
                    "",
                    "Profile-anchored paths match on the part below the profile, because the",
                    "event data has no profile placeholder. That also matches the same",
                    "relative path under a directory that is not a profile, so check the",
                    "FolderPath of a hit before treating it as one.",
                ],
            )
            + skip_lines(dedupe(skipped)),
            comment="//",
        ),
        "let AgentPaths = datatable(Agent: string, ArtifactId: string, Fragment: string)",
        "[",
    ]
    for agent_name, artifact_id, fragment in sorted(set(rows)):
        escaped = fragment.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'    "{agent_name}", "{artifact_id}", "{escaped}",')
    lines.extend(
        [
            "];",
            "DeviceFileEvents",
            "| where Timestamp > ago(30d)",
            "| extend Lowered = tolower(FolderPath)",
            "| join kind=inner (AgentPaths | extend Lowered = tolower(Fragment)) on $left.Lowered == $right.Lowered",
            "| project Timestamp, DeviceName, InitiatingProcessAccountName, Agent, ArtifactId,",
            "          ActionType, FolderPath, FileName, InitiatingProcessFileName",
            "| order by Timestamp desc",
            "",
            "// The join above is exact, which misses a file one directory deeper than the",
            "// fragment. Swap it for the substring form below when recall matters more than",
            "// query cost, remembering that it scans:",
            "//",
            "// DeviceFileEvents",
            "// | where Timestamp > ago(30d)",
            "// | extend Lowered = tolower(FolderPath)",
            "// | mv-apply Target = toscalar(AgentPaths | summarize make_list(Fragment)) on (",
            "//     where Lowered contains tolower(tostring(Target))",
            "//   )",
            "",
        ]
    )
    return Rendered("kql/agent-file-events.kql", "\n".join(lines), dedupe(skipped))


def _process_query(catalogue: Catalogue, digest: str) -> Rendered:
    binaries = _binaries(catalogue)
    skipped: list[Skip] = []
    if not binaries:
        skipped.append(
            Skip("(all)", "the catalogue names no agent executable in an install-evidence entry")
        )
    short = sorted({name for _, name in binaries if len(name) <= 2})
    short_note = (
        [
            "",
            "One caution before you run this: "
            + ", ".join(short)
            + " is short enough to collide with unrelated software, so filter a hit from it",
            "by FolderPath before treating it as an agent. It is in the list because it is",
            "the vendor's real binary name, and dropping it would lose real detections.",
        ]
        if short
        else []
    )
    lines = [
        header(
            generated_note(
                digest,
                [
                    "",
                    "A process start is a stronger signal than a file: a file can arrive by",
                    "profile sync or by restoring a backup, while a process start means the",
                    "binary ran on this device.",
                    "",
                    "The names come from the catalogue's install-evidence entries. An agent",
                    "installed under a name the catalogue does not record, or run through an",
                    "interpreter so the process name is the interpreter's, will not appear.",
                    "The second query below covers the interpreter case by command line.",
                    "",
                    "Advanced Hunting retention is finite and the window below is thirty days,",
                    "so a device that used an agent before that leaves no row here. Absence is",
                    "not evidence: it narrows a fleet, it does not clear a device.",
                    *short_note,
                ],
            )
            + skip_lines(dedupe(skipped)),
            comment="//",
        ),
        "let AgentBinaries = datatable(Agent: string, FileName: string)",
        "[",
    ]
    for agent_name, filename in binaries:
        lines.append(f'    "{agent_name}", "{filename}",')
    lines.extend(
        [
            "];",
            "DeviceProcessEvents",
            "| where Timestamp > ago(30d)",
            "| extend Lowered = tolower(FileName)",
            "| join kind=inner (AgentBinaries | extend Lowered = tolower(FileName)) on Lowered",
            "| project Timestamp, DeviceName, AccountName, Agent, FileName, ProcessCommandLine,",
            "          InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath",
            "| order by Timestamp desc",
            "",
            "// An agent started through a package runner or a language runtime shows the",
            "// runtime as its process name, so the same run is invisible above. This finds",
            "// it on the command line instead, and is deliberately a separate query because",
            "// a command-line contains is far more expensive than a filename join.",
            "//",
            "// DeviceProcessEvents",
            "// | where Timestamp > ago(30d)",
            "// | where ProcessCommandLine has_any (",
        ]
    )
    names = sorted({name for _, name in binaries} | {agent.agent for agent in agents(catalogue)})
    for name in names:
        lines.append(f'//     "{name}",')
    lines.extend(
        [
            "//   )",
            "// | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine",
            "",
        ]
    )
    return Rendered("kql/agent-process-events.kql", "\n".join(lines), dedupe(skipped))


__all__ = ["render"]
