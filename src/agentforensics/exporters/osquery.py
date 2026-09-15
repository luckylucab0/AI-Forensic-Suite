"""An osquery pack, generated from the catalogue.

Two kinds of query, because osquery answers two different questions badly if you mix them.
A presence query over the `file` table with a glob, which is cheap and tells a fleet which
hosts have an agent's data at all. And a set of per-agent detail queries over the same
table, which return the timestamps and sizes of the files themselves.

osquery cannot return file contents, so this pack is triage rather than collection: it
narrows a fleet to the hosts worth collecting from. Its glob language also has no recursive
wildcard of unbounded depth, only `%%` for one level of subdirectories below the pattern,
so a catalogue path that recurses arbitrarily is expressed as far as osquery can go and the
remainder is reported rather than implied.
"""

from __future__ import annotations

import json
import re

from agentforensics.catalog import Artifact, Catalogue
from agentforensics.exporters.common import (
    Rendered,
    Skip,
    agents,
    artifacts_for,
    bare_variable,
    catalogue_digest,
    dedupe,
    generated_note,
    has_variable,
    is_registry,
    iter_paths,
    needs_discovery,
    skip_lines,
    wildcard_segments,
)

# osquery's own wildcards: % is one path component, %% is that component and everything
# below it. There is no way to say "this filename, at any depth", which is the one shape
# the catalogue uses that does not survive the translation.
_PROFILE = {
    "windows": "C:\\Users\\%",
    "macos": "/Users/%",
    "linux": "/home/%",
}

_WINDOWS_RELATIVE = {
    "%USERPROFILE%": "",
    "%APPDATA%": "AppData\\Roaming",
    "%LOCALAPPDATA%": "AppData\\Local",
    "%TEMP%": "AppData\\Local\\Temp",
    "%TMP%": "AppData\\Local\\Temp",
}

_WINDOWS_ABSOLUTE = {
    "%PROGRAMDATA%": "C:\\ProgramData",
    "%ALLUSERSPROFILE%": "C:\\ProgramData",
    "%PROGRAMFILES%": "C:\\Program Files",
    "%PROGRAMFILES(X86)%": "C:\\Program Files (x86)",
    "%SYSTEMROOT%": "C:\\Windows",
    "%WINDIR%": "C:\\Windows",
    "%PUBLIC%": "C:\\Users\\Public",
}


def _translate(path: str, os_name: str) -> str | None:
    separator = "\\" if os_name == "windows" else "/"
    text = wildcard_segments(path)
    upper = text.upper()

    for placeholder, absolute in _WINDOWS_ABSOLUTE.items():
        if upper.startswith(placeholder):
            if os_name != "windows":
                return None
            text = absolute + text[len(placeholder) :]
            break
    else:
        for placeholder, relative in _WINDOWS_RELATIVE.items():
            if upper.startswith(placeholder):
                if os_name != "windows":
                    return None
                tail = text[len(placeholder) :].lstrip("\\/")
                text = separator.join(x for x in (_PROFILE[os_name], relative, tail) if x)
                break
        else:
            if text.startswith("~/") or text.startswith("~\\"):
                text = _PROFILE[os_name] + separator + text[2:]
            elif text.startswith("/"):
                if os_name == "windows":
                    return None
            else:
                return None

    text = text.replace("/", separator) if os_name == "windows" else text.replace("\\", "/")
    # An unbounded recursion becomes osquery's own recursive wildcard, which is the widest
    # thing it can express. It is wider than the catalogue asked for in depth and the same
    # in shape, so nothing is lost; a filename at unbounded depth is what gets lost, and
    # that case is reported by the caller.
    text = re.sub(
        re.escape(separator) + r"\*\*" + re.escape(separator) + "?", separator + "%%", text
    )
    text = text.replace("*", "%")
    return text.rstrip(separator) + separator + "%%" if text.endswith(separator) else text


def _patterns(artifact: Artifact, os_name: str) -> tuple[list[str], str | None]:
    if is_registry(artifact):
        return [], "a registry key, which osquery reads through its own registry table"
    if needs_discovery(artifact):
        return [], (
            "anchored at a working copy, whose location only the agent's own state file "
            "gives: run the suite's collector, which reads it"
        )
    patterns: list[str] = []
    saw_variable = False
    unbounded_name = False
    for path in iter_paths(artifact, os_name):
        if bare_variable(path) or has_variable(path):
            saw_variable = True
            continue
        if re.search(r"\*\*[/\\][^/\\*]", wildcard_segments(path)):
            unbounded_name = True
        translated = _translate(path, os_name)
        if translated:
            patterns.append(translated)
    if patterns:
        return sorted(set(patterns)), None
    if unbounded_name:
        return [], ("a filename at unbounded depth, which osquery's glob language cannot express")
    if saw_variable:
        return [], (
            "reachable only through a relocation variable, which a static pattern cannot "
            "resolve: read the variable off the endpoint"
        )
    return [], "no path for this operating system that this target can express"


def _sql(patterns: list[str]) -> str:
    """A file-table query over a set of glob patterns, on one line.

    One line because an osquery pack holds its queries as JSON strings, and a query split
    over several lines there is harder to copy into a shell than to read.
    """
    clause = " OR ".join(f"""path LIKE '{p.replace("'", "''")}'""" for p in patterns)
    columns = (
        "path, filename, size, type, mode, uid, gid, "
        "datetime(btime, 'unixepoch') AS created_utc, "
        "datetime(mtime, 'unixepoch') AS modified_utc, "
        "datetime(atime, 'unixepoch') AS accessed_utc"
    )
    # Not a query this process runs: it is text written into a pack for osquery to execute
    # on an endpoint. The patterns are catalogue data under version control, and the only
    # character that could break out of the literal is a quote, which is doubled above.
    return f"SELECT {columns} FROM file WHERE {clause};"  # noqa: S608


def render(catalogue: Catalogue) -> list[Rendered]:
    digest = catalogue_digest(catalogue)
    skipped: list[Skip] = []
    queries: dict[str, dict[str, object]] = {}

    for agent in agents(catalogue):
        per_os: dict[str, list[str]] = {}
        covered: dict[str, list[str]] = {}
        for os_name in ("windows", "macos", "linux"):
            for artifact in artifacts_for(agent, os_name):
                patterns, reason = _patterns(artifact, os_name)
                if reason:
                    skipped.append(Skip(artifact.id, reason))
                    continue
                per_os.setdefault(os_name, []).extend(patterns)
                covered.setdefault(os_name, []).append(artifact.id)
        for os_name, patterns in sorted(per_os.items()):
            if not patterns:
                continue
            platform = {"windows": "windows", "macos": "darwin", "linux": "linux"}[os_name]
            # The covered ids go in the description because a pack is JSON and cannot carry
            # a comment, and because one query covers many catalogue entries: without the
            # list there is no way to tell from a hit which entry predicted the location,
            # or from a miss which entries this query was even looking for.
            ids = ", ".join(sorted(set(covered.get(os_name, []))))
            queries[f"agentforensics_{agent.agent}_{os_name}"] = {
                "query": _sql(sorted(set(patterns))),
                "interval": 86400,
                "platform": platform,
                "snapshot": True,
                "description": (
                    f"On-disk artifacts of {agent.title} on {os_name}. Metadata only: "
                    f"osquery cannot return file contents. Catalogue entries covered: {ids}."
                ),
            }

    lines = [
        "{",
        '  "_generated": [',
    ]
    note = generated_note(
        digest,
        [
            "",
            "osquery returns metadata, never content, so this pack narrows a fleet to the",
            "hosts worth collecting from rather than collecting anything itself.",
        ],
    ) + skip_lines(dedupe(skipped))
    lines.extend(
        f"    {_json_string(line)}" + ("," if i < len(note) - 1 else "")
        for i, line in enumerate(note)
    )
    lines.append("  ],")
    lines.append('  "queries": {')
    names = sorted(queries)
    for i, name in enumerate(names):
        entry = queries[name]
        lines.append(f"    {_json_string(name)}: {{")
        lines.append(f'      "query": {_json_string(str(entry["query"]))},')
        lines.append(f'      "interval": {entry["interval"]},')
        lines.append(f'      "platform": {_json_string(str(entry["platform"]))},')
        lines.append('      "snapshot": true,')
        lines.append(f'      "description": {_json_string(str(entry["description"]))}')
        lines.append("    }" + ("," if i < len(names) - 1 else ""))
    lines.append("  }")
    lines.append("}")
    lines.append("")
    return [Rendered("osquery/agentforensics.conf", "\n".join(lines), dedupe(skipped))]


def _json_string(value: str) -> str:
    return json.dumps(value)


__all__ = ["render"]
