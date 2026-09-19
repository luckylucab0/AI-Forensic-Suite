"""KAPE target files, generated from the catalogue.

One `.tkape` per agent plus one compound target that pulls them all in, which is how KAPE
targets are normally organized: an examiner picks the agent they care about, or the
compound target when they do not yet know which agent was used.

KAPE is Windows only and addresses a drive letter, a path and a file mask. That is a
narrower language than the catalogue's, in two ways that matter. There is no way to say
"recurse to any depth under here and match this name", only a path with `*` segments and a
mask, so a catalogue path with a double wildcard has to be flattened to a recursive target.
And a path outside the system drive cannot be expressed at all. Both are reported as skips
rather than approximated.
"""

from __future__ import annotations

import hashlib
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
    header,
    is_registry,
    iter_paths,
    needs_discovery,
    registry_reason,
    skip_lines,
    wildcard_segments,
)

# KAPE expands %user% over every profile directory on the target drive, which is exactly
# what the catalogue's ~ and %USERPROFILE% mean.
_PROFILE = "C:\\Users\\%user%"

_PREFIXES = {
    "%USERPROFILE%": _PROFILE,
    "%APPDATA%": _PROFILE + "\\AppData\\Roaming",
    "%LOCALAPPDATA%": _PROFILE + "\\AppData\\Local",
    "%TEMP%": _PROFILE + "\\AppData\\Local\\Temp",
    "%TMP%": _PROFILE + "\\AppData\\Local\\Temp",
    "%PROGRAMDATA%": "C:\\ProgramData",
    "%ALLUSERSPROFILE%": "C:\\ProgramData",
    "%PROGRAMFILES%": "C:\\Program Files",
    "%PROGRAMFILES(X86)%": "C:\\Program Files (x86)",
    "%SYSTEMROOT%": "C:\\Windows",
    "%WINDIR%": "C:\\Windows",
    "%PUBLIC%": "C:\\Users\\Public",
}


def _split(path: str) -> tuple[str, str, bool] | None:
    """Turn a catalogue path into (Path, FileMask, recursive), or None if KAPE cannot say it.

    The boolean is whether the target has to recurse. KAPE recurses when the path ends in a
    directory and the mask is a wildcard, so a catalogue path with a `**` segment becomes a
    recursive target over the directory above it. That is wider than the catalogue asked
    for, which is the safe direction: a target that collects too much wastes disk, a target
    that collects too little produces a wrong answer.
    """
    text = wildcard_segments(path).replace("/", "\\")
    upper = text.upper()
    for placeholder, prefix in _PREFIXES.items():
        if upper.startswith(placeholder):
            text = prefix + text[len(placeholder) :]
            break
    else:
        if text.startswith("~\\"):
            text = _PROFILE + text[1:]
        elif not re.match(r"^[A-Za-z]:\\", text):
            return None

    recursive = "**" in text
    text = text.replace("\\**", "").replace("**\\", "").replace("**", "")
    text = re.sub(r"\\{2,}", "\\\\", text).rstrip("\\")

    if text.endswith(("\\*", ":\\*")):
        return text.rsplit("\\", 1)[0], "*", recursive
    head, _, tail = text.rpartition("\\")
    if not head:
        return None
    # A trailing directory, with no filename: collect everything under it.
    if "." not in tail and "*" not in tail:
        return text, "*", True
    return head, tail, recursive


def _rows(artifact: Artifact) -> tuple[list[tuple[str, str, bool]], str | None]:
    if is_registry(artifact):
        return [], registry_reason("a KAPE registry target of your own")
    if needs_discovery(artifact):
        return [], (
            "anchored at a working copy, whose location only the agent's own state file "
            "gives: run the suite's collector, which reads it"
        )
    rows: list[tuple[str, str, bool]] = []
    saw_variable = False
    for path in iter_paths(artifact, "windows"):
        if bare_variable(path) or has_variable(path):
            saw_variable = True
            continue
        split = _split(path)
        if split is None:
            continue
        rows.append(split)
    if rows:
        return sorted(set(rows)), None
    if saw_variable:
        return [], (
            "reachable only through a relocation variable, which KAPE cannot resolve: read "
            "the variable off the endpoint"
        )
    return [], "no Windows path that a drive-and-mask target can express"


def _scope_note(catalogue: Catalogue) -> list[str]:
    """What a Windows-only target cannot reach, as a count rather than a list.

    Naming two hundred macOS and Linux artifacts in every one of these files would bury the
    skips that are specific to KAPE's path language, which are the ones an examiner can act
    on. The count is here so the file cannot be mistaken for complete coverage.
    """
    out_of_scope = [a for a in catalogue.artifacts if "windows" not in a.os]
    return [
        "",
        "KAPE is Windows only. "
        f"{len(out_of_scope)} of the {len(catalogue.artifacts)} catalogue artifacts declare",
        "no Windows path and are therefore outside this target's scope entirely, which is a",
        "different thing from the per-artifact gaps listed below. For a macOS or Linux",
        "endpoint use the Velociraptor artifact or this suite's own collector.",
    ]


def render(catalogue: Catalogue) -> list[Rendered]:
    digest = catalogue_digest(catalogue)
    out: list[Rendered] = []
    names: list[tuple[str, str]] = []
    scope = _scope_note(catalogue)

    for agent in agents(catalogue):
        if not artifacts_for(agent, "windows"):
            continue
        skipped: list[Skip] = []
        entries: list[str] = []
        for artifact in artifacts_for(agent, "windows"):
            rows, reason = _rows(artifact)
            if reason:
                skipped.append(Skip(artifact.id, reason))
                continue
            for path, mask, recursive in rows:
                entries.append(
                    "\n".join(
                        [
                            "    -",
                            f"        Name: {artifact.id}",
                            f"        Category: {artifact.category}",
                            f"        Path: {path}",
                            # Quoted because a bare * is a YAML alias, which makes the
                            # file unparseable by anything except KAPE itself. An examiner
                            # who wants to lint or diff these needs them to be real YAML.
                            f'        FileMask: "{mask}"',
                            f"        Recursive: {str(recursive).lower()}",
                        ]
                    )
                )
        if not entries:
            continue
        filename = f"AIAgent_{agent.agent}.tkape"
        names.append((agent.title, filename))
        text = "\n".join(
            [
                header(generated_note(digest, scope) + skip_lines(dedupe(skipped))),
                f"Description: AI coding agent artifacts, {agent.title}",
                "Author: agentforensics",
                "Version: 1.0",
                f"Id: {_stable_id(agent.agent)}",
                "RecreateDirectories: true",
                "Targets:",
                *entries,
                "",
            ]
        )
        out.append(Rendered(f"kape/{filename}", text, dedupe(skipped)))

    out.append(_compound(names, digest))
    return out


def _stable_id(seed: str) -> str:
    """A deterministic GUID-shaped id.

    KAPE wants a unique id per target file and examiners keep these files under version
    control, so a random one would change on every regeneration and make every diff noise.
    """
    digest = hashlib.sha256(("agentforensics.kape." + seed).encode("utf-8")).hexdigest()
    return "-".join((digest[:8], digest[8:12], digest[12:16], digest[16:20], digest[20:32]))


def _compound(names: list[tuple[str, str]], digest: str) -> Rendered:
    entries = []
    for title, filename in sorted(names):
        entries.append(
            "\n".join(
                [
                    "    -",
                    f"        Name: {title}",
                    "        Category: AIAgents",
                    '        Path: ""',
                    '        FileMask: ""',
                    f"        Comment: {filename}",
                ]
            )
        )
    text = "\n".join(
        [
            header(
                generated_note(
                    digest,
                    [
                        "",
                        "A compound target: it pulls in the per-agent files beside it, so KAPE",
                        "collects every agent in one pass. Use it when you do not yet know",
                        "which agent was used, which is the usual state at the start of a case.",
                    ],
                )
            ),
            "Description: AI coding agent artifacts, every agent",
            "Author: agentforensics",
            "Version: 1.0",
            f"Id: {_stable_id('compound')}",
            "RecreateDirectories: true",
            "Targets:",
            *entries,
            "",
        ]
    )
    return Rendered("kape/AIAgents.tkape", text, [])


__all__ = ["render"]
