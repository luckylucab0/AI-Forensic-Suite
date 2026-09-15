"""A Microsoft Defender for Endpoint live response package, generated from the catalogue.

Live response is not a query language, so this exporter generates something different in
kind from the others: a runbook and two scripts, not a rule. Its command set is small, it
has no wildcards worth relying on and a file has to be named exactly to be fetched, so the
only honest way to collect 460 catalogue paths through it is to push the suite's own
collector to the endpoint, run it, and fetch the bundle it writes.

What the catalogue contributes is the presence check. A short script that says which agents
left a trace, so an analyst working through a fleet one live-response session at a time can
decide in seconds whether this host is worth the several minutes a full collection takes.
"""

from __future__ import annotations

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
    skip_lines,
    wildcard_segments,
)

_PREFIXES = {
    "%USERPROFILE%": "$profile",
    "%APPDATA%": "$profile\\AppData\\Roaming",
    "%LOCALAPPDATA%": "$profile\\AppData\\Local",
    "%TEMP%": "$profile\\AppData\\Local\\Temp",
    "%TMP%": "$profile\\AppData\\Local\\Temp",
    "%PROGRAMDATA%": "C:\\ProgramData",
    "%ALLUSERSPROFILE%": "C:\\ProgramData",
    "%PROGRAMFILES%": "C:\\Program Files",
    "%PROGRAMFILES(X86)%": "C:\\Program Files (x86)",
    "%SYSTEMROOT%": "C:\\Windows",
    "%WINDIR%": "C:\\Windows",
    "%PUBLIC%": "C:\\Users\\Public",
}


def _probe(path: str) -> str | None:
    """A path the presence script can test, or None.

    Only the fixed part up to the first wildcard is kept, because the script tests for
    existence rather than matching: the deepest directory that is certain is the most
    specific thing that can be tested without a glob.
    """
    text = wildcard_segments(path).replace("/", "\\")
    upper = text.upper()
    for placeholder, prefix in _PREFIXES.items():
        if upper.startswith(placeholder):
            text = prefix + text[len(placeholder) :]
            break
    else:
        if text.startswith("~\\"):
            text = "$profile" + text[1:]
        elif not re.match(r"^[A-Za-z]:\\", text):
            return None
    text = text.split("*", 1)[0].rstrip("\\")
    if text in ("$profile", "") or text.count("\\") < 1:
        return None
    return text


def _probes(artifact: Artifact) -> tuple[list[str], str | None]:
    if is_registry(artifact):
        return [], "a registry key, which the runbook's collector reads instead"
    if needs_discovery(artifact):
        return [], (
            "anchored at a working copy, whose location only the agent's own state file "
            "gives: the runbook's collector reads it, this check cannot"
        )
    probes: list[str] = []
    saw_variable = False
    for path in iter_paths(artifact, "windows"):
        if bare_variable(path) or has_variable(path):
            saw_variable = True
            continue
        probe = _probe(path)
        if probe:
            probes.append(probe)
    if probes:
        return sorted(set(probes)), None
    if saw_variable:
        return [], (
            "reachable only through a relocation variable: the runbook's collector reads "
            "the variable, this check does not"
        )
    return [], "no Windows path with a testable fixed prefix"


def render(catalogue: Catalogue) -> list[Rendered]:
    digest = catalogue_digest(catalogue)
    return [_presence_script(catalogue, digest), _runbook(catalogue, digest)]


def _presence_script(catalogue: Catalogue, digest: str) -> Rendered:
    skipped: list[Skip] = []
    rows: list[tuple[str, str, str]] = []
    for agent in agents(catalogue):
        for artifact in artifacts_for(agent, "windows"):
            probes, reason = _probes(artifact)
            if reason:
                skipped.append(Skip(artifact.id, reason))
                continue
            for probe in probes:
                rows.append((agent.agent, artifact.id, probe))

    lines = [
        header(
            generated_note(
                digest,
                [
                    "",
                    "Presence only. It reads directory existence and file counts and copies",
                    "nothing, so it is safe to run on a host you have not yet decided to",
                    "collect from. For the collection itself, follow the runbook beside this",
                    "file: this script cannot see a relocated tree or a project directory,",
                    "and the collector can.",
                    "",
                    "PowerShell 5.1, no modules, one file, because that is what a live",
                    "response session can run.",
                    "",
                    "Live response is Windows only here, so every catalogue artifact that",
                    "declares no Windows path is outside this check's scope entirely, which",
                    "is a different thing from the per-artifact gaps listed below.",
                ],
            )
            + skip_lines(dedupe(skipped))
        ),
        "",
        "$ErrorActionPreference = 'Stop'",
        "# Every profile on the machine, not just the interactive user's: an agent driven by",
        "# a service account is exactly the case a single-profile check would miss.",
        "$profiles = @()",
        "try {",
        "    $profiles = Get-ChildItem -LiteralPath 'C:\\Users' -Directory -ErrorAction Stop |",
        "        Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') } |",
        "        ForEach-Object { $_.FullName }",
        "} catch {",
        "    Write-Output ('cannot enumerate profiles: ' + $_.Exception.Message)",
        "}",
        "",
        "$targets = @(",
    ]
    # The artifact id travels with each path so the script says which catalogue entry it
    # is checking. Whoever reads the output is usually not whoever generated the file, and
    # "cline: 12 files" is a different statement from naming the entry that matched.
    for agent_name, artifact_id, probe in sorted(set(rows)):
        escaped = probe.replace("'", "''")
        lines.append(f"    @{{ Agent = '{agent_name}'; Id = '{artifact_id}'; Path = '{escaped}' }}")
    lines.extend(
        [
            ")",
            "",
            "$found = @{}",
            "$errors = @()",
            "foreach ($target in $targets) {",
            "    $paths = @()",
            "    if ($target.Path -like '$profile*') {",
            "        foreach ($profileDir in $profiles) {",
            "            $paths += ($target.Path -replace '^\\$profile', [regex]::Escape($profileDir) -replace '\\\\\\\\', '\\')",
            "        }",
            "    } else {",
            "        $paths += $target.Path",
            "    }",
            "    foreach ($candidate in $paths) {",
            "        try {",
            "            if (Test-Path -LiteralPath $candidate) {",
            "                $count = 1",
            "                if ((Get-Item -LiteralPath $candidate).PSIsContainer) {",
            "                    $count = (Get-ChildItem -LiteralPath $candidate -Recurse -File -ErrorAction SilentlyContinue |",
            "                        Measure-Object).Count",
            "                }",
            "                if (-not $found.ContainsKey($target.Agent)) { $found[$target.Agent] = 0 }",
            "                $found[$target.Agent] += $count",
            "            }",
            "        } catch {",
            "            # A path that cannot be read is reported rather than skipped: an",
            "            # access denial is a different answer from an absent directory, and",
            "            # collapsing the two is how a used agent looks unused.",
            "            $errors += ($candidate + ': ' + $_.Exception.Message)",
            "        }",
            "    }",
            "}",
            "",
            "if ($found.Count -eq 0) {",
            "    Write-Output 'no agent artifacts found at any catalogued Windows path'",
            "} else {",
            "    foreach ($agent in ($found.Keys | Sort-Object)) {",
            "        Write-Output ($agent + ': ' + $found[$agent] + ' file(s)')",
            "    }",
            "}",
            "foreach ($problem in ($errors | Sort-Object -Unique)) {",
            "    Write-Output ('unreadable ' + $problem)",
            "}",
            "",
        ]
    )
    return Rendered("mde/Check-AIAgentPresence.ps1", "\n".join(lines), dedupe(skipped))


def _runbook(catalogue: Catalogue, digest: str) -> Rendered:
    agent_lines = []
    for agent in agents(catalogue):
        windows = artifacts_for(agent, "windows")
        if windows:
            agent_lines.append(f"| {agent.title} | `{agent.agent}` | {len(windows)} |")

    text = "\n".join(
        [
            "# Collecting AI coding agent artifacts through live response",
            "",
            *header(generated_note(digest), comment="<!--").split("\n"),
            "-->",
            "",
            "Live response has a small command set, no usable wildcards and no way to fetch a",
            "file it cannot name exactly. Collecting a few hundred catalogued paths through it",
            "one `getfile` at a time is not practical, so the sequence below pushes this",
            "suite's own collector instead, runs it, and fetches the bundle it produced. The",
            "collector reads the relocation variables and the agents' own state files, which",
            "no fixed list of paths can.",
            "",
            "## Before the session",
            "",
            "Upload `collect.ps1` to the live response library once, under **Settings >",
            "Endpoints > Live response**. It is a single file with no modules and it runs on",
            "PowerShell 5.1, which is what a live response session provides.",
            "",
            "Upload `Check-AIAgentPresence.ps1` beside it if you are working through a fleet:",
            "it reports which agents left a trace and copies nothing, so it is the cheap first",
            "step on a host you have not yet decided to collect from.",
            "",
            "## In the session",
            "",
            "```text",
            "# 1. Decide whether this host is worth a collection. Reads only, copies nothing.",
            "run Check-AIAgentPresence.ps1",
            "",
            "# 2. Collect. Writes a bundle under the path the script reports.",
            "#    Drop -AllUsers if you are only interested in the signed-in user; the manifest",
            "#    records which was done either way, so a partial collection is an honest one.",
            'run collect.ps1 -parameters "-AllUsers -Zip"',
            "",
            "# 3. Fetch it. Use the exact path the previous step printed.",
            'getfile "C:\\\\Windows\\\\Temp\\\\agentforensics\\\\<bundle-id>.zip"',
            "```",
            "",
            "Then verify the bundle before you read it, on your own workstation:",
            "",
            "```bash",
            "afx verify <bundle-id>.zip",
            "```",
            "",
            "## Why not a list of getfile commands",
            "",
            "Because it would be a worse answer that looks like a better one. Live response",
            "fetches a named file, so a generated list could only name the paths with no",
            "wildcard in them. Every session store in this catalogue is keyed by a session",
            "identifier or a workspace hash, which means the transcripts, the part of the",
            "evidence an investigation is actually about, would be exactly what such a list",
            "left out.",
            "",
            "## What is on the endpoint, per agent",
            "",
            "Windows-relevant catalogue entries, as a sense of what a collection will cover:",
            "",
            "| Agent | Key | Windows artifacts |",
            "| --- | --- | --- |",
            *sorted(agent_lines),
            "",
            "The count is entries, not files: one entry can be a directory holding a thousand",
            "transcripts, or a file that is not there on this host.",
            "",
        ]
    )
    return Rendered("mde/RUNBOOK.md", text, [])


__all__ = ["render"]
