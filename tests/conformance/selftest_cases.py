"""The structures collect.ps1 -SelfTest prints, and the one definition of what they mean.

Two callers: the conformance test, which runs the collector itself, and
check_selftest.py, which the Windows CI job points at output from real PowerShell 5.1.
Keeping the expectations here means those two cannot disagree about what parity is.

The cases are the ones that have actually gone wrong. An empty array and a one-element
array, because PowerShell unwraps both across a function boundary and a one-file manifest
would serialize as an object. A string full of backslashes, because catalogue paths are.
Non-ASCII, because ensure_ascii=False has to be matched rather than escaped. Control
characters, because Python uses short escapes for some and \\uXXXX for the rest.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

# The catalogue path shapes whose ranking has actually decided an attribution, plus one of
# every root kind. `<project>/.mcp.json` against `<plugin-root>/.mcp.json` is the pair that
# reported a project's own server configuration as a plugin manifest: same nine literal
# characters, and only the root tells them apart. `~/.claude/CLAUDE.md` against
# `<project>/.claude/CLAUDE.md` is the pair that reported the user's own instruction file at
# project scope.
SPECIFICITY_PATTERNS = (
    "~/.claude/CLAUDE.md",
    "<project>/.claude/CLAUDE.md",
    "<project>/**/CLAUDE.md",
    "<project>/.mcp.json",
    "<plugin-root>/.mcp.json",
    "~/.gemini/",
    "~/.gemini/tmp/<hash>/chats/*.jsonl",
    "$CLAUDE_CONFIG_DIR/.claude.json",
    "%APPDATA%\\Block\\goose\\data\\sessions\\sessions.db",
    "/etc/claude-code/managed-settings.json",
)


def _collect_py() -> object:
    """collect.py as a module, without running it.

    Imported by path because it is a standalone single file rather than part of the
    package: that is the point of it, so it can be pushed through live-response tooling.
    """
    path = Path(__file__).resolve().parents[2] / "collector" / "collect.py"
    spec = importlib.util.spec_from_file_location("_collect_for_parity", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The Windows target's own expansion, which no differential reached until this case
# existed: every conformance invocation of both collectors passes --os linux, and the only
# other exercise of the Windows target never touched a filesystem. The patterns are the
# shapes that decide whether a relocated agent tree is searched, refused or silently
# dropped, one of each.
#
# A root is passed, so nothing here reads an environment variable and the answer is the same
# on every machine: a mounted image is exactly the case where the endpoint's variables
# cannot be consulted, which is the outcome that has to be reported rather than swallowed.
WINDOWS_HOME = "/mnt/img/Users/alice"
WINDOWS_ROOT = "/mnt/img"
WINDOWS_PATTERNS = (
    # An agent's own relocation variable. Unresolvable from an image, so a refusal.
    "$HERMES_HOME/state.db",
    "$CLAUDE_CONFIG_DIR/.credentials.json",
    # A freedesktop variable: another platform's spelling, dropped without a refusal
    # because the entry's Windows sibling is being searched.
    "$XDG_DATA_HOME/zed/db/0-stable/db.sqlite",
    "${XDG_STATE_HOME:-~/.local/state}/agent/x",
    # The ordinary spellings, which have to keep working.
    "~/.hermes/state.db",
    "%APPDATA%\\Block\\goose\\data\\sessions\\sessions.db",
    "%LOCALAPPDATA%\\amazon-q\\data.sqlite3",
    "%TEMP%\\qlog\\*.log",
    "%SystemRoot%\\Prefetch\\*.pf",
)


# Which claimant wins, which is what decides the catalogue entry a file is reported under
# and therefore whether a parser is found for it. The ids are chosen so the last key is the
# one that decides, and so that a culture-aware comparison would answer differently: a
# hyphen and an underscore order one way by code point and the other way by culture, and
# both characters are ordinary in an artifact id.
CLAIM_ORDER_CASES = (
    (("~/.x/y.json", "claude-code.plans"), ("~/.x/y.json", "claude_code.plans")),
    (("~/.gemini/", "a.tree"), ("~/.gemini/tmp/<hash>/chats/*.jsonl", "z.chats")),
    (("<project>/.claude/CLAUDE.md", "a.project"), ("~/.claude/CLAUDE.md", "z.user")),
    (("<plugin-root>/.mcp.json", "a.plugin"), ("<project>/.mcp.json", "z.project")),
)


def _claim_order_case() -> dict[str, object]:
    """Which of two claims on one file each collector reports it under."""
    collect = _collect_py()
    out: dict[str, object] = {}
    for case in CLAIM_ORDER_CASES:
        claims = [({"id": artifact_id}, pattern) for pattern, artifact_id in case]
        winner = sorted(
            claims,
            key=lambda claim: collect.claim_order(claim[0], claim[1]),  # type: ignore[attr-defined]
        )[0][0]["id"]
        out[" vs ".join(f"{pattern}|{artifact_id}" for pattern, artifact_id in case)] = winner
    return out


def _windows_expansion_case() -> dict[str, object]:
    """What the Python collector expands each pattern to on a Windows target.

    The PowerShell collector computes the same list with its own code and the two are
    compared, so a branch that only one of them takes shows up here rather than in a bundle
    taken from somebody's endpoint.
    """
    collect = _collect_py()
    out: dict[str, object] = {}
    for pattern in WINDOWS_PATTERNS:
        collect.PATTERN_REFUSALS.clear()  # type: ignore[attr-defined]
        expanded = collect.expand_paths(  # type: ignore[attr-defined]
            pattern, WINDOWS_HOME, "windows", WINDOWS_ROOT
        )
        out[pattern] = {
            "patterns": list(expanded),
            "refusals": [record["reason"] for record in collect.PATTERN_REFUSALS],  # type: ignore[attr-defined]
        }
    collect.PATTERN_REFUSALS.clear()  # type: ignore[attr-defined]
    return out


# Folder redirection, as fixed inputs rather than as whatever this machine happens to be
# set to. The decision is the tricky half of reading a redirected placeholder, and it is
# the half that has to be identical in both collectors: the lookup around it is guarded by
# a live host and by the profile being the process's own, neither of which is reproducible
# in a test.
REDIRECT_CASES = (
    # Moved to a share. A UNC value keeps its two leading separators.
    (
        "%APPDATA%\\Block\\goose\\sessions.db",
        "C:/Users/alice",
        "\\\\server\\share\\alice\\AppData\\Roaming",
    ),
    # Moved to another drive, with a trailing separator on the value.
    ("%LOCALAPPDATA%\\amazon-q\\data.sqlite3", "C:/Users/alice", "D:\\local\\"),
    # A wildcard in the tail has to survive.
    ("%TEMP%\\qlog\\*.log", "C:/Users/alice", "D:/tmp"),
    # Where the default already points: one pattern is enough and a second would double
    # every row of the manifest for these artifacts.
    ("%APPDATA%\\Block\\goose\\sessions.db", "C:/Users/alice", "C:/Users/alice/AppData/Roaming"),
    # The same, spelled the way Windows spells it, which is why the comparison ignores case
    # and separators.
    (
        "%APPDATA%\\Block\\goose\\sessions.db",
        "C:/Users/alice",
        "C:\\Users\\Alice\\AppData\\Roaming",
    ),
    # Not set at all.
    ("%APPDATA%\\Block\\goose\\sessions.db", "C:/Users/alice", ""),
    # Not a placeholder this collector knows.
    ("~/.hermes/state.db", "C:/Users/alice", "D:/somewhere"),
)


def _redirect_case() -> dict[str, object]:
    collect = _collect_py()
    return {
        f"{text} | {home} | {value}": collect.windows_redirect_target(text, home, value)  # type: ignore[attr-defined]
        for text, home, value in REDIRECT_CASES
    }


def _specificity_case() -> dict[str, object]:
    """The Python collector's own answer for each pattern, which the PowerShell one must
    reproduce exactly.

    Computed rather than written down, so this compares the two implementations instead of
    comparing both against a constant that could be wrong. The rule decides which catalogue
    entry a file is reported under, which decides whether a parser is found for it, so the
    two collectors disagreeing here is a bundle that reads differently depending on which
    collector took it. See ADR 0025.
    """
    collect = _collect_py()
    return {
        pattern: list(collect.pattern_specificity(pattern))  # type: ignore[attr-defined]
        for pattern in SPECIFICITY_PATTERNS
    }


CASES: dict[str, object] = {
    "dict_mixed": {"b": 1, "a": "two", "c": True, "d": None},
    "empty_dict": {},
    "empty_list": [],
    "one_element_list": ["only"],
    "nested": [[1, 2], {"k": ["x"]}],
    "unicode": "Grüezi ünd ãçcents 日本語 emoji",
    "control": "tab\there\nnewline\r\bback\fform",
    "quotes": 'he said "hi" and C:\\path\\to',
    "numbers": [0, 1, -1, 268435456, 9007199254740991],
    "bools": [True, False],
    "nulls_in_list": [None, "x", None],
    "pattern_specificity": _specificity_case(),
    "windows_expansion": _windows_expansion_case(),
    "windows_redirect": _redirect_case(),
    "claim_order": _claim_order_case(),
}


def parse_blocks(text: str) -> dict[str, str]:
    """Split -SelfTest output into {case name: rendered JSON}."""
    blocks: dict[str, list[str]] = {}
    name: str | None = None
    for line in text.replace("\r\n", "\n").split("\n"):
        if line.startswith("==="):
            name = line[3:].strip()
            blocks[name] = []
        elif name is not None:
            blocks[name].append(line)
    return {key: "\n".join(value).strip("\n") for key, value in blocks.items()}


def compare(text: str) -> list[str]:
    """Return one problem string per disagreement, empty when the two agree exactly."""
    rendered = parse_blocks(text)
    problems = []
    missing = sorted(set(CASES) - set(rendered))
    extra = sorted(set(rendered) - set(CASES))
    if missing:
        problems.append("the self test did not print: " + ", ".join(missing))
    if extra:
        problems.append("the self test printed unknown cases: " + ", ".join(extra))
    for case, value in CASES.items():
        if case not in rendered:
            continue
        want = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False)
        got = rendered[case]
        if got != want:
            # ascii() on both sides, and code points where they diverge. The first version
            # of this message used %r, and a Windows console encodes stderr as cp1252 with
            # backslashreplace: one side came out as replacement characters and the other
            # as \uXXXX escapes, for strings that may or may not have differed. A
            # diagnostic that cannot survive the log it is written to is not a diagnostic.
            problems.append(f"{case}: python {want!a}, powershell {got!a}")
            for index, (left, right) in enumerate(zip(want, got, strict=False)):
                if left != right:
                    problems.append(
                        f"{case}: first difference at index {index}: "
                        f"python U+{ord(left):04X}, powershell U+{ord(right):04X}"
                    )
                    break
            else:
                problems.append(
                    f"{case}: same prefix, different length: "
                    f"python {len(want)}, powershell {len(got)}"
                )
    return problems
