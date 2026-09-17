"""Match a concrete path from an endpoint against the artifact catalogue.

The native bundle's manifest already says which catalogue entry claimed each file, because
the collector knew. A KAPE output tree, a Velociraptor collection or a mounted image do
not: they are a root full of files, and somebody has to decide that
`Users/alice/.claude/projects/-src-app/9f2.jsonl` is a Claude Code transcript before a
parser can be chosen for it.

That decision is what this module makes, and it has one rule that shapes everything else:
a file that matches nothing is still carried forward, with its non-match recorded. A path
the catalogue does not know is either an agent nobody has catalogued yet or a gap in the
catalogue, and both are findings. Dropping it would turn either one into silence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

from agentforensics.catalog import Artifact, Catalogue

# The profile directory as it appears in a collected tree, per platform. A tree adapter
# sees an absolute path from the endpoint, so the profile is a real directory name rather
# than a placeholder, and the pattern has to allow any user name.
_PROFILE_PATTERNS = (
    r"(?:[A-Za-z]:)?/Users/[^/]+",
    r"/home/[^/]+",
    r"/root",
    r"/var/root",
    # An exported profile, whose tree has no profile directory above it. One of the four
    # sources this suite reads is exactly that, and without this every profile-anchored
    # entry in the catalogue failed to match it: an ingest of a user's own home directory
    # attributed almost nothing.
    r"~",
)

_WINDOWS_RELATIVE = {
    "%USERPROFILE%": "",
    "%APPDATA%": "AppData/Roaming",
    "%LOCALAPPDATA%": "AppData/Local",
    "%TEMP%": "AppData/Local/Temp",
    "%TMP%": "AppData/Local/Temp",
}

_WINDOWS_ABSOLUTE = {
    "%PROGRAMDATA%": r"(?:[A-Za-z]:)?/ProgramData",
    "%ALLUSERSPROFILE%": r"(?:[A-Za-z]:)?/ProgramData",
    "%PROGRAMFILES%": r"(?:[A-Za-z]:)?/Program Files",
    "%PROGRAMFILES(X86)%": r"(?:[A-Za-z]:)?/Program Files \(x86\)",
    "%SYSTEMROOT%": r"(?:[A-Za-z]:)?/Windows",
    "%WINDIR%": r"(?:[A-Za-z]:)?/Windows",
    "%PUBLIC%": r"(?:[A-Za-z]:)?/Users/Public",
}

_VSCODE_PRODUCTS = (
    "Code",
    "Code - Insiders",
    "VSCodium",
    "Cursor",
    "Windsurf",
    "Kiro",
    "Trae",
    "Positron",
)

_VSCODE_USER = (
    "Library/Application Support/{product}/User",
    ".config/{product}/User",
    "AppData/Roaming/{product}/User",
)


@dataclass(frozen=True, slots=True)
class Match:
    """One catalogue entry that claims a path, and how specifically."""

    artifact: Artifact
    # How many literal characters of the pattern matched. A path claimed by both a
    # directory-level entry and a file-level one belongs to the file-level one, and this is
    # how that is decided: the more literal the pattern, the more specific the claim.
    specificity: int


def _segment_regex(segment: str) -> str:
    """One path segment as a regex fragment.

    A catalogue segment can hold a variable placeholder, a wildcard, or both around literal
    text, as in `chat-history-<md5>.json` and `rollout-*.jsonl.zst`. Splitting on the
    placeholders and escaping the rest is what keeps the literal parts literal: a `.` in a
    filename must not match any character, or a pattern for one agent's database starts
    claiming another's.
    """
    out = []
    for piece in re.split(r"(<[^>]*>|\*)", segment):
        if piece == "*":
            out.append("[^/]*")
        elif piece.startswith("<") and piece.endswith(">"):
            out.append("[^/]+")
        elif piece:
            out.append(re.escape(piece))
    return "".join(out)


def _tail_regex(tail: str) -> tuple[str, int]:
    """The part of a pattern below its root, as a regex, plus its literal length."""
    out = []
    literal = 0
    segments = [s for s in tail.split("/") if s != ""]
    for index, segment in enumerate(segments):
        if segment == "**":
            if index == len(segments) - 1:
                # A trailing ** means everything under here, files included. Written as the
                # intermediate form it matched only directories, so a checkpoint repository
                # spelled `cli-checkouts/<id>/**` claimed the directory and none of its
                # files, which is the whole content.
                out.append(".*")
            else:
                # Any depth, including none. The trailing separator is folded in so that
                # `a/**/b` matches `a/b` as well as `a/x/y/b`.
                out.append("(?:[^/]+/)*")
            continue
        out.append(_segment_regex(segment))
        literal += len(re.sub(r"<[^>]*>|\*", "", segment))
        if index < len(segments) - 1:
            out.append("/")
    body = "".join(out)
    # A pattern that named a directory matches the directory and everything under it: that
    # is how the catalogue means it and how the collector reads it.
    if tail.endswith("/") or not segments:
        body += "(?:/.*)?" if body else ".*"
    else:
        body += "(?:/.*)?"
    return body, literal


def _pattern_regexes(path: str) -> list[tuple[str, int]]:
    """Every regex one catalogue path should be matched by, with its literal length.

    More than one because a single catalogue path can stand for several real locations: a
    profile-anchored path exists under every profile directory, and the editor user
    directory placeholder expands to one location per editor product.
    """
    text = path.replace("\\", "/")
    upper = text.upper()

    if text.startswith("<vscode-user>"):
        tail = text[len("<vscode-user>") :].lstrip("/")
        out = []
        for template in _VSCODE_USER:
            for product in _VSCODE_PRODUCTS:
                relative = template.format(product=product)
                body, literal = _tail_regex(f"{relative}/{tail}" if tail else relative + "/")
                for profile in _PROFILE_PATTERNS:
                    out.append((f"{profile}/{body}", literal))
        return out

    for placeholder, absolute in _WINDOWS_ABSOLUTE.items():
        if upper.startswith(placeholder):
            body, literal = _tail_regex(text[len(placeholder) :])
            return [(f"{absolute}/{body}" if body else absolute, literal)]

    for placeholder, relative in _WINDOWS_RELATIVE.items():
        if upper.startswith(placeholder):
            tail = text[len(placeholder) :].lstrip("/")
            joined = "/".join(x for x in (relative, tail) if x) or "/"
            body, literal = _tail_regex(joined)
            return [(f"{profile}/{body}", literal) for profile in _PROFILE_PATTERNS]

    if text.startswith("~/") or text == "~":
        body, literal = _tail_regex(text[1:] or "/")
        return [(f"{profile}/{body}", literal) for profile in _PROFILE_PATTERNS]

    drive = re.match(r"^([A-Za-z]):/", text)
    if drive:
        # Written with a drive letter in the catalogue. Matched with the drive optional,
        # because a collected tree may or may not have kept it, and matched against any
        # letter, because an endpoint whose system volume is not C: is still that endpoint.
        body, literal = _tail_regex(text[2:])
        return [(f"(?:[A-Za-z]:)?/{body.lstrip('/')}", literal)]

    if text.startswith("/"):
        body, literal = _tail_regex(text)
        # A drive letter is allowed in front so that a Windows system path collected into a
        # tree as C:/ProgramData still matches the catalogue's spelling of it.
        return [(f"(?:[A-Za-z]:)?/{body.lstrip('/')}", literal)]

    if text.startswith(
        ("<project>", "<repo-root>", "<repo_root>", "<plugin-root>", "<marketplace-root>")
    ):
        # A working copy, whose location the catalogue cannot state and the collector reads
        # out of the agent's own state file. In a tree there is no state file, so the only
        # thing to match on is what sits below the project root, at any depth.
        #
        # Worth doing rather than skipping: these are the project instruction files, the
        # rule directories and the project server inventories, which is to say exactly the
        # evidence an injected-instruction question is about. Leaving them unmatched meant
        # an ingest of a developer's home directory attributed their agent's configuration
        # and none of the files that told the agent what to do.
        #
        # Same distinctiveness floor as a relocated tree below, for the same reason: a
        # pattern that reduces to a bare file extension would claim every file of that type
        # on the disk.
        _, _, tail = text.partition("/")
        if not tail:
            return []
        named = [segment for segment in tail.split("/") if segment not in ("", "**")]
        body, literal = _tail_regex(tail)
        if not named or literal < 5:
            return []
        return [(f".*/{body}", literal)]

    if text.startswith("$"):
        # A relocated tree. Where the variable pointed is not knowable from a path alone,
        # so the part below it can only be matched at any location, and that is dangerous:
        # the first version of this turned `$VAR/**/*.jsonl` into a claim on every
        # line-delimited transcript on the disk, and `$VAR/logs/` into a claim on every log
        # directory, so four agents were credited with each other's files.
        #
        # A relocated pattern is therefore only matched when what is below the variable is
        # distinctive on its own: two or more named segments and enough literal text that
        # it is not simply a file extension. Everything else is left unmatched, which is
        # the honest answer, and the file is still carried forward with its non-match
        # recorded. A mis-attributed file is an error nobody sees; an unattributed one is a
        # question somebody answers.
        _, _, tail = text.partition("/")
        if not tail:
            return []
        named = [s for s in tail.split("/") if s not in ("", "**")]
        body, literal = _tail_regex(tail)
        if len(named) < 2 or literal < 8:
            return []
        return [(f".*/{body}", literal)]

    return []


@dataclass(frozen=True, slots=True)
class _Compiled:
    regex: re.Pattern[str]
    literal: int
    artifact: Artifact


class Matcher:
    """Matches concrete endpoint paths against the catalogue.

    Built once per ingest: compiling a few thousand regexes takes a moment, and matching a
    hundred thousand collected files against them one at a time would otherwise dominate
    the run.
    """

    def __init__(self, catalogue: Catalogue) -> None:
        self._compiled: list[_Compiled] = []
        for artifact in catalogue.artifacts:
            if artifact.root == "registry":
                continue
            for path in artifact.paths:
                for body, literal in _pattern_regexes(path):
                    try:
                        regex = re.compile("^" + body + "$", re.IGNORECASE)
                    except re.error:
                        # A pattern this module cannot turn into a regex is a catalogue
                        # entry nothing will ever match, which a test asserts against. It
                        # is skipped here rather than raised so that one malformed entry
                        # cannot stop an ingest that is otherwise fine.
                        continue
                    self._compiled.append(_Compiled(regex, literal, artifact))

    def __len__(self) -> int:
        return len(self._compiled)

    @lru_cache(maxsize=65536)  # noqa: B019 - bound per Matcher, which lives for one ingest
    def _match(self, path: str) -> tuple[Match, ...]:
        normalised = path.replace("\\", "/")
        found: dict[str, Match] = {}
        for entry in self._compiled:
            if not entry.regex.match(normalised):
                continue
            previous = found.get(entry.artifact.id)
            if previous is None or entry.literal > previous.specificity:
                found[entry.artifact.id] = Match(entry.artifact, entry.literal)
        # Most specific first, then by id so two equally specific claims order stably.
        return tuple(sorted(found.values(), key=lambda m: (-m.specificity, m.artifact.id)))

    def matches(self, path: str) -> tuple[Match, ...]:
        """Every catalogue entry that claims this path, most specific first.

        All of them, not just the best: a path can legitimately be claimed by a
        directory-level entry and a file-level one, and an analyst asking which entries
        cover a file wants both. The caller picks the first for attribution.
        """
        return self._match(path)

    def best(self, path: str) -> Match | None:
        matches = self.matches(path)
        return matches[0] if matches else None


__all__ = ["Match", "Matcher"]
