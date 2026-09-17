"""Reaching into an event from a rule file, by name.

A rule says `payload.commands[].command` and gets back every command line in that event.
This module is the whole of what a rule may address, and keeping it small is the point: a
rule file cannot execute code, cannot call a function, and cannot reach anything this file
does not name. That is what makes a pack of rules reviewable by someone who is not going to
read the engine.

Two properties are load-bearing.

**A selector resolves to a list, never to a value.** `payload.commands[].command` over an
event with three commands gives three strings, and a leaf condition matches when any of
them satisfies it. That is the semantics an analyst expects from "does this event run a
dangerous command", and it removes the whole class of rule that accidentally only checks
the first element.

**An absent field resolves to an empty list, never to None.** So `exists: false` is a real
condition rather than a special case, and no operator has to decide what to do with a
missing value. A rule about something that is not there is as ordinary as a rule about
something that is.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

# The event fields a rule may address by their bare name, mapped to where they live on the
# view. Explicit rather than getattr, so a rule cannot reach a private attribute and a
# typo in a rule file is an error at load time instead of a condition that never matches.
TOP_LEVEL = {
    "kind",
    "agent",
    "actor",
    "client",
    "host",
    "user",
    "session_id",
    "project_path",
    "git_branch",
    "ts_utc",
    "parse_problem",
    "event_id",
}

# Provenance, addressed with its prefix so a rule about a path says which path it means.
PROVENANCE = {"bundle_uuid", "original_path", "sha256", "artifact_id", "locator"}

# Whole-record text. The secrets pack needs these: a credential can sit in any field of any
# record, including one no parser mapped, and a rule that only searched the fields somebody
# thought to map would miss exactly the cases that matter.
# Rendered by flatten(), which emits the structure's leaves one per line rather than JSON.
# See the comment there: JSON escapes the quotes inside a string, and a detection pattern
# that depends on how the thing it searches was serialised breaks on the next producer.
TEXT_VIEWS = {
    # The original record.
    "raw_text",
    # The mapped payload.
    "payload_text",
    # Both, which is what "search this event for a secret" means.
    "event_text",
}

# Shorthands, because payload.text is written in almost every rule.
ALIASES = {"text": "payload.text"}


class SelectorError(ValueError):
    """A selector a rule file may not use. Raised at load time, never at scan time."""


@dataclass(frozen=True, slots=True)
class EventView:
    """One event, in the shape a rule sees it.

    Built from a case database row rather than from `Event`, because scanning reads a case
    back out and the payload and raw record arrive as text. Decoded once per event here, so
    a pack of eighty rules does not decode the same JSON eighty times.
    """

    event_id: str
    kind: str
    agent: str
    actor: str
    ts_utc: str | None
    client: str | None
    host: str | None
    user: str | None
    session_id: str | None
    project_path: str | None
    git_branch: str | None
    parse_problem: str | None
    payload: dict[str, Any]
    raw: Any
    provenance: dict[str, Any]

    def text_view(self, name: str) -> str:
        """One of the whole-record text views, built on demand.

        Not cached: a rule pack that uses them touches every event once, and holding a
        second copy of every raw record in memory for a large case costs more than the
        rendering does.
        """
        if name == "payload_text":
            return flatten(self.payload)
        if name == "raw_text":
            return flatten(self.raw)
        return flatten(self.payload) + "\n" + flatten(self.raw)


def check(selector: str) -> None:
    """Refuse a selector no event can answer.

    Called when a rule is loaded, so a misspelled field is a rule that fails to load rather
    than a rule that runs forever and never fires. A rule that silently matches nothing is
    the worst outcome available here: it looks like a clean case.
    """
    name = ALIASES.get(selector, selector)
    if name in TOP_LEVEL or name in TEXT_VIEWS:
        return
    if name.startswith("payload.") or name == "payload":
        return
    if name.startswith("provenance."):
        field = name.split(".", 1)[1].split("[")[0]
        if field in PROVENANCE:
            return
        raise SelectorError(
            f"provenance has no field {field!r}. It has: " + ", ".join(sorted(PROVENANCE))
        )
    if name in ("raw",) or name.startswith("raw."):
        return
    raise SelectorError(
        f"{selector!r} is not something an event can be asked for. Use one of "
        + ", ".join(sorted(TOP_LEVEL | TEXT_VIEWS))
        + ", or a path under payload., raw. or provenance."
    )


def resolve(event: EventView, selector: str) -> list[Any]:
    """Every value the selector names in this event, in order.

    Empty when the field is absent, which is the answer `exists: false` is written against.
    """
    name = ALIASES.get(selector, selector)
    if name in TEXT_VIEWS:
        return [event.text_view(name)]
    if name in TOP_LEVEL:
        value = getattr(event, name)
        return [] if value is None else [value]

    head, _, rest = name.partition(".")
    if head == "payload":
        root: Any = event.payload
    elif head == "raw":
        root = event.raw
    elif head == "provenance":
        root = event.provenance
    else:  # pragma: no cover - check() rejects this at load time
        raise SelectorError(f"unknown selector root {head!r}")

    if not rest:
        return [] if root is None else [root]
    return _walk([root], rest.split("."))


def _walk(values: list[Any], steps: list[str]) -> list[Any]:
    """Follow one dotted path, fanning out at every `[]`.

    The fan-out is why this is a list walk rather than a nested get: `files[].path` over an
    event that touched four files has to give four paths, and a rule written against the
    first one only would be a rule that misses three quarters of what happened.
    """
    current = values
    for step in steps:
        field, fan = (step[:-2], True) if step.endswith("[]") else (step, False)
        nxt: list[Any] = []
        for value in current:
            got = _get(value, field)
            if got is None:
                continue
            if fan:
                # A producer that wrote one mapping where the schema allows a list is
                # tolerated rather than skipped. The coarser reading is still evidence.
                nxt.extend(got if isinstance(got, list) else [got])
            else:
                nxt.append(got)
        current = nxt
        if not current:
            return []
    return current


def _get(value: Any, field: str) -> Any:
    if isinstance(value, dict):
        return value.get(field)
    # A list reached without `[]`. Read through it rather than refusing, so a rule stays
    # correct when a producer nests one level deeper than another.
    if isinstance(value, list):
        out = [item.get(field) for item in value if isinstance(item, dict)]
        out = [item for item in out if item is not None]
        return out or None
    return None


def _as_text(value: Any) -> str:
    """A value as the text a regex is run over.

    A string is itself. Anything else is JSON with ensure_ascii off, so a prompt in any
    language is searched as it was written rather than as escapes, and sort_keys on, so the
    same event always produces the same text and therefore the same findings.
    """
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def as_text(value: Any) -> str:
    """The same rendering, for an operator that has to compare a non-string."""
    return _as_text(value)


# How deep the flattener goes. A record can nest arbitrarily and a cycle cannot occur in
# JSON, but a pathological depth would cost more than it is worth to search.
_FLATTEN_DEPTH = 24


def flatten(value: Any, depth: int = 0) -> str:
    """A whole record as the plain text a rule's regex is run over.

    Not JSON. That was the first implementation and it was wrong in a way the rule tests
    caught: rendering a record as JSON escapes the quotes inside its strings, so a pattern
    written for `AUTH_TOKEN = "value"` no longer matched once the string was nested, because
    what the pattern actually saw was `AUTH_TOKEN = \\"value\\"`. A detection pattern that
    depends on the serialisation of the thing it searches is a pattern that will break
    silently on the next producer.

    So this walks the structure and emits its leaves, one per line, with a mapping's key
    joined to its value by ` = `. Two things fall out of that shape, both of them wanted. A
    credential stored as a field, `{"password": "s3cr3t"}`, reads as `password = s3cr3t`,
    which is the same text a rule already had to match in a command line. And a key whose
    name is the only evidence, with an absent or empty value, still appears.
    """
    if depth > _FLATTEN_DEPTH:
        return "..."
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dict):
        lines = []
        for key, item in value.items():
            rendered = flatten(item, depth + 1)
            # A nested structure goes on its own lines under the key rather than being
            # squeezed onto one, so a pattern anchored at a line start still works.
            joiner = "\n" if "\n" in rendered else " = "
            lines.append(f"{key}{joiner}{rendered}")
        return "\n".join(lines)
    if isinstance(value, (list, tuple)):
        return "\n".join(flatten(item, depth + 1) for item in value)
    return _as_text(value)


def as_number(value: Any) -> float | None:
    """A value as a number, or None when it is not one.

    Strings are converted, because a record can carry a size or an exit code as text, and a
    rule about a threshold should not have to know which producer wrote it.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def compile_glob(pattern: str) -> re.Pattern[str]:
    """A path glob as a regex.

    Its own implementation rather than fnmatch because a path rule needs `**` to cross
    separators and `*` not to, and fnmatch's `*` crosses everything. A rule that says
    `~/.ssh/*` and matched `~/.ssh/a/b/c` would be a rule nobody could reason about.
    """
    out = ["(?s)\\A"]
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "*":
            if pattern.startswith("**", index):
                out.append(".*")
                index += 2
                continue
            out.append("[^/\\\\]*")
        elif char == "?":
            out.append("[^/\\\\]")
        elif char in "/\\":
            # Either separator matches either, so one rule covers both platforms.
            out.append("[/\\\\]")
        else:
            out.append(re.escape(char))
        index += 1
    out.append("\\Z")
    return re.compile("".join(out), re.IGNORECASE)


__all__ = [
    "ALIASES",
    "PROVENANCE",
    "TEXT_VIEWS",
    "TOP_LEVEL",
    "EventView",
    "SelectorError",
    "as_number",
    "as_text",
    "check",
    "compile_glob",
    "flatten",
    "resolve",
]
