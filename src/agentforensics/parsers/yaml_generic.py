"""Read a whole YAML document the suite has no verified shape for, without inventing one.

The same reading as the JSON one, over the other format the catalogue's configurations are
written in: split by structure, one level deep, and read out of a record only what the
record literally names. The reading itself is in `structured_generic`; what is here is
which artifacts are YAML, which of them the catalogue calls a configuration, and the three
things about YAML that JSON does not have.

**A file can hold several documents.** `---` separates them, and several agents use that
for a list of profiles or recipes in one file. Each one is read in its own right, and the
locator says which: a single-document file is at `$`, and a multi-document file is at
`$doc[0]`, `$doc[1]` and so on, so a finding points at the document it came from rather
than at the file.

**A key does not have to be a string.** YAML allows a number, a date or a boolean as a
mapping key, and the case stores a record as JSON, which does not. Such a key is rendered
as the text of itself and the event says so, because the alternative is an ingest that
fails on the file and a record that reaches nobody.

**A value can be a date.** The loader returns a real date or datetime for one, which is
kept: the case renders it as text when it stores the record, and that rendering is the same
every time, which is what a case's determinism needs.

Nothing here resolves an alias into a copy, expands a merge key or trusts a tag: the safe
loader is used, so a file carrying a tag it does not know is a file this suite reports as
unread rather than one it executes anything for.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import yaml

from agentforensics.model import Event, unparsed
from agentforensics.parsers.base import ParseContext
from agentforensics.parsers.structured_generic import documents

# Every YAML artifact in the catalogue except the credential stores, written out rather
# than derived from the format field at runtime, for the reason `json_generic.DOCUMENTS` is
# written out: a parser is handed an artifact id and not a catalogue entry, and a document
# added to the catalogue should be read because somebody decided it should be.
# tests/unit/test_yaml_generic.py asserts that this set is exactly the catalogue's
# non-secret YAML artifacts, so adding one there fails CI until it is listed here.
#
# One of them, the fish history, is claimed by the parser for that format before this one
# ever sees it. It stays in the set on purpose: the set is what the catalogue says is YAML,
# and dropping an entry because something better took it over is how a later addition would
# stop failing the drift test.
DOCUMENTS = frozenset(
    {
        "aider.config",
        "aider.model_settings",
        "continue.agents",
        "continue.config",
        "continue.permissions",
        "crosscutting.shell_fish_history",
        "goose.config",
        "goose.permissions",
        "goose.recipes",
        "hermes.config",
        "hermes.cron",
        "hermes.profiles",
        "kilo_code.home_dir",
        "kilo_code.settings",
        "kiro.permissions_user",
        "kiro.permissions_workspace",
    }
)

# The ones the catalogue files as configuration, permissions or MCP configuration, which is
# what decides the event kind. Everything else is a document nobody has mapped, and the
# reading is exactly as thin either way.
CONFIGURATIONS = frozenset(
    {
        "aider.config",
        "aider.model_settings",
        "continue.agents",
        "continue.config",
        "continue.permissions",
        "goose.config",
        "goose.permissions",
        "goose.recipes",
        "hermes.config",
        "hermes.cron",
        "hermes.profiles",
        "kilo_code.home_dir",
        "kilo_code.settings",
        "kiro.permissions_user",
        "kiro.permissions_workspace",
    }
)

# Said on a record whose mapping had a key that was not text. The value of the key is kept,
# as its own text, so nothing is lost; what the note buys is that nobody reads the rendered
# key as the key the file contained.
RENAMED_KEYS = (
    "this record had {count} mapping key(s) that were not text, which YAML allows and the "
    "case's record format does not, so each is stored as the text of itself"
)


class YamlGenericParser:
    """The reading of last resort for a whole YAML document."""

    name = "yaml_generic"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in DOCUMENTS

    def parse(self, context: ParseContext) -> Iterator[Event]:
        try:
            text = context.local_path.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            yield unparsed(
                context.provenance("$"),
                context.agent,
                None,
                f"the file could not be read: {error}",
                user=context.user,
                host=context.host,
            )
            return

        loaded: list[Any] = []
        problem: str | None = None
        try:
            # list() rather than a lazy walk, because the loader raises while iterating and
            # a half-consumed generator would leave the documents it had already produced
            # out of the case along with the reason.
            loaded = list(yaml.safe_load_all(text))
        except yaml.YAMLError as error:
            problem = f"the file is not valid YAML this reader can load: {_one_line(error)}"

        if problem is not None:
            yield unparsed(
                context.provenance("$"),
                context.agent,
                # The text is not put in raw: a configuration file can be large, and the
                # bytes are in the bundle under their hash, which is where an analyst reads
                # them. The reason is what the case could not otherwise say.
                None,
                problem,
                user=context.user,
                host=context.host,
            )
            return

        configuration = context.artifact_id in CONFIGURATIONS
        if not loaded:
            # An empty file, or one holding nothing but comments. It is a fact about the
            # endpoint in the same way the JSON reader's empty document is.
            yield from documents(context, {}, configuration=configuration)
            return
        for index, document in enumerate(loaded):
            plain, renamed = _plain_keys(document)
            yield from documents(
                context,
                plain,
                configuration=configuration,
                # One document in the file is at `$`, several are numbered, so a finding
                # points at the document it came from and not at the file.
                at="$" if len(loaded) == 1 else f"$doc[{index}]",
                note=RENAMED_KEYS.format(count=renamed) if renamed else None,
            )


def _plain_keys(value: Any) -> tuple[Any, int]:
    """The value with every mapping key as text, and how many had to be rendered.

    Recursive, because a key that is not text anywhere in the record is enough to make the
    record unstorable, not only at the top.
    """
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        renamed = 0
        for key, nested in value.items():
            plain, deeper = _plain_keys(nested)
            renamed += deeper
            if not isinstance(key, str):
                renamed += 1
                out[str(key)] = plain
            else:
                out[key] = plain
        return out, renamed
    if isinstance(value, list):
        items = [_plain_keys(element) for element in value]
        return [item for item, _ in items], sum(count for _, count in items)
    return value, 0


def _one_line(error: Exception) -> str:
    """The loader's message as one line, because a parse problem is read in a table."""
    return " ".join(str(error).split())


__all__ = ["CONFIGURATIONS", "DOCUMENTS", "RENAMED_KEYS", "YamlGenericParser"]
