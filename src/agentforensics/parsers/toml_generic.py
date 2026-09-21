"""Read a whole TOML document the suite has no verified shape for, without inventing one.

The same reading as the JSON and YAML ones, over the format one agent family writes its
configuration, its MCP servers and its permissions in. The reading itself is in
`structured_generic`; what is here is which artifacts are TOML, which of them the catalogue
calls a configuration, and the two things about TOML that the others do not have.

**The root is always a table**, so there is one document per file and it is always at `$`,
and the split one level deep reaches exactly the array-of-tables sections, which is where
this format puts a list of servers or a list of rules.

**A value can be a date, a time or a local datetime**, which the loader returns as real
date and time objects. They are kept as they come: the case renders a value no JSON encoder
knows as its text when it stores the record, and that rendering is stable, which is what a
case's determinism needs.

One artifact the catalogue calls TOML is deliberately not read here, and the set below says
which and why.
"""

from __future__ import annotations

import tomllib
from collections.abc import Iterator

from agentforensics.model import Event, unparsed
from agentforensics.parsers.base import ParseContext
from agentforensics.parsers.structured_generic import documents

# The install-evidence directory of a Python tool installer, which the catalogue calls TOML
# because the receipt inside it is one. It is a directory of whatever a tool shipped:
# binaries, caches and a wheel's own metadata, none of which is TOML, and reading a cache
# tree as documents would file thousands of events that say only "this was not TOML" and
# bury the evidence beside them. Every one of those files is still in the case with its
# path, its hash and its times, which is what install evidence is read for.
# One editor's custom slash commands are TOML documents and are read as instructions rather
# than as documents, because what is in them is a prompt the agent runs when somebody types
# a name. Reading them here as well would file the same file twice, once under the question
# it answers and once under a question it does not.
NOT_READ = frozenset({"crosscutting.uv_tool_dir", "gemini_cli.commands"})

# Every TOML artifact in the catalogue except the one above, written out rather than derived
# from the format field at runtime, for the reason `json_generic.DOCUMENTS` is written out.
# tests/unit/test_toml_generic.py asserts that this set is exactly the catalogue's TOML
# artifacts minus NOT_READ, so adding one there fails CI until it is listed here.
DOCUMENTS = frozenset(
    {
        "codex.config",
        "codex.managed_config_legacy",
        "codex.mcp_and_notify",
        "codex.requirements_and_permissions",
        "codex.system_config",
        "gemini_cli.policies",
        "warp.cli_settings",
    }
)

# The ones the catalogue files as configuration, permissions or MCP configuration, which is
# what decides the event kind.
CONFIGURATIONS = frozenset(
    {
        "codex.config",
        "codex.managed_config_legacy",
        "codex.mcp_and_notify",
        "codex.requirements_and_permissions",
        "codex.system_config",
        "gemini_cli.policies",
        "warp.cli_settings",
    }
)


class TomlGenericParser:
    """The reading of last resort for a whole TOML document."""

    name = "toml_generic"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in DOCUMENTS

    def parse(self, context: ParseContext) -> Iterator[Event]:
        try:
            with context.local_path.open("rb") as handle:
                document = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
            # A truncated write, another encoding, or a file that is not TOML at all. The
            # reason is the event, because "we collected this and could not read it" is
            # something an analyst has to see rather than a blank.
            yield unparsed(
                context.provenance("$"),
                context.agent,
                None,
                f"the file could not be read as TOML: {' '.join(str(error).split())}",
                user=context.user,
                host=context.host,
            )
            return
        yield from documents(
            context,
            document,
            configuration=context.artifact_id in CONFIGURATIONS,
        )


__all__ = ["CONFIGURATIONS", "DOCUMENTS", "NOT_READ", "TomlGenericParser"]
