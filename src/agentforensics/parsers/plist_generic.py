"""Read a macOS property list, which is where the administrator's rules are.

Three catalogue entries are property lists and nothing read any of them. Two are managed
preferences, which is how an organization pushes policy onto a Mac: the file is written by
device management, it sits outside the user's profile, and it overrides what the user's own
settings say. A case that could not read it could not answer whether a setting an analyst
found in a user's file was the setting that applied.

The reading is the one the other whole-document readers use, from `structured_generic`:
split by structure one level deep, never by meaning, and read out of a record only what it
literally names. What this module adds is the format and its one incompatibility with the
way a case stores a record.

**Both spellings are read.** The library reads the XML form and the binary form from the
same call, which matters because a managed preferences file is usually binary, and a reader
that only handled XML would report the policy file as unreadable on exactly the machines
that have one.

**A property list can hold raw data**, which the case's record format cannot. Such a value
is stored as base64 text and every record out of that document says so, because the
alternative is an ingest that fails on the file, and a policy file that fails to ingest is
a policy nobody sees.
"""

from __future__ import annotations

import base64
import plistlib
from collections.abc import Iterator
from typing import Any
from xml.parsers.expat import ExpatError

from agentforensics.model import Event, unparsed
from agentforensics.parsers.base import ParseContext
from agentforensics.parsers.structured_generic import documents

# Every property list in the catalogue. Written out rather than derived from the format
# field at runtime, for the reason the other readers' sets are written out.
# tests/unit/test_plist_generic.py asserts that this set is exactly the catalogue's plist
# artifacts, so adding one there fails CI until it is listed here.
DOCUMENTS = frozenset(
    {
        "chatgpt_desktop.macos_preferences",
        "claude_code.managed_settings_macos_profile",
        "claude_desktop.managed_policy_macos",
        "cursor.macos_preferences",
        "windsurf.macos_preferences",
    }
)

# All three are settings or policy, so all three produce configuration events. Kept as its
# own set anyway, so that a property list of something else added later has to be decided
# rather than inherited.
CONFIGURATIONS = frozenset(DOCUMENTS)

# Said on a record that held raw data, so nobody reads the rendering as the bytes.
ENCODED_DATA = (
    "this record held {count} raw data value(s), which a property list allows and the "
    "case's record format does not, so each is stored as base64 text"
)


class PlistGenericParser:
    """The reading of last resort for a property list."""

    name = "plist_generic"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in DOCUMENTS

    def parse(self, context: ParseContext) -> Iterator[Event]:
        try:
            with context.local_path.open("rb") as handle:
                document = plistlib.load(handle)
        except (OSError, plistlib.InvalidFileException, ValueError, ExpatError) as error:
            # A truncated write, a file that is not a property list, or one in a format
            # this library does not read. The reason is the event, because "we collected
            # this and could not read it" is something an analyst has to see, and for a
            # policy file it is the difference between no policy and an unread one.
            yield unparsed(
                context.provenance("$"),
                context.agent,
                None,
                f"the file could not be read as a property list: {' '.join(str(error).split())}",
                user=context.user,
                host=context.host,
            )
            return

        plain, encoded = _plain_data(document)
        yield from documents(
            context,
            plain,
            configuration=context.artifact_id in CONFIGURATIONS,
            note=ENCODED_DATA.format(count=encoded) if encoded else None,
        )


def _plain_data(value: Any) -> tuple[Any, int]:
    """The value with every raw data field as base64 text, and how many there were.

    Recursive, because one data value anywhere in the record is enough to make the record
    unstorable, not only at the top.
    """
    if isinstance(value, (bytes, bytearray)):
        return base64.b64encode(bytes(value)).decode("ascii"), 1
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        count = 0
        for key, nested in value.items():
            plain, deeper = _plain_data(nested)
            out[key] = plain
            count += deeper
        return out, count
    if isinstance(value, list):
        items = [_plain_data(element) for element in value]
        return [item for item, _ in items], sum(n for _, n in items)
    return value, 0


__all__ = ["CONFIGURATIONS", "DOCUMENTS", "ENCODED_DATA", "PlistGenericParser"]
