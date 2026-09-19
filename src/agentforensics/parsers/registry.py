"""Read the registry keys a collection carried, which is where a managed policy can live.

Six catalogue entries are registry keys rather than files, and two of them are the managed
policy that says what an agent was allowed to do. On Windows that policy can exist in the
registry alone, with no file anywhere, so a case that stayed quiet about it would read as a
host where no policy was in force rather than as one where nobody looked. Neither collector
could reach a key until now and no generated rule covers one either, which four separate
documents in this repository used to deny.

**What a collection carries.** The Windows collector reads a key and writes it as one JSON
document into the bundle, at a path under `files/registry/`, with the key itself as the
entry's original path. The shape is in docs/BUNDLE_FORMAT.md and it is deliberately small:
the key, the time the registry last wrote it, its values with their types, and the names of
its subkeys. This module is the other half of that contract.

**One event per value, and one for a key that has none.** A key with nothing in it is a
different answer from a key that is not there, and the collection distinguishes them
already: a key that does not exist is a manifest entry with no document behind it. So an
empty key gets an event saying it existed and held nothing, which for a policy key is the
statement that the policy was not set rather than that nobody looked.

**The time belongs to the key, not to the value.** The registry records a last-write time
per key and nothing per value, so every value out of one key carries the same timestamp and
every event says which it is. Attributing a key's time to one of its values would date a
setting that may have been written years earlier.

**One product stores a whole settings document inside one value.** Its own documentation
says to read the string value named Settings, which holds the managed settings as JSON. It
is parsed here, so the rules about a permission, an endpoint or a hook see a managed policy
the same way they see a settings file. A value that does not parse stays the string it is.

**The hive is evidence.** The same policy can sit under the machine hive, which needs
administrative rights, or under the user's own, which does not. A policy present only in
the user's hive is a policy a non-administrator could have put there, and telling the two
apart is the reason the hive is a field rather than part of the path.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

from agentforensics.model import Event, unparsed
from agentforensics.parsers.base import ParseContext, normalise_ts

# The catalogue entries a collection is allowed to carry as registry documents. Four, not
# six: the two left out are the platform's own execution evidence and an installer's
# persistence keys, which every general purpose registry tool reads better than this one
# would and which are not about an agent's behaviour. scripts/build_collectors.py holds the
# same four and says the same thing, and a test binds the two lists together.
SOURCES = frozenset(
    {
        "claude_code.managed_settings_registry",
        "claude_desktop.managed_policy_windows",
        "ollama.env_overrides_registry",
        "windsurf.enterprise_policy",
    }
)

# The value one product keeps its whole managed settings document in, as a string of JSON.
# Source: https://code.claude.com/docs/en/settings
_DOCUMENT_VALUES = {"Settings"}

# What the hive prefix means for who could have written the key. Both spellings, because
# the catalogue uses both and a collection records the key as the catalogue spells it.
_HIVES = {
    "HKLM": "machine",
    "HKEY_LOCAL_MACHINE": "machine",
    "HKCU": "user",
    "HKEY_CURRENT_USER": "user",
    "HKU": "user",
    "HKEY_USERS": "user",
    "HKCR": "classes",
    "HKEY_CLASSES_ROOT": "classes",
    "HKCC": "config",
    "HKEY_CURRENT_CONFIG": "config",
}

KEY_TIME = (
    "the registry records a last-write time for a key and nothing for a value, so this "
    "time is the key's and is the same on every value out of it. It dates the last change "
    "to anything in the key, which may be a different value from this one"
)

EMPTY_KEY = (
    "this key exists and holds no values. That is a different answer from a key that is "
    "not there, which the collection records as an entry with nothing behind it: for a "
    "policy key it means the policy was not set rather than that nobody looked"
)

NOT_A_DOCUMENT = (
    "this file is under a registry path in the bundle and is not a registry document "
    "the collector writes: {reason}"
)

UNPARSED_VALUE = (
    "this value is named as the one holding a settings document and its content is not "
    "JSON, so it is carried as the string it is: {reason}"
)


class RegistryParser:
    """The registry documents a Windows collection carried, value by value."""

    name = "registry"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in SOURCES

    def parse(self, context: ParseContext) -> Iterator[Event]:
        try:
            document = json.loads(context.local_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            yield unparsed(
                context.provenance("file"),
                context.agent,
                {"file": context.local_path.name},
                NOT_A_DOCUMENT.format(reason=error),
                user=context.user,
                host=context.host,
            )
            return
        if not isinstance(document, dict) or "key" not in document:
            yield unparsed(
                context.provenance("file"),
                context.agent,
                document,
                NOT_A_DOCUMENT.format(reason="it has no key field"),
                user=context.user,
                host=context.host,
            )
            return

        key = str(document.get("key") or context.original_path)
        when, precision, timing = _written(document.get("last_write_utc"))
        hive = _hive(key)
        subkeys = [str(name) for name in document.get("subkeys") or []]
        values = document.get("values") or []

        if not values:
            yield self._event(
                context,
                "key",
                {"key": key, "hive": hive, "subkeys": subkeys},
                text=key,
                when=when,
                precision=precision,
                note=" ".join(part for part in (EMPTY_KEY, timing) if part),
            )
            return

        for index, value in enumerate(values):
            if not isinstance(value, dict):
                yield unparsed(
                    context.provenance(f"value:{index}"),
                    context.agent,
                    value,
                    "an entry in this key's value list is not an object",
                    user=context.user,
                    host=context.host,
                )
                continue
            yield self._value(context, key, hive, subkeys, value, index, when, precision, timing)

    def _value(
        self,
        context: ParseContext,
        key: str,
        hive: str | None,
        subkeys: list[str],
        value: dict[str, Any],
        index: int,
        when: str | None,
        precision: str,
        timing: str | None,
    ) -> Event:
        name = str(value.get("name", ""))
        record: dict[str, Any] = {
            "key": key,
            "hive": hive,
            # The registry's own name for the unnamed value, so a case does not show an
            # empty string where a person expects a name.
            "value_name": name or "(default)",
            "type": value.get("type"),
            "subkeys": subkeys,
        }
        notes = [KEY_TIME]
        data = value.get("data")
        if "data_base64" in value:
            # Bytes the registry holds and nothing here reads. Carried as the collector
            # encoded them rather than decoded into a page of noise.
            record["data_base64"] = value["data_base64"]
        else:
            record["data"] = data

        if name in _DOCUMENT_VALUES and isinstance(data, str):
            parsed, problem = _document(data)
            if parsed is None:
                notes.append(UNPARSED_VALUE.format(reason=problem))
            else:
                # The whole managed settings document, so the rules about a permission, an
                # endpoint or a hook search it the way they search a settings file.
                record["document"] = parsed
        return self._event(
            context,
            f"value:{name or '(default)'}",
            record,
            text=_text(name, data, value.get("data_base64")),
            when=when,
            precision=precision,
            note=" ".join(part for part in (*notes, timing) if part),
            key=f"{key}\\{name}" if name else key,
        )

    def _event(
        self,
        context: ParseContext,
        locator: str,
        record: dict[str, Any],
        *,
        text: str | None,
        when: str | None,
        precision: str,
        note: str | None,
        key: str | None = None,
    ) -> Event:
        payload: dict[str, Any] = {"text": text}
        if key:
            payload["key"] = key
        return Event(
            kind="config.snapshot",
            provenance=context.provenance(locator),
            agent=context.agent,
            # The registry is written by an administrator or an installer, not by the
            # agent and not in a conversation.
            actor="system",
            user=context.user,
            host=context.host,
            raw=record,
            ts_utc=when,
            ts_precision=precision,  # type: ignore[arg-type]
            ts_source="the registry key's last-write time" if when else None,
            payload=payload,
            parse_problem=note or None,
        )


def _hive(key: str) -> str | None:
    """Who could have written this key, from the hive its path starts with."""
    head = key.replace("/", "\\").split("\\", 1)[0].upper()
    return _HIVES.get(head)


def _written(value: Any) -> tuple[str | None, str, str | None]:
    """The key's last-write time, normalised the way every other timestamp here is."""
    if not isinstance(value, str) or not value:
        return None, "absent", None
    when, precision, note = normalise_ts(value)
    return when, precision, note


def _document(data: str) -> tuple[Any, str | None]:
    try:
        return json.loads(data), None
    except ValueError as error:
        return None, str(error)


def _text(name: str, data: Any, encoded: Any) -> str:
    """The value as one line a person and a rule can both read."""
    shown = name or "(default)"
    if encoded is not None:
        return f"{shown} = <{len(str(encoded))} characters of base64>"
    if isinstance(data, list):
        return f"{shown} = " + "\n".join(str(item) for item in data)
    return f"{shown} = {data}"


__all__ = [
    "EMPTY_KEY",
    "KEY_TIME",
    "NOT_A_DOCUMENT",
    "SOURCES",
    "UNPARSED_VALUE",
    "RegistryParser",
]
