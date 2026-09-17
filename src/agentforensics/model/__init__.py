"""The unified event model and the SQLite case database.

Two halves that only make sense together. `event` defines the one shape every parser emits,
which is what turns twelve incompatible transcript formats into a single device-wide
timeline. `case` and `schema` define where those events land, keyed so that re-ingesting
the same evidence is a no-op rather than a duplication.

The property both halves exist to protect: a record that could not be parsed is still an
event, still on the timeline, still counted. A forensic tool that quietly shows nothing
makes an analyst conclude nothing was there.
"""

from __future__ import annotations

from agentforensics.model.case import BundleRecord, Case, CaseError
from agentforensics.model.event import (
    EVENT_KINDS,
    Actor,
    Event,
    Provenance,
    TsPrecision,
    unparsed,
)
from agentforensics.model.schema import SCHEMA, SCHEMA_VERSION, apply_schema

__all__ = [
    "EVENT_KINDS",
    "SCHEMA",
    "SCHEMA_VERSION",
    "Actor",
    "BundleRecord",
    "Case",
    "CaseError",
    "Event",
    "Provenance",
    "TsPrecision",
    "apply_schema",
    "unparsed",
]
