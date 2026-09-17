"""Timeline construction and export.

The view an analyst reads first, which is why this module spends most of its care on what a
timeline must not imply: that an event with no timestamp did not happen, that two events in
the same second are ordered, or that the sequence is of what happened rather than of what
was collected.
"""

from __future__ import annotations

from agentforensics.timeline.build import (
    COLUMNS,
    FORMATS,
    Filters,
    header_notes,
    record,
    rows,
    summarise,
    write,
)

__all__ = [
    "COLUMNS",
    "FORMATS",
    "Filters",
    "header_notes",
    "record",
    "rows",
    "summarise",
    "write",
]
