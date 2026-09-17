"""The vendor-neutral log format shared by every producer and every consumer.

A Velociraptor query that normalizes on the endpoint, this suite's own analyzer reading a
bundle, and the viewer in a browser all speak the format defined here, so a new agent is
added in one place and every consumer gains it.
"""

from __future__ import annotations

from agentforensics.unified.format import (
    FORMAT_NAME,
    FORMAT_VERSION,
    PRODUCER,
    SCHEMA_PATH,
    UnifiedFormatError,
    from_record,
    read,
    schema,
    to_line,
    to_record,
    validator,
    write,
)
from agentforensics.unified.normalize import NormalizeReport, normalize, write_log

__all__ = [
    "FORMAT_NAME",
    "FORMAT_VERSION",
    "PRODUCER",
    "SCHEMA_PATH",
    "NormalizeReport",
    "UnifiedFormatError",
    "from_record",
    "normalize",
    "read",
    "schema",
    "to_line",
    "to_record",
    "validator",
    "write",
    "write_log",
]
