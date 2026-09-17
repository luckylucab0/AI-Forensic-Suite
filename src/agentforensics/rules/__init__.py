"""The declarative rule engine and the rule packs.

A rule is a YAML file: a tree of conditions over named event fields, plus its own positive
and negative tests, which pytest runs. There is no code in a rule file and no expression to
evaluate, which is what lets a detection pack be reviewed and argued about by an analyst
who will never open the engine.

Findings go into the case database next to the events they rest on, and every scan is
recorded whether or not anything fired. Without that record a case with no findings and a
case nobody scanned look the same, and those are opposite conclusions.
"""

from __future__ import annotations

from agentforensics.rules.conditions import OPERATORS, ConditionError
from agentforensics.rules.engine import Finding, ScanReport, events, scan
from agentforensics.rules.model import (
    PACKS,
    SEVERITIES,
    SEVERITY_ORDER,
    Aggregate,
    Rule,
    RuleError,
    RuleTest,
    Severity,
    load,
    load_file,
)
from agentforensics.rules.select import EventView, SelectorError

__all__ = [
    "OPERATORS",
    "PACKS",
    "SEVERITIES",
    "SEVERITY_ORDER",
    "Aggregate",
    "ConditionError",
    "EventView",
    "Finding",
    "Rule",
    "RuleError",
    "RuleTest",
    "ScanReport",
    "SelectorError",
    "Severity",
    "events",
    "load",
    "load_file",
    "scan",
]
