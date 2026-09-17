"""Building an event from the partial one a rule's own test states.

A rule file's test says only what the test is about:

    event:
      kind: command.exec
      payload: {commands: [{command: "rm -rf /"}]}

Everything else is filled in here with a value that is neutral rather than plausible. That
distinction matters: if a missing agent defaulted to `claude_code`, a rule scoped to one
agent would pass a test that says nothing about it, and the test would be measuring the
default rather than the rule. So the defaults are marked as what they are, and a rule that
cares about a field has to say so in its test.

Part of the package rather than the test suite because `afx scan --self-test` runs the same
code. A rule pack shipped to an operator should be checkable by that operator, with the
same runner that checked it here.
"""

from __future__ import annotations

from typing import Any

from agentforensics.rules.model import Rule, RuleTest
from agentforensics.rules.select import EventView

# The value a field takes when a test does not state it. Chosen so that it cannot be
# mistaken for real data in a failure message, and so that a rule scoped to a particular
# agent or kind fails a test that forgot to say which.
UNSTATED = "(unstated in the rule's test)"

DEFAULTS: dict[str, Any] = {
    "event_id": "test-event",
    "kind": UNSTATED,
    "agent": UNSTATED,
    "actor": "unknown",
    "ts_utc": None,
    "client": None,
    "host": None,
    "user": None,
    "session_id": None,
    "project_path": None,
    "git_branch": None,
    "parse_problem": None,
}

PROVENANCE_DEFAULTS: dict[str, Any] = {
    "bundle_uuid": "test-bundle",
    "original_path": "/test/path",
    "sha256": "",
    "artifact_id": None,
    "locator": "line:1",
}


class TestEventError(ValueError):
    """A rule test that states a field no event has."""


def view(partial: dict[str, Any]) -> EventView:
    """One event as a rule sees it, from a test's partial description.

    A key the event model does not have is an error rather than an ignored key. A test that
    set `command: "rm -rf /"` at the top level, meaning the payload, would otherwise pass
    silently while testing nothing, and a rule whose tests test nothing is worse than a
    rule with no tests, because it looks covered.
    """
    unknown = sorted(
        key
        for key in partial
        if key not in DEFAULTS and key not in ("payload", "raw", "provenance")
    )
    if unknown:
        raise TestEventError(
            f"a rule test states {unknown}, which an event does not have. An event has "
            + ", ".join(sorted(DEFAULTS))
            + ", plus payload, raw and provenance."
        )

    fields = {name: partial.get(name, value) for name, value in DEFAULTS.items()}
    payload = partial.get("payload") or {}
    if not isinstance(payload, dict):
        raise TestEventError("a rule test's payload has to be a mapping")
    provenance = {**PROVENANCE_DEFAULTS, **(partial.get("provenance") or {})}
    # The raw record defaults to the payload rather than to nothing, because a rule that
    # searches whole-record text should see what the test put in the payload. A test that
    # is about the difference between the two states both.
    raw = partial.get("raw", payload)
    return EventView(payload=payload, raw=raw, provenance=provenance, **fields)


def run(rule: Rule) -> list[str]:
    """Run one rule's own tests. Returns a line per failure, empty when they all pass."""
    problems: list[str] = []
    for test in rule.tests:
        try:
            event = view(test.event)
        except TestEventError as exc:
            problems.append(f"{rule.id}: test {test.name!r} is not usable: {exc}")
            continue
        got = rule.matches(event)
        if got != test.should_match:
            problems.append(_explain(rule, test, event, got))
    return problems


def _explain(rule: Rule, test: RuleTest, event: EventView, got: bool) -> str:
    """Why a rule test failed, in enough detail to fix it without a debugger.

    A bare "expected True, got False" sends the reader to the engine. Naming the condition
    and whether the rule even looked at the event separates the two mistakes that produce
    this: a condition that is wrong, and a scope that excludes the sample.
    """
    wanted = "should match" if test.should_match else "should not match"
    lines = [f"{rule.id}: test {test.name!r} {wanted}, and it {'does' if got else 'does not'}"]
    if not rule.applies_to(event):
        lines.append(
            f"  the rule does not look at this event at all: it applies to kinds "
            f"{list(rule.kinds)} and agents {list(rule.agents)}, and the test's event is "
            f"kind {event.kind!r} from agent {event.agent!r}"
        )
        if event.kind == UNSTATED or event.agent == UNSTATED:
            lines.append(
                "  the test did not state them, and they are not defaulted to anything "
                "plausible on purpose, so a scoped rule cannot pass a test that is silent "
                "about its scope"
            )
    lines.append(f"  condition: {rule.condition.describe()}")
    return "\n".join(lines)


__all__ = ["DEFAULTS", "PROVENANCE_DEFAULTS", "UNSTATED", "TestEventError", "run", "view"]
