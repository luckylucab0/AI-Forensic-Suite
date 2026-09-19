"""What a rule is, and how one is loaded.

One YAML file per rule, grouped into packs by directory. A rule carries its own tests, and
that is the part worth explaining: a detection rule without a negative test is a rule
nobody can trust, because the failure that matters is not a rule that misses, it is a rule
that fires on everything and trains an analyst to ignore the pack. So the tests are part of
the rule file rather than a separate suite, `pytest` runs every one of them, and a rule
whose tests do not pass is a rule that does not ship.

Loading is strict and total. Every rule in the directory is validated against the schema,
every selector is checked against what an event can answer, every regex is compiled, and
every inline test is required. A rule that cannot load is an error naming the file, never a
rule that is quietly skipped: a detection pack that is one rule short and does not say so
is the same failure mode as a collection rule that searches the wrong path.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, cast

import fastjsonschema
import yaml

from agentforensics.catalog import resolve_text
from agentforensics.model import UNINTERPRETED_MARK
from agentforensics.rules.conditions import Condition, ConditionError, parse
from agentforensics.rules.select import EventView

SEVERITIES = ("info", "low", "medium", "high", "critical")
Severity = Literal["info", "low", "medium", "high", "critical"]

# How much a severity weighs when a scan sorts its findings. Numbers rather than the list
# order so that a future severity can be inserted without renumbering.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# The packs this suite ships. Named here so a rule cannot land in a pack nobody documents,
# and a directory nobody expected is an error rather than a silent addition.
#
# There is deliberately no org_scope pack. See ADR 0010: the strings such rules need are
# exactly the strings a public repository must not carry, and "did our data appear here" is
# a data loss prevention question rather than a question about what an agent did.
PACKS = (
    "anti_forensics",
    # About the case rather than about the endpoint: whether what was collected can answer
    # the question it is being asked. Every other pack says something happened; this one
    # says a part of the collection may be looking in the wrong place.
    "collection_integrity",
    "dangerous_commands",
    "data_volume",
    "exfil_indicators",
    "permission_bypass",
    "prompt_injection",
    "secrets",
    "sensitive_paths",
    "supply_chain",
    "third_party_endpoints",
)

# AFX, not the brief's four-letter acronym: that acronym belongs to a forensic science
# body that has existed since the 1940s, and ADR 0002 keeps it out of this repository
# entirely.
ID_PATTERN = re.compile(r"^AFX-[A-Z][A-Z0-9_]*-\d{3}$")

SCHEMA_PATH = Path(__file__).resolve().parent / "rule.v1.schema.json"

# Where the rules themselves live, relative to the repository root. A caller can point
# somewhere else; this is the default so the CLI needs no argument in the common case.
DEFAULT_DIRECTORY = Path("rules")


class RuleError(ValueError):
    """A rule file that is missing, unreadable, or not a valid rule."""


@dataclass(frozen=True, slots=True)
class RuleTest:
    """One positive or negative sample, from the rule's own file.

    `event` is a partial event: whatever the test does not state is filled in with a
    neutral default, so a test says only what it is about. A test that had to spell out
    every field would be a test nobody would write, and the rule would ship untested.
    """

    name: str
    should_match: bool
    event: dict[str, Any]
    # True on a negative sample the rule deliberately does not look at, where that
    # exclusion is what is being demonstrated rather than an oversight.
    out_of_scope: bool = False


@dataclass(frozen=True, slots=True)
class Aggregate:
    """A rule that fires on a count rather than on one event.

    "Twenty files read from one session in a minute" is not a property any single event has.
    Such a rule groups the events it matched and fires once per group, so a finding is about
    the burst rather than about its twentieth member.
    """

    group_by: tuple[str, ...]
    min_count: int
    window_minutes: int | None = None


@dataclass(frozen=True, slots=True)
class Rule:
    """One detection rule, compiled and ready to run."""

    id: str
    pack: str
    title: str
    severity: Severity
    description: str
    rationale: str
    condition: Condition
    path: Path
    sha256: str
    agents: tuple[str, ...] = ("any",)
    kinds: tuple[str, ...] = ("any",)
    tags: tuple[str, ...] = ()
    false_positives: tuple[str, ...] = ()
    # Which of this rule's prose fields fell back to English because the requested
    # language was missing. Carried so the generated reference can mark them rather than
    # passing English off as a translation, which is the difference between a documented
    # gap and a quiet lie.
    untranslated: frozenset[str] = frozenset()
    references: tuple[str, ...] = ()
    aggregate: Aggregate | None = None
    tests: tuple[RuleTest, ...] = ()
    # Whether a finding may quote the value that matched. Off for the secrets pack: the
    # matched value there is the credential, and a finding is exported to CSV and pasted
    # into reports, so copying it out of the event and into a second place would spread
    # the credential rather than report it. The event itself still holds the original,
    # which is where an analyst looks.
    redact: bool = False
    # Fields the rule is about, for the generated reference. Derived, not declared.
    fields: tuple[str, ...] = field(default_factory=tuple)

    def applies_to(self, event: EventView) -> bool:
        """Whether this rule looks at this event at all.

        Checked before the condition because it is cheap and because it is what keeps a
        pack of eighty rules from running eighty regexes over every event in a large case.

        A record out of a store or a log nobody has mapped is the exception, and it is the
        one this project cannot afford to get wrong. Such a record is filed under
        unparsed.record because no kind could be established for it, which is not the same
        as establishing that it is not a command: for several agents the only copy of a
        conversation on the endpoint is in a format nothing has a schema for, and a pack
        that skipped those records would report nothing about exactly the evidence an
        investigation has left. So a rule restricted by kind still sees them, and the
        finding says the kind is unknown rather than implying the record is what the rule
        is usually about. See ADR 0030.
        """
        if "any" not in self.kinds and event.kind not in self.kinds and not unmapped(event):
            return False
        return "any" in self.agents or event.agent in self.agents

    def matches(self, event: EventView) -> bool:
        return self.applies_to(event) and self.condition.matches(event)


def unmapped(event: EventView) -> bool:
    """Whether this record was read fine out of a format nobody has a mapping for.

    The mark is the one the readers and the case counts already use, so there is one
    definition of the difference between a record nothing could read and a record nobody
    has read the format of. The first is a defect in the evidence and no rule should treat
    it as content; the second is intact evidence whose kind is simply unknown.
    """
    return event.kind == "unparsed.record" and UNINTERPRETED_MARK in (event.parse_problem or "")


@lru_cache(maxsize=1)
def _validator() -> Any:
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except OSError as exc:  # pragma: no cover - only when the install is broken
        raise RuleError(f"cannot read the rule schema at {SCHEMA_PATH}: {exc}") from exc
    return fastjsonschema.compile(schema)


def load_file(path: Path, pack: str | None = None, lang: str = "en") -> Rule:
    """Load and compile one rule file.

    `lang` picks which translation of the prose fields to use. The engine always loads
    English, because a finding's text goes into a case database that has one language;
    the documentation generator loads each language in turn.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuleError(f"cannot read {path}: {exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RuleError(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise RuleError(f"{path} does not hold a rule mapping")

    try:
        _validator()(data)
    except fastjsonschema.JsonSchemaException as exc:
        raise RuleError(f"{path} does not satisfy the rule schema: {exc.message}") from exc

    rule_id = str(data["id"])
    if not ID_PATTERN.match(rule_id):
        raise RuleError(
            f"{path}: {rule_id!r} is not a rule id. The shape is AFX-<PACK>-<nnn>, for "
            "example AFX-SECRETS-001."
        )
    declared = str(data["pack"])
    if declared not in PACKS:
        raise RuleError(
            f"{path}: pack {declared!r} is not one this suite ships. Packs are: " + ", ".join(PACKS)
        )
    if pack is not None and declared != pack:
        raise RuleError(
            f"{path}: the file sits in the {pack!r} pack and declares {declared!r}. The "
            "directory decides, so one of the two is a mistake."
        )
    # The id's middle segment names its pack, so a rule id read out of a report says which
    # pack to look in without anybody having to hold a mapping in their head.
    middle = rule_id.split("-")[1]
    if middle.lower() != declared.replace("_", ""):
        raise RuleError(
            f"{path}: the id says {middle} and the pack is {declared}. The id's middle "
            f"segment has to be {declared.replace('_', '').upper()}."
        )

    try:
        condition = parse(data["match"])
    except ConditionError as exc:
        raise RuleError(f"{path}: {exc}") from exc

    tests = tuple(
        RuleTest(
            name=str(item["name"]),
            should_match=bool(item["match"]),
            event=dict(item.get("event") or {}),
            out_of_scope=bool(item.get("out_of_scope", False)),
        )
        for item in data["tests"]
    )
    if not any(test.should_match for test in tests):
        raise RuleError(f"{path}: no test says this rule should ever match")
    contradictory = [test.name for test in tests if test.out_of_scope and test.should_match]
    if contradictory:
        raise RuleError(
            f"{path}: sample(s) {contradictory} are marked out_of_scope and expected to "
            "match. A rule cannot fire on an event it does not look at, so one of the two "
            "is wrong."
        )
    if not any(not test.should_match for test in tests):
        raise RuleError(
            f"{path}: no test says this rule should not match. A rule with only positive "
            "tests is a rule nobody can trust, because a rule that fires on everything "
            "passes them all."
        )

    untranslated = set()

    def prose(value: Any, field_name: str) -> str:
        text, translated = resolve_text(value, lang)
        if not translated:
            untranslated.add(field_name)
        return " ".join(text.split())

    applies = data.get("applies_to") or {}
    aggregate = None
    if "aggregate" in data:
        block = data["aggregate"]
        aggregate = Aggregate(
            group_by=tuple(block["group_by"]),
            min_count=int(block["min_count"]),
            window_minutes=(
                int(block["window_minutes"]) if block.get("window_minutes") is not None else None
            ),
        )

    return Rule(
        id=rule_id,
        pack=declared,
        title=str(data["title"]),
        severity=cast(Severity, str(data["severity"])),
        description=prose(data["description"], "description"),
        rationale=prose(data["rationale"], "rationale"),
        condition=condition,
        path=path,
        sha256=_digest(text),
        agents=tuple(applies.get("agents") or ("any",)),
        kinds=tuple(applies.get("kinds") or ("any",)),
        tags=tuple(data.get("tags") or ()),
        false_positives=tuple(
            prose(item, "false_positives") for item in (data.get("false_positives") or ())
        ),
        references=tuple(data.get("references") or ()),
        aggregate=aggregate,
        tests=tests,
        redact=bool(data.get("redact", False)),
        fields=_fields(data["match"]),
        untranslated=frozenset(untranslated),
    )


def load(
    directory: Path | None = None,
    packs: list[str] | None = None,
    lang: str = "en",
) -> list[Rule]:
    """Every rule under a directory, in a stable order.

    Sorted by id, so two scans of one case produce findings in the same order and a diff of
    two reports is readable. A directory that is not a known pack is an error rather than
    an ignored directory: a rule pack somebody added and nobody ran is worse than none.
    """
    root = DEFAULT_DIRECTORY if directory is None else directory
    if not root.is_dir():
        raise RuleError(f"no rule directory at {root}")

    wanted = set(packs) if packs else None
    if wanted:
        unknown = sorted(wanted - set(PACKS))
        if unknown:
            raise RuleError("unknown pack(s): " + ", ".join(unknown))

    rules: list[Rule] = []
    seen: dict[str, Path] = {}
    for child in sorted(root.iterdir()):
        if not child.is_dir() or child.name == "schema":
            continue
        if child.name not in PACKS:
            raise RuleError(
                f"{child} is not a known pack. Packs are: " + ", ".join(PACKS) + ". Add it "
                "to PACKS in the rules model, with a line in the generated reference "
                "saying what it is for."
            )
        if wanted is not None and child.name not in wanted:
            continue
        for path in sorted(child.glob("*.yaml")):
            rule = load_file(path, pack=child.name, lang=lang)
            if rule.id in seen:
                raise RuleError(
                    f"{path}: rule id {rule.id} is already used by {seen[rule.id]}. An id "
                    "is what a report cites, so two rules may not share one."
                )
            seen[rule.id] = path
            rules.append(rule)

    if not rules:
        raise RuleError(f"{root} holds no rules")
    rules.sort(key=lambda item: item.id)
    return rules


def _digest(text: str) -> str:
    """The rule file's hash, stored on every finding it produces.

    A finding has to say which version of which rule produced it. A rule edited after a
    scan would otherwise leave findings nobody can reproduce, and reproducing a finding is
    the whole of what makes it evidence rather than an opinion.
    """
    import hashlib

    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def _fields(node: Any) -> tuple[str, ...]:
    """Every field the condition tree addresses, for the generated reference."""
    found: list[str] = []

    def walk(item: Any) -> None:
        if not isinstance(item, dict):
            return
        for key in ("all", "any", "none"):
            if key in item:
                for part in item[key]:
                    walk(part)
                return
        if isinstance(item.get("field"), str):
            found.append(item["field"])

    walk(node)
    return tuple(dict.fromkeys(found))


__all__ = [
    "DEFAULT_DIRECTORY",
    "ID_PATTERN",
    "PACKS",
    "SCHEMA_PATH",
    "SEVERITIES",
    "SEVERITY_ORDER",
    "Aggregate",
    "Rule",
    "RuleError",
    "RuleTest",
    "Severity",
    "load",
    "load_file",
]
