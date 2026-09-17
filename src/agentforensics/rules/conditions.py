"""The condition language a rule file is written in.

Declarative on purpose, and narrow on purpose. A rule is data: a tree of `all`, `any` and
`none` over leaves that each name one field and one operator. There is no expression
evaluator, no embedded Python, no callable in a rule file. That is not a limitation to work
around, it is the property that lets a pack of detection rules be reviewed, diffed and
argued about by an analyst who will never open the engine, and that keeps a rule file from
becoming a way to run code inside a forensic tool.

Everything is compiled when the rule is loaded, not when it runs. A misspelled field, an
unknown operator, a regex that does not compile: all of them are a rule that fails to load.
The alternative is a rule that raises halfway through a scan, or worse, one that quietly
matches nothing, and a rule that matches nothing is indistinguishable from a clean case.

`none` rather than a general `not` because the useful shape is always "and none of these
apply": a dangerous command that is not one of the known-safe invocations. A bare negation
over a field that resolves to a list has two defensible meanings, and a detection language
should not have an operator whose meaning an analyst has to look up.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol

from agentforensics.rules.select import (
    EventView,
    SelectorError,
    as_number,
    as_text,
    check,
    compile_glob,
    resolve,
)


class ConditionError(ValueError):
    """A condition a rule file may not express. Raised at load time."""


class Condition(Protocol):
    """Anything a rule can ask of one event."""

    def matches(self, event: EventView) -> bool: ...

    def describe(self) -> str:
        """One line for the generated rule reference and for a finding's summary."""
        ...


@dataclass(frozen=True, slots=True)
class All:
    parts: tuple[Condition, ...]

    def matches(self, event: EventView) -> bool:
        return all(part.matches(event) for part in self.parts)

    def describe(self) -> str:
        return " and ".join(part.describe() for part in self.parts)


@dataclass(frozen=True, slots=True)
class Any_:
    parts: tuple[Condition, ...]

    def matches(self, event: EventView) -> bool:
        return any(part.matches(event) for part in self.parts)

    def describe(self) -> str:
        return "(" + " or ".join(part.describe() for part in self.parts) + ")"


@dataclass(frozen=True, slots=True)
class None_:
    parts: tuple[Condition, ...]

    def matches(self, event: EventView) -> bool:
        return not any(part.matches(event) for part in self.parts)

    def describe(self) -> str:
        return "none of (" + " or ".join(part.describe() for part in self.parts) + ")"


@dataclass(frozen=True, slots=True)
class Leaf:
    """One field, one operator.

    `hits` returns the values that satisfied it, not just whether any did, because a
    finding has to be able to say what matched. "This event runs a dangerous command" is
    not a usable finding; "this event runs `rm -rf /`" is.
    """

    selector: str
    operator: str
    rendered: str
    test: Any

    def hits(self, event: EventView) -> list[Any]:
        values = resolve(event, self.selector)
        if self.operator == "exists":
            return values if bool(values) == self.test else []
        if self.operator == "count_gte":
            # A property of the event rather than of any one value, so every value is a hit
            # or none is. The values are what a finding quotes, which is why they come back.
            return values if len(values) >= self.test else []
        return [value for value in values if self.test(value)]

    def matches(self, event: EventView) -> bool:
        if self.operator == "exists":
            return bool(resolve(event, self.selector)) is bool(self.test)
        if self.operator == "count_gte":
            return len(resolve(event, self.selector)) >= int(self.test)
        return bool(self.hits(event))

    def describe(self) -> str:
        return f"{self.selector} {self.rendered}"


# Which operators take a list of alternatives. Spelled as a separate name rather than a
# suffix check so that adding an operator cannot accidentally acquire list semantics.
_LIST_SUFFIX = "_any"

_STRING_OPERATORS = ("regex", "contains", "equals", "glob", "startswith", "endswith")
_NUMBER_OPERATORS = ("gt", "gte", "lt", "lte")
_LENGTH_OPERATORS = ("length_gt", "length_gte", "length_lt")
_OTHER_OPERATORS = ("exists", "count_gte")

OPERATORS = (
    tuple(_STRING_OPERATORS)
    + tuple(name + _LIST_SUFFIX for name in _STRING_OPERATORS)
    + tuple(_NUMBER_OPERATORS)
    + tuple(_LENGTH_OPERATORS)
    + tuple(_OTHER_OPERATORS)
)

# Modifiers, which are not operators and may sit alongside one.
MODIFIERS = ("ignore_case",)


def parse(node: Any, path: str = "match") -> Condition:
    """Compile one condition node. Raises on anything a rule may not say."""
    if not isinstance(node, dict):
        raise ConditionError(
            f"{path}: a condition has to be a mapping, not a {type(node).__name__}"
        )

    groups = [key for key in ("all", "any", "none") if key in node]
    if groups:
        if len(groups) > 1 or len(node) > 1:
            raise ConditionError(
                f"{path}: a group condition holds exactly one of all, any or none, and "
                f"nothing else. Found: {sorted(node)}"
            )
        key = groups[0]
        parts = node[key]
        if not isinstance(parts, list) or not parts:
            raise ConditionError(f"{path}.{key}: has to be a non-empty list of conditions")
        compiled = tuple(parse(part, f"{path}.{key}[{index}]") for index, part in enumerate(parts))
        if key == "all":
            return All(compiled)
        if key == "any":
            return Any_(compiled)
        return None_(compiled)

    return _leaf(node, path)


def _leaf(node: dict[str, Any], path: str) -> Leaf:
    selector = node.get("field")
    if not isinstance(selector, str) or not selector:
        raise ConditionError(f"{path}: a leaf condition needs a field")
    try:
        check(selector)
    except SelectorError as exc:
        raise ConditionError(f"{path}: {exc}") from exc

    found = [key for key in node if key in OPERATORS]
    unknown = [
        key for key in node if key not in OPERATORS and key not in MODIFIERS and key != "field"
    ]
    if unknown:
        raise ConditionError(
            f"{path}: unknown key(s) {sorted(unknown)}. Operators are: "
            + ", ".join(sorted(OPERATORS))
        )
    if len(found) != 1:
        raise ConditionError(
            f"{path}: a leaf condition needs exactly one operator, found {sorted(found)}"
        )

    operator = found[0]
    value = node[operator]
    # Case-insensitive by default for the operators where an analyst writing a rule means
    # the word rather than its casing, and never for a regex, where the pattern itself says
    # so with (?i). A silent (?i) on a hand-written pattern would change what it matches.
    default_case = operator.startswith(("contains", "equals", "startswith", "endswith"))
    ignore_case = bool(node.get("ignore_case", default_case))
    return _build(selector, operator, value, ignore_case, path)


def _build(selector: str, operator: str, value: Any, ignore_case: bool, path: str) -> Leaf:
    base = operator.removesuffix(_LIST_SUFFIX)
    is_list = operator.endswith(_LIST_SUFFIX)

    if operator == "exists":
        if not isinstance(value, bool):
            raise ConditionError(f"{path}.exists: has to be true or false")
        return Leaf(selector, "exists", "is present" if value else "is absent", value)

    if operator == "count_gte":
        number = as_number(value)
        if number is None:
            raise ConditionError(f"{path}.count_gte: has to be a number")
        # A field-level count: how many values the selector resolved to. Used for "this
        # event touched more than twenty files", which is a property of the event rather
        # than of any one value, and is therefore not a per-value test.
        return Leaf(selector, "count_gte", f"has at least {int(number)} value(s)", int(number))

    if base in _NUMBER_OPERATORS:
        number = as_number(value)
        if number is None:
            raise ConditionError(f"{path}.{operator}: has to be a number")

        def numeric(got: Any, _limit: float = number, _op: str = base) -> bool:
            # A value that is not a number at all fails the comparison rather than raising.
            # A record can carry an exit code as text or as nothing, and a rule about a
            # threshold should not have to know which producer wrote it.
            size = as_number(got)
            if size is None:
                return False
            if _op == "gt":
                return size > _limit
            if _op == "gte":
                return size >= _limit
            if _op == "lt":
                return size < _limit
            return size <= _limit

        symbol = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[base]
        return Leaf(selector, operator, f"{symbol} {value}", numeric)

    if base in _LENGTH_OPERATORS or operator in _LENGTH_OPERATORS:
        number = as_number(value)
        if number is None:
            raise ConditionError(f"{path}.{operator}: has to be a number")
        limit = int(number)

        def compare(size: int, _limit: int = limit, _op: str = operator) -> bool:
            if _op == "length_gt":
                return size > _limit
            if _op == "length_gte":
                return size >= _limit
            return size < _limit

        symbol = {"length_gt": ">", "length_gte": ">=", "length_lt": "<"}[operator]
        return Leaf(
            selector, operator, f"is {symbol} {limit} long", lambda got: compare(_length(got))
        )

    if base not in _STRING_OPERATORS:  # pragma: no cover - OPERATORS covers the rest
        raise ConditionError(f"{path}: unknown operator {operator!r}")

    wanted = value if is_list else [value]
    if not isinstance(wanted, list) or not wanted:
        raise ConditionError(f"{path}.{operator}: has to be a non-empty list")
    if any(not isinstance(item, str) for item in wanted):
        raise ConditionError(f"{path}.{operator}: every alternative has to be a string")

    if base == "regex":
        flags = re.IGNORECASE if ignore_case else 0
        try:
            patterns = [re.compile(item, flags | re.DOTALL) for item in wanted]
        except re.error as exc:
            raise ConditionError(f"{path}.{operator}: {exc}") from exc
        rendered = "matches " + " or ".join(f"/{item}/" for item in wanted)
        return Leaf(
            selector,
            operator,
            rendered,
            lambda got: any(pattern.search(as_text(got)) for pattern in patterns),
        )

    if base == "glob":
        globs = [compile_glob(item) for item in wanted]
        rendered = "matches path " + " or ".join(wanted)
        return Leaf(
            selector,
            operator,
            rendered,
            lambda got: any(pattern.match(as_text(got)) for pattern in globs),
        )

    needles = [item.casefold() for item in wanted] if ignore_case else list(wanted)

    def fold(got: Any) -> str:
        text = as_text(got)
        return text.casefold() if ignore_case else text

    if base == "contains":
        rendered = "contains " + " or ".join(repr(item) for item in wanted)
        return Leaf(selector, operator, rendered, lambda got: any(n in fold(got) for n in needles))
    if base == "equals":
        rendered = "is " + " or ".join(repr(item) for item in wanted)
        return Leaf(selector, operator, rendered, lambda got: fold(got) in needles)
    if base == "startswith":
        rendered = "starts with " + " or ".join(repr(item) for item in wanted)
        return Leaf(selector, operator, rendered, lambda got: fold(got).startswith(tuple(needles)))
    rendered = "ends with " + " or ".join(repr(item) for item in wanted)
    return Leaf(selector, operator, rendered, lambda got: fold(got).endswith(tuple(needles)))


def _length(value: Any) -> int:
    """How long a value is, for a threshold rule.

    A string's characters, a list's elements, and anything else's rendered length. A rule
    about a large paste should fire on a large paste whether the producer stored it as a
    string or as a list of chunks.
    """
    if isinstance(value, (str, list, dict)):
        return len(value)
    return len(as_text(value))


__all__ = [
    "MODIFIERS",
    "OPERATORS",
    "All",
    "Any_",
    "Condition",
    "ConditionError",
    "Leaf",
    "None_",
    "parse",
]
