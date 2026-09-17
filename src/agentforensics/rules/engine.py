"""Running a pack of rules over a case.

One pass over the events, every rule offered every event it applies to. Deliberately not
clever: no index of rules by field, no query pushed down into SQLite. A case is bounded by
what one endpoint wrote, the expensive part is the regexes rather than the row fetch, and a
detection engine an analyst cannot follow in one reading is a detection engine nobody will
trust the output of.

Three properties are load-bearing.

**A finding is keyed by its evidence, not by a counter.** The identifier is derived from
the rule id and the event ids it rests on, so re-scanning a case leaves it unchanged rather
than doubling its findings, and a finding cited in a report last week still resolves to the
same row. Same as the event model's own idempotence, for the same reason.

**A scan that found nothing is recorded.** `scan_runs` gets a row naming every rule that
ran, whether or not any fired. Without it, a case with no findings and a case nobody
scanned are the same case, and those are opposite conclusions. This is the same rule the
collection side follows for a glob it declined to search.

**A rule that fires says what fired it.** The finding carries the matched values, the
condition in words, and the rule file's hash. A finding that only named a rule would be
something an analyst has to take on trust, and the whole point of the provenance in this
tool is that nothing has to be taken on trust. The exception is a rule marked `redact`,
where the matched value is the credential itself; there the finding says what kind of thing
matched and where, and the event holds the original.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from agentforensics import __version__
from agentforensics.model import Case
from agentforensics.rules.conditions import Leaf
from agentforensics.rules.model import SEVERITY_ORDER, Aggregate, Rule
from agentforensics.rules.select import EventView, as_text

# How much of a matched value a finding quotes. Long enough to recognise a command line,
# short enough that a findings CSV stays readable. The event holds the whole thing, which
# is where an analyst goes for the rest, so nothing is lost by stopping here.
QUOTE_LIMIT = 300

# How many matched values one finding quotes. A rule that matched sixty paths is better
# described by six of them and a count than by sixty, and the events are all linked.
QUOTE_COUNT = 6


@dataclass(frozen=True, slots=True)
class Finding:
    """One thing a rule found, and the evidence it rests on."""

    finding_id: str
    rule: Rule
    event_ids: tuple[str, ...]
    ts_utc: str | None
    agent: str | None
    user: str | None
    session_id: str | None
    summary: str
    matched: dict[str, Any]

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.rule.severity, len(SEVERITY_ORDER))


@dataclass
class ScanReport:
    """What one scan did, in the terms a report will quote."""

    run_id: str
    started_utc: str
    finished_utc: str
    events_read: int = 0
    rules_run: int = 0
    findings: list[Finding] = field(default_factory=list)
    # Rules that matched nothing. Listed rather than counted, because "this rule ran and
    # found nothing" is the sentence that makes an empty result meaningful.
    silent: list[str] = field(default_factory=list)
    # Events the case holds that no rule could even look at, because their kind is not one
    # any rule applies to. A large number here is not a clean case, it is a gap in the
    # pack, and it is the number a pack's author should read first.
    events_no_rule_applied: int = 0

    def by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for finding in self.findings:
            out[finding.rule.severity] = out.get(finding.rule.severity, 0) + 1
        return out

    def summary(self) -> str:
        lines = [
            f"scan {self.run_id}",
            f"  {self.rules_run} rule(s) over {self.events_read} event(s)",
            f"  {len(self.findings)} finding(s)",
        ]
        counts = self.by_severity()
        if counts:
            ordered = sorted(counts.items(), key=lambda item: SEVERITY_ORDER.get(item[0], 9))
            lines.append("  by severity: " + ", ".join(f"{name} {n}" for name, n in ordered))
        if self.silent:
            lines.append(
                f"  {len(self.silent)} rule(s) ran and matched nothing, which is what makes "
                "an empty result mean something"
            )
        if self.events_no_rule_applied:
            lines.append(
                f"  {self.events_no_rule_applied} event(s) no rule in this pack looks at. "
                "That is a gap in the pack rather than a clean case."
            )
        return "\n".join(lines)


def events(case: Case) -> Iterator[EventView]:
    """Every event in a case, in a stable order, as a rule sees it.

    Ordered the same way the timeline is: undated first, because their position is unknown
    rather than early, then by time, then by where they came from. Two scans of one case
    therefore produce findings in the same order, which is what makes two reports
    comparable.
    """
    rows = case.query(
        """
        SELECT e.event_id, e.kind, e.agent, e.actor, e.ts_utc, e.client,
               h.name AS host, u.name AS user, e.session_id, e.project_path, e.git_branch,
               e.parse_problem, e.payload, e.raw,
               e.bundle_uuid, e.original_path, e.file_sha256, e.artifact_id, e.locator
          FROM events e
          LEFT JOIN users u ON u.user_id = e.user_id
          LEFT JOIN hosts h ON h.host_id = e.host_id
         ORDER BY e.ts_utc IS NULL DESC, e.ts_utc, e.original_path, e.locator, e.kind
        """
    )
    for row in rows:
        yield _view(row)


def _view(row: sqlite3.Row) -> EventView:
    return EventView(
        event_id=row["event_id"],
        kind=row["kind"],
        agent=row["agent"],
        actor=row["actor"],
        ts_utc=row["ts_utc"],
        client=row["client"],
        host=row["host"],
        user=row["user"],
        session_id=row["session_id"],
        project_path=row["project_path"],
        git_branch=row["git_branch"],
        parse_problem=row["parse_problem"],
        payload=_decode(row["payload"]),
        raw=_decode_any(row["raw"]),
        provenance={
            "bundle_uuid": row["bundle_uuid"],
            "original_path": row["original_path"],
            "sha256": row["file_sha256"],
            "artifact_id": row["artifact_id"],
            "locator": row["locator"],
        },
    )


def _decode(text: Any) -> dict[str, Any]:
    value = _decode_any(text)
    return value if isinstance(value, dict) else {}


def _decode_any(text: Any) -> Any:
    """Decode a stored JSON column, tolerating one that will not decode.

    A column this build cannot read is not a reason to abandon a scan: the rest of the
    event is still there, and the text itself is returned so a rule searching whole-record
    text still sees it. Losing the event would be worse than reading it coarsely.
    """
    if text is None:
        return None
    if not isinstance(text, str):
        return text
    try:
        return json.loads(text)
    except ValueError:
        return text


def scan(case: Case, rules: Sequence[Rule], *, store: bool = True) -> ScanReport:
    """Run every rule over every event, and record what happened."""
    started = _now()
    report = ScanReport(
        run_id="scan-" + uuid.uuid4().hex[:12],
        started_utc=started,
        finished_utc=started,
        rules_run=len(rules),
    )

    simple = [rule for rule in rules if rule.aggregate is None]
    grouped = [rule for rule in rules if rule.aggregate is not None]
    fired: set[str] = set()
    # Per aggregate rule, the events it matched, keyed by group.
    buckets: dict[str, dict[tuple[Any, ...], list[EventView]]] = {rule.id: {} for rule in grouped}

    for event in events(case):
        report.events_read += 1
        looked = False
        for rule in simple:
            if not rule.applies_to(event):
                continue
            looked = True
            if rule.condition.matches(event):
                fired.add(rule.id)
                report.findings.append(_finding(rule, [event]))
        for rule in grouped:
            if not rule.applies_to(event):
                continue
            looked = True
            aggregate = rule.aggregate
            if aggregate is not None and rule.condition.matches(event):
                key = tuple(_group_value(event, name) for name in aggregate.group_by)
                buckets[rule.id].setdefault(key, []).append(event)
        if not looked:
            report.events_no_rule_applied += 1

    for rule in grouped:
        aggregate = rule.aggregate
        if aggregate is None:  # pragma: no cover - grouped is filtered on this
            continue
        for members in buckets[rule.id].values():
            for window in _windows(members, aggregate):
                if len(window) >= aggregate.min_count:
                    fired.add(rule.id)
                    report.findings.append(_finding(rule, window))

    report.findings.sort(key=lambda item: (item.severity_rank, item.ts_utc or "", item.finding_id))
    report.silent = sorted(rule.id for rule in rules if rule.id not in fired)
    report.finished_utc = _now()

    if store:
        _store(case, report, rules)
    return report


def _group_value(event: EventView, name: str) -> Any:
    """One grouping key, with an absent value kept distinct from an empty one."""
    value = getattr(event, name, None)
    return ("\x00absent",) if value is None else value


def _windows(members: list[EventView], aggregate: Aggregate) -> list[list[EventView]]:
    """The groups an aggregate rule fires on.

    Without a window, one group. With one, every maximal run of events inside it, so a rule
    about a burst does not fire on the same number of events spread over a week.

    Undated events are put in a group of their own rather than folded into a window they
    might not belong to. Their position is unknown, and a burst assembled out of events
    that might not have been close together would be a finding built on a guess.
    """
    if aggregate.window_minutes is None:
        return [members]

    dated = sorted((event for event in members if event.ts_utc), key=lambda item: item.ts_utc or "")
    undated = [event for event in members if not event.ts_utc]

    out: list[list[EventView]] = []
    span = aggregate.window_minutes * 60
    start = 0
    for end in range(len(dated)):
        while start < end and _seconds(dated[end]) - _seconds(dated[start]) > span:
            start += 1
        if end - start + 1 >= aggregate.min_count:
            out.append(dated[start : end + 1])
    # The longest run wins rather than every prefix of it, so a burst of thirty is one
    # finding and not eleven overlapping ones.
    if out:
        out = [max(out, key=len)]
    if undated:
        out.append(undated)
    return out


def _seconds(event: EventView) -> float:
    """An event's time in seconds, best effort.

    Best effort is honest: a producer can write a time this build cannot parse, and a rule
    about a burst should degrade to "all in one group" rather than raise. The precision the
    event carries says how much to trust the ordering anyway.
    """
    text = (event.ts_utc or "").replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return 0.0


def _finding(rule: Rule, members: Sequence[EventView]) -> Finding:
    first = members[0]
    dated = [event.ts_utc for event in members if event.ts_utc]
    matched = _matched(rule, members)
    return Finding(
        finding_id=_finding_id(rule, members),
        rule=rule,
        event_ids=tuple(event.event_id for event in members),
        ts_utc=min(dated) if dated else None,
        agent=first.agent,
        user=first.user,
        session_id=first.session_id,
        summary=_summary(rule, members, matched),
        matched=matched,
    )


def _finding_id(rule: Rule, members: Sequence[EventView]) -> str:
    """Derived from the rule and its evidence, so a re-scan changes nothing.

    The rule's file hash is deliberately not in it. A finding is about the evidence, and an
    edit to a rule's prose should not produce a second finding about the same events; which
    version of the rule produced it is recorded on the row instead.
    """
    digest = hashlib.sha256()
    digest.update(rule.id.encode("utf-8"))
    for event_id in sorted(event.event_id for event in members):
        digest.update(b"\x00")
        digest.update(event_id.encode("utf-8"))
    return digest.hexdigest()[:32]


def _matched(rule: Rule, members: Sequence[EventView]) -> dict[str, Any]:
    """What fired the rule, in the form a finding carries.

    Collected from the leaves rather than re-derived, so the finding quotes the value the
    condition actually accepted. For a redacted rule the values are replaced by their shape:
    which field, how long, and the first few characters, which is enough to find it in the
    event and not enough to be the secret.
    """
    values: dict[str, list[str]] = {}
    for leaf in _leaves(rule.condition):
        for event in members:
            for value in leaf.hits(event):
                text = as_text(value)
                bucket = values.setdefault(leaf.selector, [])
                if rule.redact:
                    shown = f"<redacted, {len(text)} characters, begins {text[:4]!r}>"
                else:
                    shown = text if len(text) <= QUOTE_LIMIT else text[:QUOTE_LIMIT] + " ..."
                if shown not in bucket:
                    bucket.append(shown)

    out: dict[str, Any] = {}
    for selector, bucket in values.items():
        out[selector] = bucket[:QUOTE_COUNT]
        if len(bucket) > QUOTE_COUNT:
            out[selector + " (more)"] = len(bucket) - QUOTE_COUNT
    if rule.redact:
        out["note"] = (
            "The matched values are not quoted here. This rule matches credentials, and a "
            "finding is exported and pasted into reports, so the value stays in the event "
            "it came from."
        )
    return out


def _leaves(condition: Any) -> Iterator[Leaf]:
    if isinstance(condition, Leaf):
        yield condition
        return
    for part in getattr(condition, "parts", ()):
        yield from _leaves(part)


def _summary(rule: Rule, members: Sequence[EventView], matched: dict[str, Any]) -> str:
    """The one line an analyst reads first.

    The title, then what the finding is about, then where. Written here rather than in the
    rule file because the second and third parts are properties of the evidence, and a rule
    file that tried to phrase them would be guessing.
    """
    where = members[0].provenance.get("original_path") or "an unknown path"
    quoted = ""
    for key, value in matched.items():
        if isinstance(value, list) and value:
            quoted = f"{key} {value[0]}"
            break
    parts = [rule.title]
    if len(members) > 1:
        parts.append(f"{len(members)} events")
    if quoted:
        parts.append(quoted)
    parts.append(f"in {where}")
    return ", ".join(parts)


def _store(case: Case, report: ScanReport, rules: Sequence[Rule]) -> None:
    """Write the findings and the run into the case.

    One transaction, so a scan either lands or does not. A case holding half a scan would
    have counts nobody could trust, and a count is what an analyst reads first.

    Findings are inserted with the conflict ignored rather than replaced, for the same
    reason events are: the same evidence and the same rule always produce the same row, so
    a second scan has nothing to say the first did not.
    """
    scanned = _now()
    with case.transaction() as connection:
        for finding in report.findings:
            connection.execute(
                """
                INSERT INTO findings (
                    finding_id, rule_id, pack, severity, title, ts_utc, agent, user_id,
                    session_id, summary, matched, event_count, rule_sha256, scanned_utc
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(finding_id) DO NOTHING
                """,
                (
                    finding.finding_id,
                    finding.rule.id,
                    finding.rule.pack,
                    finding.rule.severity,
                    finding.rule.title,
                    finding.ts_utc,
                    finding.agent,
                    case.user_id(finding.user),
                    finding.session_id,
                    finding.summary,
                    json.dumps(finding.matched, sort_keys=True, ensure_ascii=False, default=str),
                    len(finding.event_ids),
                    finding.rule.sha256,
                    scanned,
                ),
            )
            for event_id in finding.event_ids:
                connection.execute(
                    "INSERT OR IGNORE INTO finding_events (finding_id, event_id) VALUES (?,?)",
                    (finding.finding_id, event_id),
                )

        connection.execute(
            """
            INSERT INTO scan_runs (
                run_id, started_utc, finished_utc, rules_run, rule_ids, events_read,
                findings, tool_version
            ) VALUES (?,?,?,?,?,?,?,?)
            """,
            (
                report.run_id,
                report.started_utc,
                report.finished_utc,
                len(rules),
                # Every rule that ran, named. This is what turns "no findings" from an
                # absence into a statement about which questions were asked.
                json.dumps(sorted(rule.id for rule in rules)),
                report.events_read,
                len(report.findings),
                __version__,
            ),
        )


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


__all__ = ["QUOTE_COUNT", "QUOTE_LIMIT", "Finding", "ScanReport", "events", "scan"]
