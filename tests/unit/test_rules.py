"""The rule engine, and every rule's own tests.

The first test in this file is the one the brief asked for and the one that matters: every
positive and negative sample in every shipped rule file is its own pytest case, so a rule
that stops working names itself in the failure output. A detection pack whose rules are not
executed by the test suite is a pack that silently rots, and the failure mode is not a rule
that misses, it is a rule that fires on everything and trains an analyst to skip the pack.

The rest is the engine. Most of it is about the two ways a rule can be wrong in a way
nobody notices: a selector that resolves to nothing, and a condition that matches
everything. Both look like a working tool from the outside, one reporting a clean case and
the other reporting noise.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from agentforensics.model import Case
from agentforensics.rules import (
    PACKS,
    SEVERITIES,
    Rule,
    RuleError,
    load,
    load_file,
    scan,
)
from agentforensics.rules import testing as rule_testing
from agentforensics.rules.conditions import ConditionError, parse
from agentforensics.rules.select import SelectorError, check, flatten, resolve

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = REPO_ROOT / "rules"


@pytest.fixture(scope="module")
def rules() -> list[Rule]:
    return load(RULES_DIR)


def _samples() -> list[tuple[str, str, Rule, Any]]:
    """Every (rule, sample) pair, for parametrization.

    Collected at import time because pytest parametrization happens then. A rule directory
    that will not load is therefore a collection error naming the file, which is what should
    happen: a pack that cannot be loaded must not be reported as a pack with no failures.
    """
    out = []
    for rule in load(RULES_DIR):
        for test in rule.tests:
            out.append((rule.id, test.name, rule, test))
    return out


SAMPLES = _samples()


@pytest.mark.parametrize(
    ("rule", "sample"),
    [(rule, sample) for _, _, rule, sample in SAMPLES],
    ids=[f"{rule_id}:{name}" for rule_id, name, _, _ in SAMPLES],
)
def test_a_rule_agrees_with_its_own_sample(rule: Rule, sample: Any) -> None:
    """One case per sample, so a broken rule names itself and its sample."""
    event = rule_testing.view(sample.event)
    got = rule.matches(event)
    assert got == sample.should_match, "\n".join(
        [
            f"{rule.id} sample {sample.name!r}: "
            f"expected {'a match' if sample.should_match else 'no match'}, got the opposite",
            f"condition: {rule.condition.describe()}",
            f"the event as a rule sees it:\n{flatten(sample.event)}",
        ]
    )


def test_every_sample_is_reachable() -> None:
    """A sample whose event the rule does not even look at tests nothing.

    Checked separately from the sample itself because such a sample can still pass: a
    negative sample that the rule's scope excludes passes for the wrong reason, and would
    keep passing if the condition were deleted.
    """
    unreachable = []
    for rule_id, name, rule, sample in SAMPLES:
        if sample.out_of_scope:
            # Declared. Some rules are protected by their scope rather than by their
            # condition, and for those the exclusion is the thing worth demonstrating.
            continue
        if not rule.applies_to(rule_testing.view(sample.event)):
            unreachable.append(f"{rule_id}: {name}")
    assert not unreachable, (
        "these samples are outside their rule's own applies_to, so the rule never looks at "
        "them and a negative sample among them passes for the wrong reason. Either fix the "
        "sample, or mark it out_of_scope if the exclusion is what it demonstrates: "
        f"{unreachable}"
    )


# ----------------------------------------------------------------- pack hygiene


def test_every_rule_loads_and_the_ids_are_unique(rules: list[Rule]) -> None:
    assert rules
    ids = [rule.id for rule in rules]
    assert len(ids) == len(set(ids))
    assert ids == sorted(ids), "load() has to return a stable order, so two reports compare"


def test_every_rule_names_a_pack_this_suite_ships(rules: list[Rule]) -> None:
    for rule in rules:
        assert rule.pack in PACKS
        assert rule.path.parent.name == rule.pack


def test_there_is_no_organization_scope_pack() -> None:
    """ADR 0010. The strings such rules need are exactly the strings a public repository
    must not carry, and the question they answer is a data loss prevention question rather
    than a question about what an agent did."""
    assert "org_scope" not in PACKS
    assert not (RULES_DIR / "org_scope").exists()


def test_no_rule_id_carries_the_superseded_acronym(rules: list[Rule]) -> None:
    """ADR 0002 keeps the brief's working name out of the repository, and a rule id is the
    string that ends up quoted in somebody's report."""
    for rule in rules:
        assert rule.id.startswith("AFX-")


def test_every_rule_explains_why_an_analyst_cares(rules: list[Rule]) -> None:
    """The field that decides whether a rule is worth shipping. A rule nobody can explain
    the point of gets ignored, and a pack whose rules get ignored is worse than no pack."""
    for rule in rules:
        assert len(rule.rationale) >= 40, f"{rule.id} has a rationale of {len(rule.rationale)}"
        assert rule.rationale != rule.description


def test_a_severe_rule_says_what_it_fires_on_wrongly(rules: list[Rule]) -> None:
    """A high or critical rule interrupts somebody, so it has to have had its false
    positives thought about. An empty list would be a claim that there are none."""
    for rule in rules:
        if rule.severity in ("high", "critical"):
            assert rule.false_positives, f"{rule.id} is {rule.severity} and lists none"


def test_every_severity_is_one_of_the_five(rules: list[Rule]) -> None:
    for rule in rules:
        assert rule.severity in SEVERITIES


# The secrets rules whose match is a name rather than a value, with the reason. Redaction
# replaces a match with its shape, which is right when the match is the credential and wrong
# when the match is the path to one: a finding that said a file of ten characters beginning
# ".env" had been copied everywhere would have hidden the one thing it exists to report.
# Kept as a list with reasons rather than as a field on the rule, so adding one is a
# decision somebody writes down here and not a flag they set in passing.
MATCHES_A_NAME = {
    "AFX-SECRETS-008": "the match is an entry in a worktree include list, which is a file "
    "name the author wrote down. The finding is where copies of that file are, and the "
    "name is the whole of it; no value is read and none is quoted",
}


def test_a_secrets_rule_never_quotes_what_it_matched(rules: list[Rule]) -> None:
    """The matched value there is the credential. A finding is exported to CSV and pasted
    into reports, so quoting it would spread the credential rather than report it."""
    exempt = set(MATCHES_A_NAME)
    for rule in rules:
        if rule.pack == "secrets" and rule.id not in exempt:
            assert rule.redact, f"{rule.id} matches credentials and does not redact them"
    # Both directions, so an exemption that stops being needed has to be removed rather
    # than sitting here making the guard look narrower than it is.
    ids = {rule.id for rule in rules}
    assert exempt <= ids, sorted(exempt - ids)
    for rule in rules:
        if rule.id in exempt:
            assert not rule.redact, f"{rule.id} redacts and no longer needs its exemption"
            assert MATCHES_A_NAME[rule.id].strip()


def test_every_rule_file_hashes_to_something_stable(rules: list[Rule]) -> None:
    """A finding carries the hash of the rule text that produced it, so a rule edited after
    a scan leaves findings that can still be reproduced against the right text."""
    for rule in rules:
        assert len(rule.sha256) == 64
        assert load_file(rule.path, pack=rule.pack).sha256 == rule.sha256


# ------------------------------------------------------- the loader refuses things


def write(tmp_path: Path, pack: str, name: str, body: str) -> Path:
    directory = tmp_path / pack
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(body, encoding="utf-8")
    return path


MINIMAL = """
id: AFX-SECRETS-900
pack: secrets
title: A rule used by the loader tests
severity: low
description: Long enough to satisfy the schema's minimum length for a description.
rationale: Long enough to satisfy the schema's minimum length for a rationale field.
redact: true
match:
  field: text
  contains: needle
tests:
  - name: the needle
    match: true
    event: {payload: {text: needle}}
  - name: no needle
    match: false
    event: {payload: {text: hay}}
"""


def test_the_minimal_rule_the_other_tests_build_on_loads(tmp_path: Path) -> None:
    path = write(tmp_path, "secrets", "AFX-SECRETS-900.yaml", MINIMAL)
    rule = load_file(path, pack="secrets")
    assert rule.id == "AFX-SECRETS-900"
    assert not rule_testing.run(rule)


def test_a_rule_with_only_positive_tests_is_refused(tmp_path: Path) -> None:
    """The failure that matters is a rule that fires on everything, and such a rule passes
    every positive test it has."""
    body = MINIMAL.replace(
        """  - name: no needle
    match: false
    event: {payload: {text: hay}}""",
        """  - name: another needle
    match: true
    event: {payload: {text: needle two}}""",
    )
    path = write(tmp_path, "secrets", "AFX-SECRETS-901.yaml", body.replace("900", "901"))
    with pytest.raises(RuleError, match="should not match"):
        load_file(path, pack="secrets")


def test_a_rule_with_no_positive_test_is_refused(tmp_path: Path) -> None:
    body = MINIMAL.replace(
        """  - name: the needle
    match: true
    event: {payload: {text: needle}}""",
        """  - name: also no needle
    match: false
    event: {payload: {text: straw}}""",
    )
    path = write(tmp_path, "secrets", "AFX-SECRETS-902.yaml", body.replace("900", "902"))
    with pytest.raises(RuleError, match="should ever match"):
        load_file(path, pack="secrets")


def test_a_misspelled_field_is_refused_at_load_time(tmp_path: Path) -> None:
    """Rather than a rule that runs and never fires. A rule that silently matches nothing
    is the worst outcome available: it looks like a clean case."""
    body = MINIMAL.replace("field: text", "field: payloadd.text").replace("900", "903")
    path = write(tmp_path, "secrets", "AFX-SECRETS-903.yaml", body)
    with pytest.raises(RuleError, match="not something an event can be asked for"):
        load_file(path, pack="secrets")


def test_a_regex_that_does_not_compile_is_refused_at_load_time(tmp_path: Path) -> None:
    body = MINIMAL.replace("contains: needle", "regex: '[unclosed'").replace("900", "904")
    path = write(tmp_path, "secrets", "AFX-SECRETS-904.yaml", body)
    with pytest.raises(RuleError):
        load_file(path, pack="secrets")


def test_an_id_that_disagrees_with_its_pack_is_refused(tmp_path: Path) -> None:
    """The id's middle segment names its pack, so an id quoted in a report says where to
    look without anybody holding a mapping in their head."""
    body = MINIMAL.replace("AFX-SECRETS-900", "AFX-SUPPLYCHAIN-900")
    path = write(tmp_path, "secrets", "AFX-SUPPLYCHAIN-900.yaml", body)
    with pytest.raises(RuleError, match="middle"):
        load_file(path, pack="secrets")


def test_a_rule_in_the_wrong_directory_is_refused(tmp_path: Path) -> None:
    path = write(tmp_path, "anti_forensics", "AFX-SECRETS-900.yaml", MINIMAL)
    with pytest.raises(RuleError, match="directory decides"):
        load_file(path, pack="anti_forensics")


def test_a_directory_that_is_not_a_pack_is_refused(tmp_path: Path) -> None:
    """Rather than ignored. A rule pack somebody added and nobody ran is worse than none."""
    write(tmp_path, "my_rules", "AFX-SECRETS-900.yaml", MINIMAL)
    with pytest.raises(RuleError, match="not a known pack"):
        load(tmp_path)


def test_two_rules_may_not_share_an_id(tmp_path: Path) -> None:
    write(tmp_path, "secrets", "a.yaml", MINIMAL)
    write(tmp_path, "secrets", "b.yaml", MINIMAL)
    with pytest.raises(RuleError, match="already used by"):
        load(tmp_path)


def test_a_test_that_states_a_field_no_event_has_is_refused() -> None:
    """A test that set a payload key at the top level would otherwise pass while testing
    nothing, and a rule whose tests test nothing looks covered."""
    with pytest.raises(rule_testing.TestEventError, match="which an event does not have"):
        rule_testing.view({"command": "rm -rf /"})


# ------------------------------------------------------------ the condition language


def event(**fields: Any) -> Any:
    return rule_testing.view(fields)


def cond(node: Any) -> Any:
    return parse(node)


def test_a_selector_resolves_to_every_value_it_names() -> None:
    """The property that removes the class of rule that only checks the first element."""
    view = event(payload={"commands": [{"command": "a"}, {"command": "b"}, {"command": "c"}]})
    assert resolve(view, "payload.commands[].command") == ["a", "b", "c"]
    assert cond({"field": "payload.commands[].command", "equals": "c"}).matches(view)


def test_an_absent_field_resolves_to_nothing_rather_than_none() -> None:
    view = event(payload={})
    assert resolve(view, "payload.nope") == []
    assert cond({"field": "payload.nope", "exists": False}).matches(view)
    assert not cond({"field": "payload.nope", "exists": True}).matches(view)


def test_a_group_condition_holds_exactly_one_operator() -> None:
    with pytest.raises(ConditionError, match="exactly one of all, any or none"):
        cond({"all": [{"field": "kind", "equals": "a"}], "any": [{"field": "kind", "equals": "b"}]})


def test_none_is_the_negation_the_language_has() -> None:
    """Not a general not: a bare negation over a field that resolves to a list has two
    defensible meanings, and a detection language should not have one of those."""
    view = event(payload={"commands": [{"command": "git push origin main"}]})
    condition = cond(
        {
            "all": [
                {"field": "payload.commands[].command", "contains": "git push"},
                {"none": [{"field": "payload.commands[].command", "contains": "--dry-run"}]},
            ]
        }
    )
    assert condition.matches(view)
    dry = event(payload={"commands": [{"command": "git push --dry-run origin main"}]})
    assert not condition.matches(dry)


def test_a_leaf_needs_exactly_one_operator() -> None:
    with pytest.raises(ConditionError, match="exactly one operator"):
        cond({"field": "text", "contains": "a", "equals": "b"})
    with pytest.raises(ConditionError, match="exactly one operator"):
        cond({"field": "text"})


def test_an_unknown_key_in_a_leaf_is_refused() -> None:
    """Rather than ignored, because a misspelled operator would be a condition with no
    test in it, and a leaf with no test matches nothing."""
    with pytest.raises(ConditionError, match="unknown key"):
        cond({"field": "text", "containss": "a"})


def test_contains_ignores_case_and_regex_does_not() -> None:
    """A silent (?i) on a hand-written pattern would change what it matches, so the pattern
    says so itself."""
    view = event(payload={"text": "DROP TABLE users"})
    assert cond({"field": "text", "contains": "drop table"}).matches(view)
    assert not cond({"field": "text", "regex": "drop table"}).matches(view)
    assert cond({"field": "text", "regex": "(?i)drop table"}).matches(view)


def test_a_glob_stops_at_a_separator_unless_it_says_otherwise() -> None:
    """fnmatch's * crosses separators, which would make a rule that says .ssh/* match
    .ssh/a/b/c, and nobody could reason about such a rule.

    A pattern is anchored at both ends, so a single * is exactly one segment. The
    distinction this pins is between one level under a directory and any depth under it,
    which is the difference between "a key file in .ssh" and "anything in .ssh at all".
    """
    shallow = event(payload={"files": [{"path": "/home/alice/.ssh/id_ed25519"}]})
    deep = event(payload={"files": [{"path": "/home/alice/.ssh/keys/old/id_rsa"}]})
    one_level = cond({"field": "payload.files[].path", "glob": "**/.ssh/*"})
    assert one_level.matches(shallow)
    assert not one_level.matches(deep)
    any_depth = cond({"field": "payload.files[].path", "glob": "**/.ssh/**"})
    assert any_depth.matches(shallow)
    assert any_depth.matches(deep)
    # A single leading * really is one segment, which is what makes the two distinct.
    assert not cond({"field": "payload.files[].path", "glob": "*/.ssh/*"}).matches(shallow)


def test_a_glob_matches_either_separator() -> None:
    """So one rule covers both platforms."""
    windows = event(payload={"files": [{"path": "C:\\Users\\alice\\.ssh\\id_rsa"}]})
    assert cond({"field": "payload.files[].path", "glob": "**/.ssh/**"}).matches(windows)


def test_a_numeric_comparison_ignores_a_value_that_is_not_a_number() -> None:
    assert cond({"field": "payload.n", "gt": 5}).matches(event(payload={"n": 6}))
    assert cond({"field": "payload.n", "gt": 5}).matches(event(payload={"n": "6"}))
    assert not cond({"field": "payload.n", "gt": 5}).matches(event(payload={"n": "six"}))


def test_count_gte_counts_values_rather_than_testing_one() -> None:
    many = event(payload={"files": [{"path": f"/a/{n}"} for n in range(25)]})
    few = event(payload={"files": [{"path": "/a/1"}]})
    condition = cond({"field": "payload.files[].path", "count_gte": 20})
    assert condition.matches(many)
    assert not condition.matches(few)


def test_length_measures_a_string_or_a_list() -> None:
    assert cond({"field": "text", "length_gt": 10}).matches(event(payload={"text": "x" * 11}))
    assert not cond({"field": "text", "length_gt": 10}).matches(event(payload={"text": "x"}))


# ------------------------------------------------------------- the whole-record text


def test_whole_record_text_is_not_json() -> None:
    """The first implementation rendered JSON, and the rule tests caught it: JSON escapes
    the quotes inside a string, so a pattern written for AUTH_TOKEN = "value" stopped
    matching once the string was nested. A pattern that depends on the serialisation of the
    thing it searches breaks on the next producer."""
    rendered = flatten({"text": 'AUTH_TOKEN = "abcd1234"'})
    assert '\\"' not in rendered
    assert 'AUTH_TOKEN = "abcd1234"' in rendered


def test_a_field_name_and_its_value_read_as_an_assignment() -> None:
    """Which is what makes one pattern cover a credential in a command line and the same
    credential stored as a field."""
    assert "password = s3cr3t" in flatten({"password": "s3cr3t"})


def test_whole_record_text_reaches_a_field_nobody_mapped() -> None:
    """The reason the secrets pack searches it. A credential can sit in any field of any
    record, including one no parser understood."""
    view = event(payload={}, raw={"a_field_nobody_maps": "AKIAIOSFODNN7EXAMPLE"})
    assert cond({"field": "event_text", "regex": r"\bAKIA[0-9A-Z]{16}\b"}).matches(view)


def test_a_raw_record_that_is_a_string_is_still_searched() -> None:
    """Which is the shape a line that did not decode arrives in."""
    view = event(kind="unparsed.record", raw='{"truncated": "AKIAIOSFODNN7EXAMPLE')
    assert cond({"field": "event_text", "regex": r"\bAKIA[0-9A-Z]{16}\b"}).matches(view)


def test_check_refuses_a_provenance_field_that_does_not_exist() -> None:
    check("provenance.original_path")
    with pytest.raises(SelectorError, match="provenance has no field"):
        check("provenance.nope")


# ----------------------------------------------------------------------- the engine


def ingested(tmp_path: Path) -> Case:
    """A tiny case with three events, built by hand.

    By hand rather than from the fixture profile, because these tests are about the engine
    and a case whose contents can change under them would make a failure here ambiguous.
    """
    from agentforensics.model import BundleRecord
    from agentforensics.model.event import Event, Provenance

    case = Case.open(tmp_path / "case.sqlite")
    case.add_bundle(BundleRecord(bundle_uuid="b1", source_kind="directory", source_path="/x"))

    def make(index: int, command: str, ts: str | None) -> Event:
        return Event(
            kind="command.exec",
            provenance=Provenance(
                "b1", "/home/alice/.claude/history.jsonl", "aa", None, f"line:{index}"
            ),
            agent="claude_code",
            raw={"command": command},
            ts_utc=ts,
            ts_precision="second" if ts else "absent",
            ts_source="timestamp" if ts else None,
            actor="assistant",
            user="alice",
            session_id="s1",
            payload={"commands": [{"command": command}]},
        )

    case.add_events(
        [
            make(1, "rm -rf ~/.claude/projects", "2026-09-06T09:00:00Z"),
            make(2, "npm ci", "2026-09-06T09:00:10Z"),
            make(3, "claude --dangerously-skip-permissions", None),
        ]
    )
    return case


def test_a_scan_records_itself_even_when_it_finds_nothing(tmp_path: Path) -> None:
    """Without that record, a case with no findings and a case nobody scanned look the
    same, and those are opposite conclusions."""
    quiet = write(
        tmp_path / "rules",
        "secrets",
        "AFX-SECRETS-905.yaml",
        MINIMAL.replace("900", "905").replace("contains: needle", "contains: nothinghere"),
    )
    # The rule's own positive test still has to pass, so the needle moves rather than going
    # away: this is about the scan finding nothing in the case, not about a broken rule.
    quiet.write_text(
        quiet.read_text(encoding="utf-8").replace(
            "event: {payload: {text: needle}}", "event: {payload: {text: nothinghere}}"
        ),
        encoding="utf-8",
    )
    rules = load(tmp_path / "rules")
    with ingested(tmp_path) as case:
        report = scan(case, rules)
        assert not report.findings
        assert report.silent == ["AFX-SECRETS-905"]
        runs = case.query("SELECT rules_run, findings, rule_ids FROM scan_runs")
        assert len(runs) == 1
        assert runs[0]["rules_run"] == 1
        assert runs[0]["findings"] == 0
        assert "AFX-SECRETS-905" in runs[0]["rule_ids"]


def test_a_finding_links_to_the_events_it_rests_on(tmp_path: Path, rules: list[Rule]) -> None:
    with ingested(tmp_path) as case:
        report = scan(case, rules)
        assert report.findings
        for finding in report.findings:
            assert finding.event_ids
            rows = case.query(
                "SELECT event_id FROM finding_events WHERE finding_id = ?", (finding.finding_id,)
            )
            assert {row["event_id"] for row in rows} == set(finding.event_ids)


def test_re_scanning_a_case_does_not_double_its_findings(tmp_path: Path, rules: list[Rule]) -> None:
    """A finding is keyed by the rule and the evidence, so the same evidence and the same
    rule always produce the same row. Re-scanning after a rule is fixed is what an analyst
    does, and the counts have to survive it."""
    with ingested(tmp_path) as case:
        first = scan(case, rules)
        before = case.query("SELECT count(*) AS n FROM findings")[0]["n"]
        scan(case, rules)
        after = case.query("SELECT count(*) AS n FROM findings")[0]["n"]
        assert before == after == len(first.findings)


def test_a_finding_says_what_matched(tmp_path: Path, rules: list[Rule]) -> None:
    """A finding that only named a rule would be something an analyst has to take on
    trust, and nothing in this tool is meant to be taken on trust."""
    with ingested(tmp_path) as case:
        report = scan(case, rules, store=False)
        bypass = next(f for f in report.findings if f.rule.id == "AFX-PERMISSIONBYPASS-001")
        quoted = " ".join(str(v) for v in bypass.matched.values())
        assert "dangerously-skip-permissions" in quoted


def test_a_redacted_rule_does_not_put_the_secret_in_the_finding(tmp_path: Path) -> None:
    """The matched value there is the credential, and a finding is exported to CSV and
    pasted into reports."""
    from agentforensics.model import BundleRecord
    from agentforensics.model.event import Event, Provenance

    case = Case.open(tmp_path / "secret.sqlite")
    case.add_bundle(BundleRecord(bundle_uuid="b1", source_kind="directory", source_path="/x"))
    case.add_events(
        [
            Event(
                kind="user.prompt",
                provenance=Provenance("b1", "/p", "aa", None, "line:1"),
                agent="claude_code",
                raw={"text": "use AKIAIOSFODNN7EXAMPLE"},
                actor="user",
                payload={"text": "use AKIAIOSFODNN7EXAMPLE"},
            )
        ]
    )
    rules = [r for r in load(RULES_DIR) if r.id == "AFX-SECRETS-001"]
    report = scan(case, rules, store=False)
    case.close()
    assert len(report.findings) == 1
    text = str(report.findings[0].matched) + report.findings[0].summary
    assert "AKIAIOSFODNN7EXAMPLE" not in text
    assert "redacted" in text


def test_an_aggregate_rule_fires_once_per_group(tmp_path: Path) -> None:
    """A burst is one finding over many events, not many findings. A rule that reported the
    twentieth member of a burst would be reporting the wrong thing."""
    body = """
id: AFX-DATAVOLUME-900
pack: data_volume
title: A rule used by the aggregate engine tests
severity: low
description: Fires when several matching commands appear in one session, for the tests.
rationale: Long enough to satisfy the schema, and it exists only to exercise aggregation.
applies_to:
  kinds: [command.exec]
match:
  field: payload.commands[].command
  exists: true
aggregate:
  group_by: [session_id]
  min_count: 2
tests:
  - name: a command
    match: true
    event: {kind: command.exec, payload: {commands: [{command: ls}]}}
  - name: no command
    match: false
    event: {kind: command.exec, payload: {}}
"""
    write(tmp_path / "rules", "data_volume", "AFX-DATAVOLUME-900.yaml", body)
    rules = load(tmp_path / "rules")
    with ingested(tmp_path) as case:
        report = scan(case, rules, store=False)
        assert len(report.findings) == 1, "three commands in one session are one finding"
        assert len(report.findings[0].event_ids) == 3


def test_an_aggregate_window_does_not_fold_undated_events_in(tmp_path: Path) -> None:
    """Their position is unknown, and a burst assembled out of events that might not have
    been close together would be a finding built on a guess."""
    body = """
id: AFX-DATAVOLUME-901
pack: data_volume
title: A windowed rule used by the aggregate engine tests
severity: low
description: Fires when several matching commands appear close together, for the tests.
rationale: Long enough to satisfy the schema, and it exists only to exercise windowing.
applies_to:
  kinds: [command.exec]
match:
  field: payload.commands[].command
  exists: true
aggregate:
  group_by: [session_id]
  min_count: 2
  window_minutes: 1
tests:
  - name: a command
    match: true
    event: {kind: command.exec, payload: {commands: [{command: ls}]}}
  - name: no command
    match: false
    event: {kind: command.exec, payload: {}}
"""
    write(tmp_path / "rules", "data_volume", "AFX-DATAVOLUME-901.yaml", body)
    rules = load(tmp_path / "rules")
    with ingested(tmp_path) as case:
        report = scan(case, rules, store=False)
        # The two dated events are ten seconds apart, so they are one window. The undated
        # one is on its own and never reaches min_count, so it produces no finding.
        assert len(report.findings) == 1
        assert len(report.findings[0].event_ids) == 2


def test_the_scan_reports_events_no_rule_looked_at(tmp_path: Path) -> None:
    """A large number there is a gap in the pack rather than a clean case, and it is the
    number a pack's author should read first."""
    body = MINIMAL.replace("900", "906").replace(
        "match:\n  field: text\n  contains: needle",
        "applies_to:\n  kinds: [mcp.call]\nmatch:\n  field: text\n  contains: needle",
    )
    body = body.replace(
        "event: {payload: {text: needle}}", "event: {kind: mcp.call, payload: {text: needle}}"
    ).replace("event: {payload: {text: hay}}", "event: {kind: mcp.call, payload: {text: hay}}")
    write(tmp_path / "rules", "secrets", "AFX-SECRETS-906.yaml", body)
    rules = load(tmp_path / "rules")
    with ingested(tmp_path) as case:
        report = scan(case, rules, store=False)
        assert report.events_read == 3
        assert report.events_no_rule_applied == 3


def test_findings_are_ordered_by_severity(tmp_path: Path, rules: list[Rule]) -> None:
    """So two scans of one case produce comparable reports, and the thing that should
    interrupt somebody is at the top."""
    with ingested(tmp_path) as case:
        report = scan(case, rules, store=False)
        ranks = [finding.severity_rank for finding in report.findings]
        assert ranks == sorted(ranks)


def test_no_rule_file_carries_key_material(rules: list[Rule]) -> None:
    """The secrets pack is about credentials, so its files hold the shapes it matches.

    A PEM header is one of those shapes, and it is why `detect-private-key` is excluded for
    this directory in the pre-commit configuration. This is the check that makes the
    exclusion narrow rather than a hole: a header with nothing after it is a pattern, and a
    header followed by a long run of base64 is a key somebody pasted in.

    The same applies to the other shapes the pack matches. A sample is allowed to look like
    a credential, which is the point of it, and the loader's own honesty rule is that a
    sample's value has to be an example rather than a live one. What can be checked
    mechanically is the length: nothing in a rule file needs a 100-character opaque string.
    """
    import re

    body = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[^\n]*\n?[A-Za-z0-9+/=]{60,}")
    long_opaque = re.compile(r"\b[A-Za-z0-9+/=_-]{100,}\b")
    for rule in rules:
        text = rule.path.read_text(encoding="utf-8")
        assert not body.search(text), (
            f"{rule.path} carries a PEM header followed by key material. A rule sample "
            "needs the header, which is what its pattern matches, and never a body."
        )
        found = long_opaque.findall(text)
        assert not found, (
            f"{rule.path} carries an opaque string of {len(found[0])} characters. Nothing "
            "in a rule file needs one, and a credential long enough to be real does not "
            "belong in a repository."
        )


def test_whitespace_in_a_pattern_can_cross_a_field_boundary() -> None:
    """The trap two shipped rules fell into, pinned so it is not rediscovered.

    The whole-record text views emit a record's leaves one per line, and `\\s` matches a
    newline. So a pattern shaped like NAME\\s*=\\s*\\S, meaning "NAME assigned something",
    reaches past the end of its own field and matches an unset NAME followed by whatever
    the next field happens to hold. The rule schema says to use [^\\S\\n] instead, and this
    is the demonstration behind that sentence.
    """
    view = event(payload={"a": "HTTPS_PROXY=", "b": "something else"})
    greedy = cond({"field": "event_text", "regex": r"HTTPS_PROXY\s*=\s*\S"})
    careful = cond({"field": "event_text", "regex": r"HTTPS_PROXY[^\S\n]*=[^\S\n]*\S"})
    assert greedy.matches(view), "this is the trap, not a feature: it reads the next field"
    assert not careful.matches(view)
    # And the careful one still does its job when the value really is there.
    assigned = event(payload={"a": "HTTPS_PROXY=http://proxy.example.org:3128"})
    assert careful.matches(assigned)


def test_no_shipped_rule_uses_whitespace_that_can_cross_a_field(rules: list[Rule]) -> None:
    """Mechanical, because the failure is invisible in the rule text.

    A pattern that pairs a field name with an assignment and then `\\s` is the shape that
    reaches into the next field. Rules that need whitespace across lines on purpose can
    say so with an explicit newline in the class, which this allows.
    """
    import re

    suspicious = re.compile(r"[:=]\\s\*")
    for rule in rules:
        text = rule.path.read_text(encoding="utf-8")
        for line in text.splitlines():
            if "regex" not in line and not line.strip().startswith("- '"):
                continue
            assert not suspicious.search(line), (
                f"{rule.path}: {line.strip()}\n"
                "an assignment followed by \\s* reaches past the end of its own field, "
                "because the text a rule searches is the record's leaves one per line. "
                "Use [^\\S\\n]* for whitespace that has to stay on one line."
            )


# --------------------------------------------------------- the generated reference


def test_the_committed_rule_reference_is_current() -> None:
    """The rule files are the source of truth, so the reference is output.

    Checked here as well as by the generator's own --check, because this is the one that
    runs in every contributor's test suite. A reference that lags the rules describes
    detections that are not the ones running.
    """
    import subprocess

    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "gen_rule_docs.py"), "--check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_a_translated_prose_field_is_used_and_not_marked(tmp_path: Path) -> None:
    """The convention the whole project follows for free text: a plain string is English,
    a mapping carries a translation, and a generated document marks what fell back rather
    than passing English off as a translation."""
    body = MINIMAL.replace("900", "907").replace(
        "description: Long enough to satisfy the schema's minimum length for a description.",
        "description:\n"
        "  en: Long enough to satisfy the schema's minimum length for a description.\n"
        "  de: Lang genug fuer die Mindestlaenge, die das Schema fuer eine Beschreibung fordert.",
    )
    path = write(tmp_path, "secrets", "AFX-SECRETS-907.yaml", body)

    english = load_file(path, pack="secrets", lang="en")
    assert english.description.startswith("Long enough")
    assert "description" not in english.untranslated

    german = load_file(path, pack="secrets", lang="de")
    assert german.description.startswith("Lang genug")
    assert "description" not in german.untranslated
    # The rationale has no translation, so it falls back and says so.
    assert "rationale" in german.untranslated


def test_the_engine_always_reads_english(rules: list[Rule]) -> None:
    """A finding's text goes into a case database that has one language, so the engine does
    not get to pick. Only the documentation generator loads a translation."""
    for rule in rules:
        assert load_file(rule.path, pack=rule.pack).description == rule.description


# ------------------------------------- a record nobody has mapped, and what sees it

UNMAPPED_PROBLEM = (
    "this record came out of a protocol buffer with no schema, so the record is returned "
    "uninterpreted"
)

COMMAND_RULE = """
id: AFX-DANGEROUSCOMMANDS-901
pack: dangerous_commands
title: A test rule about commands
severity: low
description: A rule that says which kind of event it is about and searches whole-record text.
rationale: >
  It exists for the tests below, which are about which events a rule with a kind
  restriction is allowed to see.
applies_to:
  kinds: [command.exec]
match:
  field: event_text
  contains: rm -rf /
tests:
  - name: a command
    match: true
    event:
      kind: command.exec
      payload: {text: "rm -rf /"}
  - name: something else
    match: false
    event:
      kind: command.exec
      payload: {text: "ls"}
"""


def unmapped_view(text: str, *, mapped: bool = False, unreadable: bool = False) -> Any:
    """One record as a rule sees it, in the three states this distinction is about."""
    if mapped:
        problem = None
    elif unreadable:
        problem = "the line did not decode as UTF-8"
    else:
        problem = UNMAPPED_PROBLEM
    return rule_testing.view(
        {
            "kind": "unparsed.record",
            "agent": "windsurf",
            "parse_problem": problem,
            "raw": {"f2": text},
        }
    )


def command_rule(tmp_path: Path) -> Rule:
    path = tmp_path / "AFX-DANGEROUSCOMMANDS-901.yaml"
    path.write_text(COMMAND_RULE, encoding="utf-8")
    return load_file(path)


def test_a_rule_about_one_kind_still_sees_a_record_nobody_has_mapped(tmp_path: Path) -> None:
    """The case this project cannot afford to get wrong. For several agents the only copy
    of a conversation on the endpoint is in a format nothing has a schema for, so those
    records are filed under unparsed.record: not because they are not commands, but
    because nobody could establish what they are. A pack that skipped them would report
    nothing about exactly the evidence those cases have left."""
    rule = command_rule(tmp_path)
    assert rule.matches(unmapped_view("rm -rf /var/log"))


def test_a_record_nothing_could_read_is_not_treated_as_content(tmp_path: Path) -> None:
    """The other half of the same distinction. A line that would not decode is a defect in
    the evidence, and matching a pattern in the bytes that survived it would report a
    command out of a damaged record."""
    rule = command_rule(tmp_path)
    assert not rule.matches(unmapped_view("rm -rf /var/log", unreadable=True))


def test_a_mapped_event_of_another_kind_is_still_skipped(tmp_path: Path) -> None:
    """The kind restriction keeps its meaning where the kind is known: a rule about
    commands does not look at a prompt that mentions one."""
    rule = command_rule(tmp_path)
    prompt = rule_testing.view({"kind": "user.prompt", "payload": {"text": "rm -rf /"}})
    assert not rule.matches(prompt)


def test_the_finding_says_the_kind_of_such_a_record_is_unknown(tmp_path: Path) -> None:
    """Without it a findings list reads as "the agent ran this", and what is established
    is only that the text is in the file."""
    from agentforensics.rules.engine import _summary

    rule = command_rule(tmp_path)
    view = unmapped_view("rm -rf /var/log")
    summary = _summary(rule, [view], {"event_text": ["rm -rf /var/log"]})
    assert "nobody has mapped" in summary
    assert "has not been established" in summary


def test_a_summary_of_a_mapped_event_says_nothing_of_the_sort(tmp_path: Path) -> None:
    from agentforensics.rules.engine import _summary

    rule = command_rule(tmp_path)
    view = rule_testing.view({"kind": "command.exec", "payload": {"text": "rm -rf /"}})
    assert "nobody has mapped" not in _summary(rule, [view], {"event_text": ["rm -rf /"]})


def test_a_summary_stays_on_one_line(tmp_path: Path) -> None:
    """A whole-record text view can be a screenful, and a findings list is read by
    scanning it."""
    from agentforensics.rules.engine import _summary

    rule = command_rule(tmp_path)
    view = rule_testing.view({"kind": "command.exec", "payload": {"text": "rm -rf /"}})
    summary = _summary(rule, [view], {"event_text": ["a\nb\n" + "x" * 500]})
    assert "\n" not in summary
    assert " ..." in summary


def test_the_generated_rule_is_current_with_the_catalogue() -> None:
    """The one rule here that is written by a script rather than by a person.

    It names sixty-odd environment variables the catalogue records as changing where an
    agent writes or whether it writes, and a stale copy of that list is a rule that quietly
    stops covering the agent somebody added last week. CI checks this too; it is here so a
    contributor who edits the catalogue finds out from the test suite rather than from a
    pipeline.
    """
    import subprocess
    import sys

    repo = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, str(repo / "scripts" / "gen_relocation_rule.py"), "--check"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_generated_rule_says_it_is_generated() -> None:
    """A generated file that does not say so gets hand-edited, and the edit disappears at
    the next run with nobody the wiser."""
    text = (
        Path(__file__).resolve().parents[2]
        / "rules"
        / "collection_integrity"
        / "AFX-COLLECTIONINTEGRITY-001.yaml"
    ).read_text(encoding="utf-8")
    assert text.startswith("# GENERATED by scripts/gen_relocation_rule.py")
    # And it states what it leaves out, because an exclusion nobody can see is a silent
    # narrowing of a detection.
    assert "Deliberately excluded" in text


# ------------------------------- a group judged by how many different things are in it

DISTINCT_RULE = """
id: AFX-COLLECTIONINTEGRITY-900
pack: collection_integrity
title: A rule used by the distinct-count engine tests
severity: low
description: Fires when one folder appears under more than one agent, for the tests.
rationale: Long enough to satisfy the schema, and it exists only to exercise distinct.
applies_to:
  kinds: [config.snapshot]
match:
  field: project_path
  exists: true
aggregate:
  group_by: [project_path]
  min_count: 2
  distinct: agent
  distinct_gte: 2
tests:
  - name: a snapshot that names a folder
    match: true
    event: {kind: config.snapshot, project_path: /repos/proj}
  - name: a snapshot that names none
    match: false
    event: {kind: config.snapshot}
"""


def two_product_case(tmp_path: Path, agents: list[str | None]) -> Case:
    """One folder, one event per entry in `agents`, each under the agent named."""
    from agentforensics.model import BundleRecord
    from agentforensics.model.event import Event, Provenance

    case = Case.open(tmp_path / "distinct.sqlite")
    case.add_bundle(BundleRecord(bundle_uuid="b1", source_kind="directory", source_path="/x"))
    case.add_events(
        [
            Event(
                kind="config.snapshot",
                provenance=Provenance("b1", f"/x/{index}/state.vscdb", "aa", None, "row:1"),
                agent=agent or "unknown",
                raw={},
                ts_utc=None,
                ts_precision="absent",
                ts_source=None,
                actor="system",
                user="alice",
                project_path="/Users/alice/repos/proj",
                payload={"key": "k", "text": "v"},
            )
            for index, agent in enumerate(agents)
        ]
    )
    return case


def test_a_distinct_count_does_not_fire_on_one_product_alone(tmp_path: Path) -> None:
    """The whole reason the option exists. Twenty rows of one product in one folder is
    every developer machine; one row each from two products in one folder is the finding,
    and a count of events cannot tell them apart."""
    write(
        tmp_path / "rules",
        "collection_integrity",
        "AFX-COLLECTIONINTEGRITY-900.yaml",
        DISTINCT_RULE,
    )
    rules = load(tmp_path / "rules")
    case = two_product_case(tmp_path, ["cursor", "cursor", "cursor"])
    report = scan(case, rules, store=False)
    case.close()

    assert not report.findings


def test_a_distinct_count_fires_when_the_group_holds_two_of_them(tmp_path: Path) -> None:
    write(
        tmp_path / "rules",
        "collection_integrity",
        "AFX-COLLECTIONINTEGRITY-900.yaml",
        DISTINCT_RULE,
    )
    rules = load(tmp_path / "rules")
    case = two_product_case(tmp_path, ["cursor", "windsurf"])
    report = scan(case, rules, store=False)
    case.close()

    assert len(report.findings) == 1
    assert len(report.findings[0].event_ids) == 2


def test_an_absent_value_counts_as_one_of_its_own(tmp_path: Path) -> None:
    """Dropping the events that did not say would turn "one product, and some rows that did
    not say" into "one product", which is a smaller claim than the evidence supports. The
    finding is then somebody's to read rather than the engine's to suppress."""
    write(
        tmp_path / "rules",
        "collection_integrity",
        "AFX-COLLECTIONINTEGRITY-900.yaml",
        DISTINCT_RULE,
    )
    rules = load(tmp_path / "rules")
    case = two_product_case(tmp_path, ["cursor", None])
    report = scan(case, rules, store=False)
    case.close()

    assert len(report.findings) == 1


def test_a_distinct_field_without_a_threshold_is_refused(tmp_path: Path) -> None:
    """A field named with no threshold would silently do nothing, which is the kind of
    half-written rule that makes a pack untrustworthy."""
    body = DISTINCT_RULE.replace("  distinct_gte: 2\n", "")
    write(tmp_path / "rules", "collection_integrity", "AFX-COLLECTIONINTEGRITY-900.yaml", body)
    with pytest.raises(RuleError):
        load(tmp_path / "rules")


def test_a_threshold_without_a_field_is_refused(tmp_path: Path) -> None:
    body = DISTINCT_RULE.replace("  distinct: agent\n", "")
    write(tmp_path / "rules", "collection_integrity", "AFX-COLLECTIONINTEGRITY-900.yaml", body)
    with pytest.raises(RuleError):
        load(tmp_path / "rules")


def test_the_cross_product_rule_fires_from_the_filesystem_up(tmp_path: Path) -> None:
    """The shipped rule, over a profile on disk, through the catalogue and the parsers.

    Its inline tests can only show that the condition matches one event, and this rule is
    not about one event: it is about a group holding two products. The path it depends on
    has four places to break silently, and two of them already had. The catalogue has to
    claim the file beside each store for this operating system; the matcher has to attribute
    both trees; the parser has to resolve the folder out of that file; and the engine has to
    count the products rather than the rows. A test over constructed events would pass with
    any of those broken.

    Both directions, because the first is what makes the rule true and the second is what
    keeps it from firing on every developer machine.
    """
    import sqlite3

    from agentforensics.catalog import load_catalogue
    from agentforensics.ingest import ingest

    schema = (
        "CREATE TABLE IF NOT EXISTS ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)"
    )
    folder = "file:///home/alice/repos/proj"

    def profile(home: Path, products: tuple[str, ...]) -> Path:
        for product in products:
            directory = home / ".config" / product / "User" / "workspaceStorage" / "b4af02248189"
            directory.mkdir(parents=True)
            (directory / "workspace.json").write_text(f'{{"folder": "{folder}"}}')
            connection = sqlite3.connect(directory / "state.vscdb")
            try:
                connection.execute(schema)
                connection.execute("INSERT INTO ItemTable VALUES ('aiService.prompts', '[]')")
                connection.commit()
            finally:
                connection.close()
        return home

    root = Path(__file__).resolve().parents[2]
    catalogue = load_catalogue(root / "catalog")
    rules = [rule for rule in load(root / "rules") if rule.id == "AFX-COLLECTIONINTEGRITY-004"]
    assert rules, "the shipped rule this test is about"

    def findings(products: tuple[str, ...], name: str) -> list:
        home = profile(tmp_path / name / "alice", products)
        with Case.open(tmp_path / f"{name}.db") as case:
            ingest(case, home, catalogue)
            return scan(case, rules, store=False).findings

    alone = findings(("Cursor",), "one")
    assert not alone, "one product in one folder is every developer machine, not a finding"

    both = findings(("Cursor", "Devin"), "two")
    assert len(both) == 1, f"one folder in two products is one finding, got {len(both)}"
    assert both[0].matched == {"project_path": ["/home/alice/repos/proj"]}, (
        "the folder the finding is about, resolved out of the file beside each store "
        "rather than out of the directory name, which is not a digest of it"
    )
    # Three events per store carry the folder: the store's own inventory, its one row, and
    # the workspace file itself. The rule groups them and counts the products, not the rows.
    assert len(both[0].event_ids) == 6
