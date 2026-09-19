"""The Velociraptor artifact that normalizes on the endpoint.

These read the generated artifact as text and as YAML. They cannot tell whether the VQL
does the right thing at run time, which is what `scripts/check_velociraptor_vql.py` is for;
what they can do is run everywhere, on every commit, and hold the properties that do not
need an engine: that the query parses as YAML, that every normalizer emits the same set of
columns, that the mapping has not drifted from the Python parsers, and that the honesty
rules this artifact is built around are still in the file.

The last group is the point. An artifact that reads less than it appears to is the failure
this project exists to prevent, and three of these tests exist because the engine actually
behaved that way: `parse_jsonl` skips a line it cannot decode, a buffered line reader stops
at a long line and takes the rest of the file with it, and `count()` accumulates across a
`foreach` so the second file's first record gets numbered after the first file's last.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from agentforensics.catalog import Catalogue, load_catalogue
from agentforensics.exporters import velociraptor_unified as unified
from agentforensics.exporters.velociraptor_unified import (
    CATEGORIES,
    GENERIC,
    MAPPERS,
    NOT_NORMALIZED,
    PRODUCER,
    UNINTERPRETED,
    UNINTERPRETED_FORMATS,
    Target,
    UnsafeTarget,
    render,
)
from agentforensics.parsers import PARSERS
from agentforensics.unified import schema

REPO_ROOT = Path(__file__).resolve().parents[2]

# The record fields, in the order every normalizer has to emit them. Taken from the schema
# rather than written out, so the artifact and the format cannot disagree about the shape.
ENVELOPE = (
    "v",
    "agent",
    "kind",
    "ts_utc",
    "ts_precision",
    "ts_source",
    "actor",
    "client",
    "host",
    "user",
    "session_id",
    "project_path",
    "git_branch",
    "payload",
    "parse_problem",
    "provenance",
    "raw",
    "producer",
)


@pytest.fixture(scope="module")
def catalogue() -> Catalogue:
    return load_catalogue(REPO_ROOT / "catalog")


@pytest.fixture(scope="module")
def artifact(catalogue: Catalogue) -> dict:
    (rendered,) = render(catalogue)
    return dict(yaml.safe_load(rendered.text))


@pytest.fixture(scope="module")
def committed() -> dict:
    """The file in the repository, as opposed to a fresh render.

    Read separately because the staleness check is a different guarantee from the content
    checks: a correct generator with a stale committed file gives an operator a rule that
    searches last month's locations.
    """
    path = (
        REPO_ROOT
        / "exporters"
        / "generated"
        / "velociraptor"
        / "Custom.Forensics.AIAgents.UnifiedLog.yaml"
    )
    return dict(yaml.safe_load(path.read_text(encoding="utf-8")))


def queries(artifact: dict) -> dict[str, str]:
    return {source["name"]: str(source["query"]) for source in artifact["sources"]}


def code(query: str) -> str:
    """A query with its comments removed.

    Needed because the query explains at length why it does not call `parse_jsonl`, and a
    test looking for that call would find the explanation.
    """
    return "\n".join(line for line in query.splitlines() if not line.strip().startswith("--"))


# --------------------------------------------------------------------- structure


def test_the_artifact_is_valid_yaml_with_a_source_per_platform(artifact: dict) -> None:
    assert artifact["name"].endswith(".UnifiedLog")
    assert artifact["type"] == "CLIENT"
    assert sorted(queries(artifact)) == ["linux", "macos", "windows"]


def test_every_source_has_a_precondition_naming_its_platform(artifact: dict) -> None:
    """Without one, the Windows globs run on macOS and find nothing, which reads as a host
    with no agents on it."""
    expected = {"windows": "'windows'", "macos": "'darwin'", "linux": "'linux'"}
    for source in artifact["sources"]:
        assert expected[source["name"]] in source["precondition"]


def test_the_committed_file_matches_a_fresh_render(artifact: dict, committed: dict) -> None:
    """Checked here as well as by the generator's own --check, because this is the one that
    runs in every contributor's test suite."""
    assert committed == artifact


# ------------------------------------------------------------- the record shape


def test_every_normalizer_emits_the_whole_envelope(artifact: dict) -> None:
    """One column spelled differently in one normalizer would be a field that is silently
    absent for one agent, which is the kind of gap nobody notices until a case needs it."""
    for name, query in queries(artifact).items():
        blocks = re.findall(r"^\s*1 AS v,(.*?)(?=^\s*(?:LET|SELECT|--|$))", query, re.S | re.M)
        assert blocks, f"{name}: no record-emitting SELECT found at all"
        for block in blocks:
            emitted = re.findall(r"\bAS (\w+)", "1 AS v," + block)
            missing = [field for field in ENVELOPE if field not in emitted]
            assert not missing, f"{name}: a normalizer does not emit {missing}"


def test_every_record_carries_the_producer_and_its_version(artifact: dict) -> None:
    """So a case can be asked which version of this query read a file, and two collections
    months apart can be told apart."""
    for query in queries(artifact).values():
        assert f"'{PRODUCER}' AS producer" in query
    assert PRODUCER.endswith("/1")


def test_no_record_claims_an_event_id(artifact: dict) -> None:
    """It is derived from provenance and the kind, and a reader recomputes it, so emitting
    one here would create something to disagree with and nothing to gain."""
    for query in queries(artifact).values():
        assert "AS event_id" not in query


def test_the_envelope_fields_are_the_schema_fields() -> None:
    """The list this test file checks against is not allowed to drift from the format."""
    allowed = set(schema()["properties"]) - {"event_id"}
    assert set(ENVELOPE) == allowed


# ------------------------------------------------------------- the honesty rules


def test_the_query_never_uses_parse_jsonl(artifact: dict) -> None:
    """The plugin skips a line it cannot decode, leaving only a deduplicated note in the
    collection log. A skipped line reads as a line that was never there, which is exactly
    what a truncated or deliberately corrupted record would hide behind."""
    for name, query in queries(artifact).items():
        assert "parse_jsonl" not in code(query), (
            f"{name}: parse_jsonl silently drops a line it cannot read, so this artifact "
            "must decode lines itself"
        )
        assert "parse_lines" in query


def test_a_line_that_does_not_decode_still_becomes_a_row(artifact: dict) -> None:
    for name, query in queries(artifact).items():
        assert "LET Unreadable(" in query, f"{name}: no normalizer for an unreadable record"
        assert "'unparsed.record' AS kind" in query
        # Every mapper has to route what it could not map into it, not drop it.
        for mapper in sorted(set(MAPPERS.values())):
            stem = "".join(part.capitalize() for part in mapper.split("_"))
            assert f"{stem}Bad = Unreadable(" in query or f"{stem}" in query, (
                f"{name}: {mapper} has no branch for a record it cannot map"
            )


def test_the_query_checks_that_it_read_whole_files(artifact: dict) -> None:
    """parse_lines is a buffered scanner: a line longer than its buffer ends the scan and
    the rest of the file is simply absent. Agent transcripts carry multi-megabyte lines
    whenever a tool output was large, so a collection that returned half a transcript as
    though it were whole is a routine risk rather than an exotic one."""
    for name, query in queries(artifact).items():
        assert "LET BytesRead" in query, f"{name}: the query does not check its own reading"
        assert "Bytes + Lines < Size" in query
        assert "MaxLineSize" in query


def test_the_line_counter_is_per_file(artifact: dict) -> None:
    """count() accumulates in the scope's aggregator context, and inside a foreach that
    context is shared, so a counter written the obvious way numbers the second file's first
    line after the first file's last. A locator that names the wrong line is worse than no
    locator, because it reads as a fact. Calling a stored query gives a fresh context."""
    for name, query in queries(artifact).items():
        assert "LET NumberedLines(Path) = SELECT count() AS LineNumber" in query, (
            f"{name}: line numbers are not produced through a parameterised stored query, "
            "so they are shared across files"
        )
        # And the blank-line filter must not sit inside the counting query, because count()
        # runs after a WHERE in the same SELECT and would number records, not lines.
        counting = query.split("LET NumberedLines(Path) =", 1)[1].split("LET ", 1)[0]
        assert "WHERE" not in counting, (
            f"{name}: the line-counting query has a WHERE, which makes count() number the "
            "rows that survived it rather than the lines in the file"
        )


def test_a_file_nothing_can_read_is_still_reported(artifact: dict) -> None:
    """The difference between an agent that left nothing and a store nobody has read is the
    difference between two opposite conclusions."""
    for name, query in queries(artifact).items():
        assert "'artifact.fs' AS kind" in query, f"{name}: files are not reported at all"
        assert "LET FileRows" in query
        assert "larger than MaxFileSize" in query


def test_an_unverified_format_is_returned_uninterpreted_not_guessed(artifact: dict) -> None:
    """A mapping invented for a format nobody has read against its vendor is the same defect
    as an invented catalogue path: it produces output that looks like an answer."""
    for name, query in queries(artifact).items():
        assert "LET GenericRecords" in query, f"{name}: no branch for an unmapped agent log"
        assert "no verified mapping" in query


def test_join_over_a_possibly_absent_value_is_guarded(artifact: dict) -> None:
    """VQL's join() over a null returns the four-character string 'Null'. A record whose
    text or command read 'Null' would be a fabricated value sitting in evidence."""
    for name, query in queries(artifact).items():
        for helper in ("LET TextOf(Content) = if(condition=", "LET CommandOf(Value) = if("):
            assert helper in query, f"{name}: {helper} is missing its guard"


# ----------------------------------------------------- parity with the analyzer


def test_every_artifact_a_python_parser_claims_is_accounted_for(catalogue: Catalogue) -> None:
    """The two producers of this format read the same files, and where they cannot, the gap
    is written down.

    A format VQL cannot read line by line is a real limit: a whole JSON document and a
    directory with no stated extension are both outside what this query does. The invariant
    is therefore not that the two producers are equal, which would be a lie, but that every
    difference is either the generic normalizer, which returns every record uninterpreted
    and loses nothing, or an entry in UNINTERPRETED, which the generated artifact prints so
    an operator reads it before running a hunt rather than after."""
    claimed = {
        artifact.id
        for artifact in catalogue.artifacts
        if any(parser.handles(artifact.id) for parser in PARSERS)
    }
    in_scope = {artifact.id for artifact in catalogue.artifacts if artifact.category in CATEGORIES}
    by_id = {artifact.id: artifact for artifact in catalogue.artifacts}

    # An artifact the query cannot express a glob for at all, with the reason. The generated
    # artifact prints these in its own not-covered section, which an operator reads in the
    # same place as the list below, so a second entry there would be a worse statement of
    # the same limit: it would say the hunt returns the file, and for these it returns
    # nothing at all.
    unreachable = {skip.artifact_id for skip in render(catalogue)[0].skipped}

    unaccounted = []
    for artifact_id in sorted(claimed & in_scope):
        if artifact_id in MAPPERS or artifact_id in UNINTERPRETED or artifact_id in unreachable:
            continue
        artifact = by_id[artifact_id]
        # A format the query cannot read at all is named once for the format rather than
        # once per artifact, so that a store added to the catalogue later is covered by
        # the statement the operator already reads instead of becoming a silent gap.
        if artifact.format in UNINTERPRETED_FORMATS:
            continue
        # The generic normalizer covers a line-delimited log with no verified mapping, and
        # it returns every record, so it is not a gap. Anything else is one.
        mappers = {
            unified._mapper_for(artifact, glob)
            for os_name in ("linux", "macos", "windows")
            for glob in (unified._covered(artifact, os_name)[0] or [])
        }
        if mappers and mappers <= {GENERIC}:
            continue
        unaccounted.append(artifact_id)
    assert not unaccounted, (
        "a Python parser reads these, the Velociraptor artifact returns only the file, and "
        "nothing says so. Add a normalizer or name the gap in UNINTERPRETED: "
        f"{unaccounted}"
    )


def test_the_artifact_names_the_formats_it_does_not_interpret(catalogue: Catalogue) -> None:
    """A limit an operator cannot read before running a hunt is a limit they discover
    afterwards, from an empty result that looks like an agent nobody used."""
    (rendered,) = render(catalogue)
    text = rendered.text
    for artifact_id, reason in UNINTERPRETED.items():
        assert artifact_id in text, artifact_id
        assert reason in text, reason
    for fmt, reason in UNINTERPRETED_FORMATS.items():
        assert fmt in text, fmt
        assert reason in text, reason


def test_nothing_in_the_uninterpreted_list_is_invented(catalogue: Catalogue) -> None:
    """Both directions: an entry naming an artifact no parser reads would be describing a
    gap that does not exist, and one naming an artifact with a mapper would be wrong."""
    known = {artifact.id for artifact in catalogue.artifacts}
    for artifact_id in UNINTERPRETED:
        assert artifact_id in known, artifact_id
        assert artifact_id not in MAPPERS, artifact_id
        assert any(parser.handles(artifact_id) for parser in PARSERS), artifact_id

    formats = {artifact.format for artifact in catalogue.artifacts}
    for fmt in UNINTERPRETED_FORMATS:
        assert fmt in formats, fmt
        # A format declared uninterpreted while a mapper reads one of its artifacts would
        # tell an operator to collect a file the hunt already returns as records.
        for artifact in catalogue.artifacts:
            if artifact.format == fmt:
                assert artifact.id not in MAPPERS, artifact.id


def test_nothing_the_endpoint_query_reads_is_unread_by_the_analyzer(
    catalogue: Catalogue,
) -> None:
    """The asymmetry that was there for months, in the direction that costs the most.

    The generic normalizer returns every record of an unmapped line-delimited log, and for
    ten artifacts the analyzer had no reading at all, so the same file produced records in a
    fleet hunt and one `artifact.fs` event in a case. The primary route through this suite
    is the second one: collect on the endpoint, analyse in the lab. Returning less there
    than a hunt does is the failure the whole design is against, because a case showing
    nothing is read as a file that held nothing.

    So the rule is one line: whatever the query reads record by record, something here reads
    too. A format nobody has mapped is covered by `jsonl_generic`, the same way the query
    covers it, and a verified parser takes an artifact over from either of them.
    """
    unread = []
    for artifact in catalogue.artifacts:
        if artifact.category not in CATEGORIES:
            continue
        mappers = {
            unified._mapper_for(artifact, glob)
            for os_name in ("linux", "macos", "windows")
            for glob in (unified._covered(artifact, os_name)[0] or [])
        }
        if not mappers - {NOT_NORMALIZED}:
            continue
        if not any(parser.handles(artifact.id) for parser in PARSERS):
            unread.append(artifact.id)
    assert not unread, (
        "the endpoint query returns records for these and the analyzer returns nothing, so "
        "a case built from a collection says less than a hunt over the same endpoint: "
        f"{unread}"
    )


def test_no_vql_mapper_claims_an_artifact_no_parser_knows(catalogue: Catalogue) -> None:
    """The other direction. A mapper here with no parser behind it means nobody has read
    that format against its vendor, and the mapping is a guess."""
    known = {artifact.id for artifact in catalogue.artifacts}
    for artifact_id in MAPPERS:
        assert artifact_id in known, f"{artifact_id} is not a catalogue entry"
        assert any(parser.handles(artifact_id) for parser in PARSERS), (
            f"{artifact_id} has a VQL mapping and no Python parser, so the mapping rests on "
            "nothing that was checked against a vendor"
        )


# ------------------------------------------------------------------- the globs


def test_every_in_scope_artifact_is_globbed_or_declared(
    catalogue: Catalogue, artifact: dict, committed: dict
) -> None:
    """The rule the whole exporter package exists for, applied to this artifact's own scope."""
    (rendered,) = render(catalogue)
    mentioned = set(re.findall(r"\b([a-z][a-z0-9_]*\.[a-z][a-z0-9_]*)\b", rendered.text))
    mentioned.update(skip.artifact_id for skip in rendered.skipped)
    missing = sorted(
        item.id
        for item in catalogue.artifacts
        if item.category in CATEGORIES and item.id not in mentioned
    )
    assert not missing, f"neither globbed nor declared: {missing}"


def test_the_header_states_what_is_out_of_scope(catalogue: Catalogue) -> None:
    """A reader has to be able to tell a deliberate scope from an accidental gap."""
    (rendered,) = render(catalogue)
    assert "Scope: the" in rendered.text
    assert " and ".join(CATEGORIES) in rendered.text
    assert "Collect" in rendered.text, "the header does not point at the artifact that does"


def test_a_subtree_glob_is_never_read_line_by_line(artifact: dict) -> None:
    """A store catalogued as a directory holds SQLite databases and compressed copies next
    to its logs. Reading that tree with a line reader would read a multi-gigabyte binary one
    line at a time, on a live endpoint, for nothing."""
    for name, query in queries(artifact).items():
        for line in query.splitlines():
            parts = line.strip().split(",")
            if len(parts) < 4 or parts[0] in ("agent",) or "." not in parts[1]:
                continue
            mapper, glob = parts[2], ",".join(parts[3:])
            if mapper in (NOT_NORMALIZED, "glob"):
                continue
            assert not glob.rstrip("/").endswith(("**", "/*")), (
                f"{name}: {glob} is a subtree and would be read line by line by {mapper}"
            )


def test_a_mapped_store_catalogued_as_a_directory_is_narrowed_to_its_logs(
    artifact: dict,
) -> None:
    """Codex is the case this exists for: the vendor documents the store as a directory, the
    rollouts sit under a dated tree inside it, and refusing the subtree outright would have
    left the Codex conversation out of every collection."""
    for name, query in queries(artifact).items():
        rollouts = [line for line in query.splitlines() if "codex.rollouts,codex_rollout," in line]
        assert rollouts, f"{name}: the Codex rollouts are not read at all"
        assert all(line.rstrip().endswith("/**/*.jsonl") for line in rollouts), rollouts


def test_one_store_is_not_globbed_twice(artifact: dict) -> None:
    """Two overlapping globs would return every record of that store twice, and a log that
    reports one prompt as two prompts is a log that cannot be counted."""
    for name, query in queries(artifact).items():
        rows = [
            line.strip()
            for line in query.splitlines()
            if line.strip().count(",") >= 3 and not line.strip().startswith(("--", "LET", "SELECT"))
        ]
        globs = [
            row.split(",", 3)[3] for row in rows if row.split(",", 3)[3].startswith(("/", "C"))
        ]
        assert len(globs) == len(set(globs)), f"{name}: a glob is listed twice"


# ------------------------------------------------- the data block cannot break


def test_a_value_that_would_shift_a_column_is_refused() -> None:
    """The block is CSV inside a VQL string. A comma in a path would not corrupt one row, it
    would shift every column after it, and a shifted column means globbing the wrong path
    under the wrong agent's name."""
    for value in (",", '"', "'''", "\n"):
        with pytest.raises(UnsafeTarget):
            unified._check(Target("agent", "a.b", GENERIC, f"/home/*/x{value}y"))


def test_a_value_with_padding_is_refused() -> None:
    """Velociraptor's parse_csv trims leading whitespace in every field, so a path that
    began with a space would search somewhere other than the catalogue says."""
    with pytest.raises(UnsafeTarget):
        unified._check(Target("agent", "a.b", GENERIC, " /home/*/x"))


def test_the_catalogue_as_it_stands_passes_that_check(catalogue: Catalogue) -> None:
    """Which is what makes the refusal above a guard rather than a wall."""
    render(catalogue)


def test_the_generated_if_chains_are_balanced() -> None:
    """Generated rather than typed, because VQL has no case expression and a mapping over
    eight record types is eight closing parentheses in a row. Hand-counting them is how this
    shipped a query that did not parse, once."""
    chain = unified._if_chain([("a", "1"), ("b", "2"), ("c", "3")], "NULL")
    assert chain.count("if(") == 3
    assert chain.count("(") == chain.count(")")
    assert chain.startswith("if(condition=a, then=1,")
    assert chain.endswith("else=NULL)))")


def test_the_query_text_is_balanced(artifact: dict) -> None:
    """A cheap check that catches the commonest generation defect without an engine. Quotes
    are left out of it on purpose: the data block is one long single-quoted string and
    counting quotes across it says nothing."""
    for name, query in queries(artifact).items():
        stripped = re.sub(r"'''.*?'''", "''", query, flags=re.S)
        stripped = "\n".join(
            line for line in stripped.splitlines() if not line.strip().startswith("--")
        )
        for opener, closer in (("(", ")"), ("{", "}"), ("[", "]")):
            assert stripped.count(opener) == stripped.count(closer), (
                f"{name}: unbalanced {opener}{closer}"
            )


def test_codex_event_msg_is_read_the_same_way_by_both_producers(
    artifact: dict, tmp_path: Path
) -> None:
    """One format, two producers, and they have to agree on which records exist.

    A Codex event_msg record mirrors a response_item, so neither producer maps it as a turn
    of the conversation, and both keep it as one config.snapshot row per line with the line
    itself in raw. Making the same choice in both is the point: the CI job that runs this
    query against a synthetic profile compares its reading with the analyzer's record for
    record, and a record only one of them emits surfaces there as a disagreement between
    the two. That is how this was found, with the analyzer counting these records by subtype
    and discarding their content while the query kept every one of them.
    """
    import json

    from agentforensics.parsers import for_artifact
    from agentforensics.parsers.base import ParseContext

    query = code(queries(artifact)["linux"])
    assert "Rec_.type = 'event_msg'" in query
    assert "mirrored_event_msg=Rec.type = 'event_msg'" in query

    rollout = tmp_path / "rollout-2026-01-01T00-00-00-s1.jsonl"
    rollout.write_text(
        json.dumps({"timestamp": "2026-01-01T00:00:00Z", "type": "session_meta", "payload": {}})
        + "\n"
        + json.dumps(
            {
                "timestamp": "2026-01-01T00:00:01Z",
                "type": "event_msg",
                "payload": {"type": "agent_message", "message": "x"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    parser = for_artifact("codex.rollouts")
    assert parser is not None
    events = list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path="/home/alice/.codex/sessions/" + rollout.name,
                local_path=rollout,
                sha256="aa",
                artifact_id="codex.rollouts",
                agent="codex",
                user="alice",
            )
        )
    )
    mirrors = [event for event in events if event.payload.get("mirrored_event_msg")]
    assert [event.kind for event in mirrors] == ["config.snapshot"]
    assert mirrors[0].provenance.locator == "line:2"
