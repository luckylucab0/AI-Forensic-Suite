"""The local web UI: the projections, and the hardening list ADR 0006 made part of it.

The hardening is tested one item at a time on purpose. ADR 0006 says in as many words that
the list is hand-maintained and the part most likely to rot, and a list nobody checks is a
list that is wrong by the third change to the file. Each test below names the item it
pins, so a failure says which property was lost rather than only that a request returned
something unexpected.

Requests go through http.client rather than urllib, for two reasons. It sends exactly the
headers a test asks for, which is what lets the Host and Origin checks be exercised at all,
and it never consults a proxy, which matters because the point of this server is that
nothing leaves the machine.
"""

from __future__ import annotations

import http.client
import json
import re
import socket
import sqlite3
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from agentforensics.catalog import load_catalogue
from agentforensics.ingest import ingest
from agentforensics.model import Case, CaseError
from agentforensics.rules import load as load_rules
from agentforensics.rules import scan
from agentforensics.webui import api
from agentforensics.webui import server as webui

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests" / "fixtures"))

from generate import build_home  # noqa: E402

TOKEN = "t" * 24


@pytest.fixture(scope="module")
def case_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One synthetic case, built once: ingested from a synthetic profile and scanned.

    Scanned as well as ingested because half of what the web UI has to show is the findings
    and the fact of a scan having run, and a case that was never scanned cannot demonstrate
    the difference between those two.
    """
    root = tmp_path_factory.mktemp("webui")
    home = root / "home"
    build_home(home)
    path = root / "case.db"
    catalogue = load_catalogue(REPO_ROOT / "catalog")
    with Case.open(path) as case, case.transaction():
        ingest(case, home, catalogue)
    with Case.open(path) as case:
        scan(case, load_rules(REPO_ROOT / "rules"))
    return path


@pytest.fixture(scope="module")
def case(case_path: Path) -> Iterator[Case]:
    with Case.open(case_path, create=False, read_only=True) as opened:
        yield opened


class Client:
    """A minimal HTTP client against one running server."""

    def __init__(self, port: int, token: str) -> None:
        self.port = port
        self.token = token

    def request(
        self,
        path: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        *,
        raw: bool = False,
    ) -> tuple[int, dict[str, str], bytes]:
        target = path if raw else f"/{self.token}{path}"
        sent = {"Host": f"127.0.0.1:{self.port}"}
        sent.update(headers or {})
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.request(method, target, headers=sent)
            response = connection.getresponse()
            body = response.read()
            return response.status, dict(response.getheaders()), body
        finally:
            connection.close()

    def json(self, path: str) -> dict:
        status, _, body = self.request(path)
        assert status == 200, (path, status, body[:200])
        decoded = json.loads(body)
        assert isinstance(decoded, dict)
        return decoded


@pytest.fixture(scope="module")
def client(case_path: Path) -> Iterator[Client]:
    """A server on a port the kernel picks, so the suite never collides with a real one."""
    server, ctx = webui.build(case_path, port=0, token=TOKEN)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield Client(int(server.server_address[1]), ctx.token)
    finally:
        server.shutdown()
        server.server_close()


# --------------------------------------------------------------------- projections


def test_the_case_summary_carries_the_counts_that_qualify_it(case: Case) -> None:
    """The four uncomfortable counts are in every summary, not only when they are non-zero.

    A summary that showed them conditionally would read as completeness on the cases where
    they happen to be absent, and an analyst cannot tell a case with nothing missing from
    one that does not mention what is.
    """
    summary = api.case_summary(case)
    for key in (
        "artifacts_unparsed",
        "events_unparsed",
        # The part of the unparsed records that was read and has no mapping yet. Without it
        # a screen can only call all of them unreadable, which on a case holding a store
        # nobody has a schema for is wrong about nearly every one of them.
        "events_uninterpreted",
        "events_without_timestamp",
        "collection_gaps",
    ):
        assert key in summary["counts"]
    assert summary["afx_api"] == api.API_VERSION
    assert summary["counts"]["events"] > 0
    assert summary["scanned"] is True


def test_the_summary_says_which_artifacts_the_unread_records_are_in(case: Case) -> None:
    """The counts above are a total, and a total cannot be acted on: one debug log and
    every transcript on the machine produce the same number and call for opposite next
    steps. The breakdown is what turns the number into a next step."""
    summary = api.case_summary(case)
    unread = summary["unread"]
    assert unread["total"] >= 1, "the fixture case holds records nobody read"
    assert unread["listed"] == len(unread["artifacts"])
    for row in unread["artifacts"]:
        assert row["unreadable"] or row["uninterpreted"], (
            "an artifact with nothing wrong with it would be noise in the view somebody "
            "reads to find the holes"
        )
        assert row["files"] >= 1


def test_every_event_in_the_case_belongs_to_exactly_one_session(case: Case) -> None:
    """The property the whole session view rests on. An event in no group would be an event
    an analyst can only reach through the timeline, and one in two groups would be an event
    shown twice in a transcript, which reads as the agent having done it twice."""
    groups = api.sessions(case)
    total = sum(group["events"] for group in groups)
    counts = case.counts()
    assert total == counts["events"]
    assert len({group["key"] for group in groups}) == len(groups)


def test_a_session_key_is_derived_and_therefore_stable(case: Case) -> None:
    """Two reads of the same case produce the same keys, which is what lets a link into a
    session survive a re-ingest of the same bundle."""
    first = [group["key"] for group in api.sessions(case)]
    second = [group["key"] for group in api.sessions(case)]
    assert first == second


def test_an_absent_value_and_an_empty_one_do_not_collide(case: Case) -> None:
    """A session id that is null and one that is the empty string are different claims, and
    two groups colliding onto one key would merge two sessions into one transcript."""
    rows = case.query(
        "SELECT 'a' AS agent, NULL AS host, NULL AS user, 0 AS files, "
        "       NULL AS project_path, NULL AS session_id"
    )
    empty = case.query(
        "SELECT 'a' AS agent, NULL AS host, NULL AS user, 0 AS files, "
        "       '' AS project_path, '' AS session_id"
    )
    assert api._group_key(rows[0]) != api._group_key(empty[0])


def test_the_filesystem_events_are_grouped_apart(case: Case) -> None:
    """One per collected file, and on a real collection they outnumber the conversation. In
    their own group they are still served, which matters because for a file with no
    internal timestamps they are the only temporal evidence there is."""
    groups = api.sessions(case)
    files = [group for group in groups if group["files"]]
    assert files, "the synthetic case has collected files, so it has filesystem events"
    for group in files:
        assert group["kinds"] == ["artifact.fs"]
    for group in groups:
        if not group["files"]:
            assert "artifact.fs" not in group["kinds"]


def test_a_session_page_is_a_unified_log(case: Case) -> None:
    """Served in the format `afx normalize` and the Velociraptor artifact write, so the
    viewer reads a case through the reader it already has. Validated against the schema
    file, which is the single definition all three producers are held to."""
    from agentforensics.unified import validator

    check = validator()
    group = next(group for group in api.sessions(case) if not group["files"])
    records, _ = api.session_records(case, group["key"], limit=50)
    assert records
    for record in records:
        check(record)


def test_a_session_is_paged_without_losing_or_repeating_a_record(case: Case) -> None:
    """Paging is the one place a projection can quietly drop evidence: an off-by-one in an
    offset loses a record per page, and the result still looks like a transcript."""
    group = max(api.sessions(case), key=lambda item: item["events"])
    whole, after = api.session_records(case, group["key"], limit=api.MAX_PAGE)
    assert after is None
    assert len(whole) == group["events"]

    collected: list[dict] = []
    offset: int | None = 0
    while offset is not None:
        page, offset = api.session_records(case, group["key"], offset=offset, limit=3)
        collected.extend(page)
    assert [record["event_id"] for record in collected] == [record["event_id"] for record in whole]


def test_an_unreadable_record_is_served_like_any_other(case: Case) -> None:
    """The records no parser could read are in the case as events, and they have to arrive
    at the viewer. A projection that skipped them would make a partly unreadable log look
    clean, which is the one failure this suite must not have."""
    unparsed = []
    for group in api.sessions(case):
        if "unparsed.record" not in group["kinds"]:
            continue
        records, _ = api.session_records(case, group["key"], limit=api.MAX_PAGE)
        unparsed.extend([r for r in records if r["kind"] == "unparsed.record"])
    assert unparsed, "the synthetic profile carries records nothing can parse"
    for record in unparsed:
        assert record["parse_problem"]
        assert record["raw"] is not None


def test_a_session_key_that_names_nothing_is_an_error(case: Case) -> None:
    with pytest.raises(api.ApiError):
        api.session_records(case, "0" * 32)


def test_the_timeline_is_the_same_rows_the_export_writes(case: Case) -> None:
    """One definition of a timeline row. Two would let the CSV attached to a report and the
    table on screen describe the same case differently."""
    from agentforensics.timeline import COLUMNS

    page = api.timeline(case, limit=25)
    assert page["rows"]
    for row in page["rows"]:
        assert set(row) == set(COLUMNS)
    # Undated first, the same reading of "in order" the exports use: an event with no
    # timestamp has an unknown position, not an early one.
    kinds = [row["ts_utc"] for row in page["rows"]]
    assert kinds == sorted(kinds, key=lambda value: (value is not None, value or ""))


def test_the_findings_carry_the_fact_of_a_scan_having_run(case: Case) -> None:
    found = api.findings(case)
    assert found["scanned"] is True
    assert found["scan_runs"]
    assert found["findings"], "the synthetic profile trips several of the shipped rules"
    for finding in found["findings"]:
        assert finding["event_ids"], "a finding an analyst cannot check is an opinion"
        assert finding["rule_sha256"]


def test_an_event_a_finding_rests_on_can_be_fetched(case: Case) -> None:
    finding = api.findings(case)["findings"][0]
    record = api.event_record(case, finding["event_ids"][0])
    assert record["event_id"] == finding["event_ids"][0]
    assert record["provenance"]["original_path"]


def test_the_instruction_view_lists_what_the_agents_were_told_to_obey(case: Case) -> None:
    view = api.instructions(case)

    assert view["instructions"], "the synthetic profile carries several instruction files"
    paths = {row["original_path"] for row in view["instructions"]}
    assert any(path.endswith("SKILL.md") for path in paths)
    skill = next(row for row in view["instructions"] if row["original_path"].endswith("SKILL.md"))
    # A skill that grants itself a shell is a permission change written as a document, so it
    # has to be readable from the instruction view and not only from the permissions one.
    assert skill["declared_tools"] == ["Bash", "Write"]
    hidden = next(row for row in view["instructions"] if row["hidden_characters"])
    assert any(entry["codepoint"] == "U+200B" for entry in hidden["hidden_characters"])
    assert view["counts"]["files"] == len(view["instructions"])


def test_an_instruction_recorded_somewhere_else_names_the_file_it_is(case: Case) -> None:
    """The row's own path says where this was found. It is not always the file that shaped
    the agent, and the difference is the whole point of the view.

    Continue records, per turn, which rule files applied to it, so the event comes out of a
    session file and names a rules file in the working copy. Shown only by the path it was
    found under, that row reads as a session file being an instruction, and the one thing an
    analyst came here for, which file shaped the turn, is not on the screen at all.
    """
    view = api.instructions(case)

    elsewhere = [row for row in view["instructions"] if row["instruction_is_elsewhere"]]

    assert elsewhere, "the synthetic profile records a rule that applied to a turn"
    row = elsewhere[0]
    assert row["instruction_paths"], "a row that says the file is elsewhere has to say where"
    assert not any(path == row["original_path"] for path in row["instruction_paths"])
    assert view["counts"]["recorded_elsewhere"] == len(elsewhere)


def test_an_instruction_file_names_itself_and_is_not_called_elsewhere(case: Case) -> None:
    """The other side of the same field, and the common case. A file the instruction parser
    read is its own instruction, so a view that flagged every row would be telling an
    analyst to check seventeen files for a difference that exists in one."""
    view = api.instructions(case)

    own = [
        row
        for row in view["instructions"]
        if row["original_path"].endswith("CLAUDE.md") and row["instruction_paths"]
    ]

    assert own
    assert all(row["instruction_is_elsewhere"] is False for row in own)


def test_the_instruction_view_says_it_is_not_a_system_prompt(case: Case) -> None:
    """The honesty guarantee of the whole view, pinned as a test because it is the one thing
    a reader would otherwise assume. The base prompt is compiled into the product or comes
    from the vendor's server, so it is not on the endpoint and not in the case, and a view
    that let somebody quote this as the system prompt would be worse than no view."""
    note = api.instructions(case)["note"]

    assert "not a system prompt" in note
    assert "not on the endpoint" in note


def test_a_scope_nothing_could_decide_is_unknown_and_says_why(case: Case) -> None:
    """This case is ingested from a plain tree, which records no working copies, so a
    project instruction file cannot be told from a profile one. The honest answer is unknown
    with the reason on the event, because the alternative reverses the finding about who
    instructed the agent."""
    view = api.instructions(case)
    rows = view["instructions"]

    unknown = [row for row in rows if row["scope"] == "unknown"]
    assert unknown, "a tree source records no working copies, so nothing here is decidable"
    assert all("unknown rather than assumed" in (row["scope_problem"] or "") for row in unknown)
    assert view["counts"]["scope_unknown"] == len(unknown)


def test_a_file_whose_scope_is_unknown_is_not_counted_as_unreadable(case: Case) -> None:
    """The two say opposite things about the same evidence.

    A file whose tier nobody could settle was read completely; a file that is unreadable
    was not. Carrying the first as a parse problem made every view in this project report
    that all seven instruction files in the synthetic profile had not been fully read, which
    is a statement about the quality of the evidence and it was false. A tool that reports
    sound evidence as unreadable teaches an analyst to skip the one case where it means it.
    """
    view = api.instructions(case)

    assert view["counts"]["scope_unknown"], "the fixture has files whose scope is unknown"
    assert view["counts"]["unreadable"] == 0, [
        row["parse_problem"] for row in view["instructions"] if row["parse_problem"]
    ]


def test_a_prompt_out_of_a_freed_page_is_shown_and_is_not_called_unreadable(case: Case) -> None:
    """The instruction surface has to show a prompt that is no longer in the library.

    One editor keeps its prompts in a store that never overwrites a page, so a prompt
    somebody deleted is still readable out of it, and it is part of the answer to what the
    agent was told to obey. What it must not do is sit here looking like a prompt that is
    in force, and what the view must not do is count it as a file it failed to read: the
    reading worked, and the sentence on the row is about where the record came from.
    """
    view = api.instructions(case)
    recovered = [row for row in view["instructions"] if row["recovery_note"]]

    assert recovered, "the synthetic profile holds a prompt that was deleted from a library"
    assert view["counts"]["recovered"] == len(recovered)
    assert view["counts"]["unreadable"] == 0
    for row in recovered:
        assert row["parse_problem"] is None
        assert "no longer points at" in row["recovery_note"]
    assert any("skip the review" in (row["preview"] or "") for row in recovered)


def test_a_preview_says_whether_it_is_the_whole_file(case: Case) -> None:
    """A preview mistaken for a whole file is a wrong reading of evidence, so the row says
    which it is rather than leaving it to be inferred from a length."""
    for row in api.instructions(case)["instructions"]:
        assert row["preview_is_whole_file"] == (row["chars"] <= api.PREVIEW)


def test_the_instruction_endpoint_is_served(client: Client) -> None:
    """Routed explicitly, because the route table has no fallback: an endpoint nobody added
    to it answers 404 however well the projection behind it works."""
    served = client.json("/api/instructions")

    assert served["afx_api"] == api.API_VERSION
    assert served["instructions"]
    assert "not a system prompt" in served["note"]


def test_the_corroboration_endpoint_is_served(client: Client) -> None:
    """Routed explicitly, for the reason the instruction endpoint is: no fallback."""
    served = client.json("/api/corroboration")

    assert served["afx_api"] == api.API_VERSION
    assert served["sessions"], "the synthetic profile has conversations"
    assert "lead and not a finding" in served["note"]


def test_the_artifact_list_separates_not_collected_from_not_read(case: Case) -> None:
    """The distinction the reliability of every other view depends on."""
    listed = api.artifacts(case)
    assert listed["artifacts"]
    assert any(
        entry["parse_status"] in ("unsupported", "failed", None) for entry in listed["artifacts"]
    )
    for entry in listed["artifacts"]:
        assert isinstance(entry["collected"], bool)


def test_a_transcript_set_aside_is_visible_as_the_same_bytes(case: Case) -> None:
    """The copy an agent leaves behind, named as what it is.

    Claude Code sets a transcript aside rather than deleting it, under a name its own
    session picker does not show. The copy is byte for byte the original, which the
    collection already recorded as a hash, so the list can say it without interpreting
    anything. Two questions turn on it: a conversation that survived a deletion is what an
    investigation is looking for, and a finding that appears twice for one event is one
    incident rather than two.
    """
    listed = api.artifacts(case)

    same = [entry for entry in listed["artifacts"] if entry["identical_to"]]

    assert same, "the synthetic profile holds a transcript that was set aside"
    assert listed["identical_files"] == len(same)
    # The relation is symmetric, because it is equality of bytes: a file that names another
    # has to be named by it, or the list would be telling two different stories about one
    # pair depending on which row an analyst read first.
    by_path = {entry["original_path"]: entry for entry in same}
    for entry in same:
        for other in entry["identical_to"]:
            assert entry["original_path"] in by_path[other]["identical_to"]
    assert any(
        any("superseded" in other or "orphaned" in other for other in entry["identical_to"])
        for entry in same
    )


def test_a_file_with_no_twin_says_nothing_rather_than_an_empty_claim(case: Case) -> None:
    """Most files have no copy, and a list that flagged every row would cost the flag its
    meaning. An uncollected file is never claimed to be identical to anything either: its
    content was not read, so there is no hash to compare."""
    listed = api.artifacts(case)

    assert any(not entry["identical_to"] for entry in listed["artifacts"])
    for entry in listed["artifacts"]:
        if not entry["collected"]:
            assert entry["identical_to"] == []


# ----------------------------------------------------------------------- hardening


def test_the_socket_binds_loopback_and_there_is_no_option_not_to(case_path: Path) -> None:
    """The first item on the list. A forensic case on a socket another machine can reach is
    a disclosure, so the address is a constant rather than a parameter."""
    server, _ = webui.build(case_path, port=0, token=TOKEN)
    try:
        assert server.server_address[0] == "127.0.0.1"
        assert webui.HOST == "127.0.0.1"
    finally:
        server.server_close()
    assert "host" not in webui.build.__annotations__


def test_nothing_is_served_without_the_token(client: Client) -> None:
    for path in ("/", "/index.html", "/api/case", "/api/projects", "/api/health"):
        status, _, _ = client.request(path, raw=True)
        assert status == 404, path
    status, _, _ = client.request("/" + "z" * 24 + "/api/case", raw=True)
    assert status == 404


def test_the_token_prefix_redirects_only_to_put_its_slash_on(client: Client) -> None:
    status, headers, _ = client.request(f"/{TOKEN}", raw=True)
    assert status == 308
    assert headers["Location"] == f"/{TOKEN}/"


def test_a_host_header_that_is_not_loopback_is_refused(client: Client) -> None:
    """The DNS rebinding check. A hostile page can resolve its own name to 127.0.0.1, but it
    still sends its own name in this header."""
    status, _, _ = client.request("/api/case", headers={"Host": "case.example.org"})
    assert status == 403
    status, _, _ = client.request("/api/case", headers={"Host": f"case.example.org:{client.port}"})
    assert status == 403


def test_a_cross_origin_request_is_refused(client: Client) -> None:
    status, _, _ = client.request("/api/case", headers={"Origin": "http://evil.example.org"})
    assert status == 403
    status, _, _ = client.request(
        "/api/case", headers={"Origin": f"http://127.0.0.1:{client.port}"}
    )
    assert status == 200


def test_only_get_and_head_exist(client: Client) -> None:
    for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
        status, headers, _ = client.request(
            "/api/case", method=method, headers={"Content-Length": "0"}
        )
        assert status == 405, method
        assert headers["Allow"] == "GET, HEAD"


def test_a_request_that_announces_a_body_is_refused_unread(client: Client) -> None:
    status, _, _ = client.request("/api/case", headers={"Content-Length": "5"})
    assert status == 413
    status, _, _ = client.request("/api/case", headers={"Transfer-Encoding": "chunked"})
    assert status == 411


def test_there_is_no_fallback_handler(client: Client) -> None:
    """Every path that is not in the table is a 404. Nothing is reachable by naming it,
    which is also why there is no directory listing to hide."""
    for path in (
        "/api",
        "/api/",
        "/api/case/",
        "/api/sessions",
        "/api/sessions/nope/events",
        "/../../etc/passwd",
        "/viewer/index.html",
        "/index.html/x",
    ):
        status, _, _ = client.request(path)
        assert status == 404, path
    # A query string is not part of the path and is not matched against the table. Stated
    # as its own case because the opposite reading, that anything after a question mark
    # could reach a route, is the mistake this test is here to rule out.
    status, _, _ = client.request("/api/health?x=1/../..")
    assert status == 200


def test_the_viewer_is_served_from_memory_and_not_from_a_path(client: Client) -> None:
    """There is no path to traverse because no request ever reaches the filesystem."""
    status, headers, body = client.request("/")
    assert status == 200
    assert headers["Content-Type"].startswith("text/html")
    assert b"<title>" in body
    # The same bytes, whatever the URL asked for, because there is only one byte string.
    assert client.request("/index.html")[2] == body


def test_every_response_carries_the_security_headers(client: Client) -> None:
    """Including the error ones. An error response is the first thing an attacker sees, and
    it used to be the one path that skipped these."""
    for path, method in (
        ("/", "GET"),
        ("/api/case", "GET"),
        ("/api/case", "HEAD"),
        ("/api/nope", "GET"),
        ("/api/case", "POST"),
    ):
        status, headers, _ = client.request(path, method=method, headers={"Content-Length": "0"})
        for name, value in webui.SECURITY_HEADERS:
            assert headers.get(name) == value, (path, method, name, status)


def test_the_server_header_names_nothing_but_this_tool(client: Client) -> None:
    """A banner naming the Python build is free reconnaissance for anything scanning the
    workstation's loopback interface."""
    _, headers, _ = client.request("/api/health")
    assert headers["Server"] == "afx"


def test_the_content_security_policy_forbids_reaching_off_this_server(client: Client) -> None:
    """The offline guarantee, enforced at the browser as well as at the socket."""
    policy = dict(webui.SECURITY_HEADERS)["Content-Security-Policy"]
    assert "default-src 'none'" in policy
    assert "connect-src 'self'" in policy
    for source in ("http:", "https:", "*"):
        assert f"src {source}" not in policy


def test_an_error_body_says_nothing_but_the_error(client: Client) -> None:
    status, _, body = client.request("/api/sessions/" + "0" * 32 + "/events")
    assert status == 404
    decoded = json.loads(body)
    assert set(decoded) == {"error", "status"}
    assert "Traceback" not in body.decode("utf-8")


def test_the_case_is_opened_read_only(case_path: Path) -> None:
    """Enforced by SQLite rather than promised by this code, so it holds even for a bug."""
    with (
        Case.open(case_path, create=False, read_only=True) as opened,
        pytest.raises(sqlite3.OperationalError),
    ):
        opened.query("DELETE FROM events")
    with pytest.raises(CaseError):
        Case.open(case_path.parent / "absent.db", create=False, read_only=True)


def test_the_viewer_bytes_are_hashed_and_reported(client: Client) -> None:
    """So that a screenshot can be attributed to a build, the same reason every event
    carries the hash of the file it came from."""
    import hashlib

    summary = client.json("/api/case")
    served = client.request("/")[2]
    assert summary["viewer_sha256"] == hashlib.sha256(served).hexdigest()


def test_the_startup_notice_names_the_token_and_the_binding(case_path: Path) -> None:
    server, ctx = webui.build(case_path, port=0, token=TOKEN)
    try:
        lines = "\n".join(webui.startup_lines(server, ctx))
    finally:
        server.server_close()
    assert TOKEN in lines
    assert "127.0.0.1" in lines
    assert "read-only" in lines


# -------------------------------------------------------------------- end to end


def test_a_case_is_readable_end_to_end_over_http(client: Client) -> None:
    """The whole path a browser takes: the marker, the session list, and one session's
    events as a unified log."""
    summary = client.json("/api/case")
    assert summary["afx_api"] == api.API_VERSION

    projects = client.json("/api/projects")["projects"]
    assert projects
    session = next(
        session for project in projects for session in project["sessions"] if not session["files"]
    )

    # Fetched at exactly the path the API handed out, relative to the token prefix the
    # viewer is served under. The server owns the URL shape; the browser only appends.
    status, headers, body = client.request("/" + session["path"])
    assert status == 200
    assert headers["Content-Type"].startswith("application/x-ndjson")
    records = [json.loads(line) for line in body.decode("utf-8").splitlines()]
    assert len(records) == int(headers["X-Afx-Records"])
    assert records and all(record["v"] == 1 for record in records)


def test_the_documented_screenshots_exist() -> None:
    """Every image the web UI documentation points at is in the repository.

    A broken image in a public README is the kind of thing nobody notices from a checkout,
    because the file is there locally right up until it is not committed. The images are
    regenerated with scripts/shot_webui.py.
    """
    import re

    missing = []
    for doc in (REPO_ROOT / "docs" / "WEBUI.md", REPO_ROOT / "docs" / "WEBUI.de.md"):
        text = doc.read_text(encoding="utf-8")
        for target in re.findall(r"!\[[^\]]*\]\(([^)]+)\)", text):
            if not (doc.parent / target).is_file():
                missing.append(f"{doc.name} -> {target}")
    for doc in (REPO_ROOT / "README.md", REPO_ROOT / "README.de.md"):
        text = doc.read_text(encoding="utf-8")
        for target in re.findall(r"!\[[^\]]*\]\(([^)]+)\)", text):
            if not (REPO_ROOT / target).is_file():
                missing.append(f"{doc.name} -> {target}")
    assert not missing, missing


@pytest.mark.viewer
def test_the_viewer_renders_a_served_session(client: Client, tmp_path: Path) -> None:
    """One session, fetched over the API and put through the viewer's own normalizer.

    This is the end of the chain the phase is judged on: a case, over HTTP, through the
    code that runs in the browser, into rows. Without it the API could be correct and the
    viewer still show an empty transcript, which is the failure mode that looks like no
    evidence.
    """
    import shutil

    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")

    projects = client.json("/api/projects")["projects"]
    # The largest session that holds a turn somebody typed. The three generic readers put
    # every unmapped store, log and document into the case as records with no session of
    # their own, and those group into one large per-agent row that is evidence rather than
    # a conversation. What this test is about is the viewer rendering a conversation, so it
    # asks for one.
    session = max(
        (
            session
            for project in projects
            for session in project["sessions"]
            if not session["files"] and "user.prompt" in session["kinds"]
        ),
        key=lambda item: item["events"],
    )
    status, _, body = client.request("/" + session["path"])
    assert status == 200
    log = tmp_path / "session.jsonl"
    log.write_bytes(body)

    script = tmp_path / "render.mjs"
    script.write_text(
        """
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
const html = fs.readFileSync(path.join(process.argv[2], 'viewer', 'index.html'), 'utf8');
const blocks = [...html.matchAll(/<script>([\\s\\S]*?)<\\/script>/g)].map((m) => m[1]);
let code = blocks[blocks.length - 1];
code = code.slice(0, code.indexOf('// ---------- boot ----------'));
const ctx = { console, JSON, Math, Object, Array, String, Number, Boolean, Set, Map,
              Promise, RegExp, Error, Date, URL, TextEncoder, window: {} };
vm.createContext(ctx);
vm.runInContext(code + ';globalThis.__api = { normalizeEvents, summarize, groupUnified };', ctx);
const records = fs.readFileSync(process.argv[3], 'utf8').split('\\n')
  .filter((line) => line.trim()).map((line) => JSON.parse(line));
const groups = ctx.__api.groupUnified(records);
const rows = ctx.__api.normalizeEvents(records, 'unified');
const summary = ctx.__api.summarize(rows);
console.log(JSON.stringify({
  records: records.length,
  groups: Object.keys(groups).length,
  rows: rows.length,
  userMsgs: summary.userMsgs,
  toolCalls: summary.toolCalls,
  unparsed: summary.unparsed,
  title: summary.title,
}));
""",
        encoding="utf-8",
    )
    out = subprocess.run(
        [node, str(script), str(REPO_ROOT), str(log)],
        capture_output=True,
        text=True,
        check=True,
        cwd=REPO_ROOT,
    )
    result = json.loads(out.stdout)
    assert result["records"] == session["events"]
    # One group, because the whole page came from one derived session: if the server's
    # grouping and the viewer's disagreed, this is where it would show.
    assert result["groups"] == 1
    assert result["rows"] >= 1
    assert result["userMsgs"] >= 1
    assert result["title"]


# --------------------------------------------- every route, reached over the socket

# The tests above call the projections directly, which is the right way to check what
# they return and says nothing about whether the server ever calls them. Between the two
# sit the routing table, the token prefix, the query parser and the JSON writer, and a
# handler that raised there would give the analyst an empty panel rather than an error
# anybody notices. Four of the twelve routes had never been requested over the socket.
#
# So one sample request per route, and a guard that the table names every route there is,
# because a route added without a sample is a panel nothing has ever loaded.


def _samples(case: Case) -> dict[str, str]:
    """One concrete path per route pattern, with real identifiers where a route takes one."""
    session = api.sessions(case)[0]["key"]
    event = api.timeline(case, limit=1)["rows"][0]["event_id"]
    return {
        r"^/$": "/",
        r"^/index\.html$": "/index.html",
        r"^/api/case$": "/api/case",
        r"^/api/projects$": "/api/projects",
        r"^/api/sessions/(?P<key>[0-9a-f]{32})/events$": f"/api/sessions/{session}/events",
        r"^/api/events/(?P<event>[0-9a-f]{32})$": f"/api/events/{event}",
        r"^/api/timeline$": "/api/timeline",
        r"^/api/findings$": "/api/findings",
        r"^/api/instructions$": "/api/instructions",
        r"^/api/corroboration$": "/api/corroboration",
        r"^/api/artifacts$": "/api/artifacts",
        r"^/api/health$": "/api/health",
    }


def test_the_sample_table_names_every_route_the_server_has(case: Case) -> None:
    served = {pattern.pattern for pattern, _ in webui.ROUTES}
    assert set(_samples(case)) == served, {
        "never requested": sorted(served - set(_samples(case))),
        "not a route": sorted(set(_samples(case)) - served),
    }


def test_every_route_answers_with_something(client: Client, case: Case) -> None:
    """A 200 and a body with content in it. An endpoint that answers 500, or 200 with
    nothing, is a view that reads as a case holding nothing of that kind."""
    for pattern, path in sorted(_samples(case).items()):
        status, headers, body = client.request(path)
        assert status == 200, (pattern, path, status, body[:200])
        assert body, (pattern, path, "an empty body is not an answer")
        if path.startswith("/api/"):
            assert "json" in headers["Content-Type"], (path, headers["Content-Type"])


def test_an_event_id_that_names_nothing_is_a_404_and_says_what_is_missing(
    client: Client,
) -> None:
    """Not a 500 and not an empty record. An analyst following a link from a finding into
    an event that is no longer in the case has to be told which of the two happened."""
    status, _, body = client.request("/api/events/" + "b" * 32)
    assert status == 404
    assert b"b" * 32 in body or b"event" in body.lower(), body[:200]


def test_a_paging_parameter_that_is_not_a_number_shows_the_first_page(
    client: Client,
) -> None:
    """A hand-edited URL bar is not an attack and must not be an error page: every
    projection bounds its own limits, so the tolerant reading is the safe one."""
    status, _, body = client.request("/api/timeline?offset=nonsense&limit=whatever")
    assert status == 200, body[:200]
    assert json.loads(body)["rows"], "the first page of a case that has events"


# ----------------------------------------------- the answers given when something is wrong

# Every hardening item above is pinned by a test that makes a well-formed request. The
# responses given when the request is not well formed were not, and those are the ones an
# attacker sees first: the server's own docstring says so about the malformed-request path
# and nothing had ever taken it.


def _raw_exchange(port: int, request: bytes) -> str:
    """One request written straight onto the socket, and everything that comes back.

    http.client cannot send a request this server should reject, because it builds a
    well-formed one, so these go out as bytes.
    """
    connection = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        connection.sendall(request)
        raw = b""
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            raw += chunk
    finally:
        connection.close()
    return raw.decode("latin-1")


def test_a_request_the_base_class_rejects_still_carries_the_security_headers(
    client: Client,
) -> None:
    """The base class answers a request it cannot parse before any of this server's code
    runs. Without the override that hands that answer back through the same writer, it
    would be the one response in the server with no content security policy and no nosniff
    on it, and it is reachable by anybody who can open the socket. An over-long header line
    is the way to get there with the request line itself intact.
    """
    head = _raw_exchange(
        client.port,
        b"GET /api/health HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Long: " + b"a" * 100_000 + b"\r\n\r\n",
    )
    assert head.startswith("HTTP/1."), head[:200]
    assert " 431 " in head.splitlines()[0] or " 400 " in head.splitlines()[0], head[:200]
    for name, value in webui.SECURITY_HEADERS:
        assert f"{name}: {value}" in head, (name, head[:400])


def test_a_request_line_too_broken_to_have_a_version_gets_a_body_and_no_headers(
    client: Client,
) -> None:
    """A limit of the protocol rather than of this server, written down so nobody reads
    the test above as covering it.

    A request line the base class cannot parse at all leaves the version at HTTP/0.9, and
    that version has no headers to send, so the answer is a bare body. No browser speaks
    it. What matters is that the body is the same generic error as everywhere else: no
    token, no path on the analyst's machine, nothing about the case.
    """
    body = _raw_exchange(client.port, b"GET\r\n\r\n")
    assert '"status": 400' in body, body[:200]
    assert TOKEN not in body
    assert "Traceback" not in body and ".db" not in body, body[:200]


def test_a_query_string_past_the_limit_is_refused_by_length(client: Client) -> None:
    """Refused for what it is rather than parsed and then found to be nonsense, so the
    parser never sees a megabyte of it."""
    status, _, _ = client.request("/api/timeline?agent=" + "a" * (webui.MAX_QUERY + 1))
    assert status == 414


def test_a_handler_that_raises_becomes_an_error_and_not_a_traceback(
    client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A traceback on the socket would name paths on the analyst's machine and the shape
    of the case, and it would do it to whoever asked. Nothing had ever made one happen."""

    def explode(*_: object) -> None:
        raise RuntimeError("the secret path is /home/alice/cases/one.db")

    # The routing table holds the function object, so replacing the module attribute
    # would leave the table pointing at the original. The table is what is swapped.
    monkeypatch.setattr(webui, "ROUTES", ((re.compile(r"^/api/health$"), explode),))
    status, _, body = client.request("/api/health")
    assert status == 500
    assert b"Traceback" not in body and b"/home/alice" not in body, body[:400]


def test_a_case_that_is_not_there_fails_at_the_command_line(tmp_path: Path) -> None:
    """Opened once before the socket exists, so a wrong path is a message in the terminal
    rather than a 503 the analyst meets in a browser with a case they think is loaded."""
    with pytest.raises(CaseError):
        webui.build(tmp_path / "no-such-case.db", port=0, token=TOKEN)
