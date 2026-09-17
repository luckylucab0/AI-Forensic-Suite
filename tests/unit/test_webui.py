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
        "events_without_timestamp",
        "collection_gaps",
    ):
        assert key in summary["counts"]
    assert summary["afx_api"] == api.API_VERSION
    assert summary["counts"]["events"] > 0
    assert summary["scanned"] is True


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


def test_the_artifact_list_separates_not_collected_from_not_read(case: Case) -> None:
    """The distinction the reliability of every other view depends on."""
    listed = api.artifacts(case)
    assert listed["artifacts"]
    assert any(
        entry["parse_status"] in ("unsupported", "failed", None) for entry in listed["artifacts"]
    )
    for entry in listed["artifacts"]:
        assert isinstance(entry["collected"], bool)


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
    session = max(
        (
            session
            for project in projects
            for session in project["sessions"]
            if not session["files"]
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
