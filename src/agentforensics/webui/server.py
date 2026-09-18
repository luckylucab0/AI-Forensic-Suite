"""The local read-only web server: `afx serve`.

One case, one loopback socket, no framework. ADR 0006 chose `http.server` over Starlette
and accepted what that costs: routing, validation and error bodies are written by hand
here, and a session projection is paged rather than streamed. What it buys is that the web
UI adds no runtime dependency to a tool that may have to be vendored onto an air-gapped
workstation.

The hardening below is part of that decision rather than a later concern, because a
forensic workstation is not a friendly network and a local HTTP server is reachable by
every process and every web page on the machine:

  * the socket binds 127.0.0.1 and nothing else, and there is no option to change it
  * every URL lives under a random per-run token, printed on the console. A page in the
    analyst's browser cannot guess it, so it cannot read the case
  * the `Host` header has to name loopback, which is what stops a DNS rebinding attack
    from turning a hostile page into a reader of this case
  * an `Origin`, when the browser sends one, has to be this server
  * only GET and HEAD exist, and a request that announces a body is refused unread
  * there is one explicit table of method and path, and no fallback handler. An
    unrecognised path is a 404, never a file
  * nothing is served from the filesystem by path. The viewer is one byte string read once
    at startup, so there is no path to traverse and no directory to list
  * the case is opened read-only, so SQLite itself refuses a write

ADR 0006 also says this list is the part most likely to rot, which is why every item on it
is pinned by a test in tests/unit/test_webui.py.
"""

from __future__ import annotations

import hashlib
import json
import re
import socket
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from secrets import token_urlsafe
from typing import Any
from urllib.parse import parse_qs, urlsplit

from agentforensics import __version__
from agentforensics.model import Case, CaseError
from agentforensics.webui import api

# Loopback only, and not a parameter. A forensic case on a listening socket that any other
# machine can reach is a disclosure, and an option to do it is an option somebody will find
# in a hurry at two in the morning.
HOST = "127.0.0.1"

# What a Host header may say. The port is checked separately against the port actually
# bound, so a header naming loopback on someone else's port is still refused.
_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "[::1]", "::1"})

# Where the viewer is looked for, in order: the copy inside an installed package, then the
# one in a source checkout. Two places rather than one because the viewer is also a
# standalone file an analyst opens directly (ADR 0001), so it lives at viewer/index.html in
# the repository and is copied into the wheel at build time.
_HERE = Path(__file__).resolve()
VIEWER_CANDIDATES = (
    _HERE.parent / "viewer" / "index.html",
    _HERE.parents[3] / "viewer" / "index.html",
)

# Sent on every response, including every error. A viewer that could load a script or
# reach a host of its own would break the offline guarantee the whole suite rests on, so it
# is denied at the browser as well as at the socket: default-src 'none' allows nothing that
# is not named, and connect-src 'self' keeps its fetches on this server.
#
# 'unsafe-inline' is needed twice and is not a compromise here: the viewer is deliberately
# one self-contained file, so its script, its style and its event handlers are all inline,
# and no external source is permitted at all.
CSP = (
    "default-src 'none'; "
    "script-src 'unsafe-inline'; "
    "style-src 'unsafe-inline'; "
    "connect-src 'self'; "
    "img-src data:; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)

SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("Content-Security-Policy", CSP),
    # Without this a browser may decide a response is HTML because of what is inside it,
    # which turns a record holding markup into a page that runs.
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    # The path carries the access token, so a cached copy on disk is a copy of the token.
    ("Cache-Control", "no-store"),
    ("X-Frame-Options", "DENY"),
)

JSON_TYPE = "application/json; charset=utf-8"
HTML_TYPE = "text/html; charset=utf-8"
# The unified log's own type. One JSON object per line, which is not a JSON document, and
# saying so keeps a client from trying to parse the page as one.
NDJSON_TYPE = "application/x-ndjson; charset=utf-8"

# No endpoint takes a body, so any request that announces one is refused without being
# read. A cap large enough to be worth reading would be a cap worth attacking.
MAX_BODY = 0
MAX_QUERY = 4096


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: bytes
    content_type: str = JSON_TYPE
    headers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class Context:
    """Everything a route needs. Assembled once, so a route holds no global state."""

    case_path: Path
    viewer: bytes
    viewer_sha256: str
    token: str


@dataclass(frozen=True, slots=True)
class Query:
    """One request's query string, already parsed and bounded."""

    values: Mapping[str, list[str]] = field(default_factory=dict)

    def one(self, name: str, default: str | None = None) -> str | None:
        found = self.values.get(name)
        return found[0] if found else default

    def many(self, name: str) -> tuple[str, ...]:
        return tuple(self.values.get(name, ()))

    def number(self, name: str, default: int) -> int:
        """An integer parameter, or the default when it is absent or not a number.

        Tolerant rather than an error on purpose: a hand-edited offset in a URL bar should
        show the first page, not an error page, and every projection bounds its own limits
        anyway.
        """
        raw = self.one(name)
        if raw is None:
            return default
        try:
            return int(raw)
        except ValueError:
            return default

    def flag(self, name: str) -> bool:
        return self.one(name) in ("1", "true", "yes", "on")


def _json(payload: Any, status: int = 200) -> Response:
    """A JSON response. sort_keys so two runs of the same request return the same bytes."""
    text = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str, indent=1)
    return Response(status, text.encode("utf-8"))


def _error(status: int, message: str) -> Response:
    """An error a client can act on, and nothing else.

    No traceback, no path, no SQL. An error body is the one part of an interface an attacker
    reads for free.
    """
    return _json({"error": message, "status": status}, status)


# ---------------------------------------------------------------------------- routes


def _viewer(ctx: Context, match: re.Match[str], query: Query) -> Response:
    """The viewer, from the byte string read at startup.

    Never from the filesystem by path. That is what makes path traversal structurally
    impossible here rather than a thing this file has to keep getting right.
    """
    return Response(200, ctx.viewer, HTML_TYPE)


def _case(ctx: Context, match: re.Match[str], query: Query) -> Response:
    with _open(ctx) as case:
        payload = api.case_summary(case)
    payload["viewer_sha256"] = ctx.viewer_sha256
    return _json(payload)


def _projects(ctx: Context, match: re.Match[str], query: Query) -> Response:
    with _open(ctx) as case:
        return _json(api.projects(case))


def _session_events(ctx: Context, match: re.Match[str], query: Query) -> Response:
    """One page of a session, as unified log records, one per line.

    The next page is announced in a header rather than wrapped around the records, so the
    body stays a unified log: the same bytes `afx normalize` writes, which the viewer
    already knows how to read and an analyst can save straight to a file.
    """
    with _open(ctx) as case:
        try:
            records, next_offset = api.session_records(
                case,
                match.group("key"),
                offset=query.number("offset", 0),
                limit=query.number("limit", api.DEFAULT_PAGE),
            )
        except api.ApiError as exc:
            return _error(404, str(exc))
    lines = "".join(
        json.dumps(record, ensure_ascii=False, default=str) + "\n" for record in records
    )
    headers: tuple[tuple[str, str], ...] = (("X-Afx-Records", str(len(records))),)
    if next_offset is not None:
        headers += (("X-Afx-Next-Offset", str(next_offset)),)
    return Response(200, lines.encode("utf-8"), NDJSON_TYPE, headers)


def _event(ctx: Context, match: re.Match[str], query: Query) -> Response:
    with _open(ctx) as case:
        try:
            return _json(api.event_record(case, match.group("event")))
        except api.ApiError as exc:
            return _error(404, str(exc))


def _timeline(ctx: Context, match: re.Match[str], query: Query) -> Response:
    with _open(ctx) as case:
        return _json(
            api.timeline(
                case,
                offset=query.number("offset", 0),
                limit=query.number("limit", api.DEFAULT_PAGE),
                agents=query.many("agent"),
                kinds=query.many("kind"),
                since=query.one("since"),
                until=query.one("until"),
                session_id=query.one("session"),
                exclude_artifact_fs=query.flag("no_fs"),
            )
        )


def _findings(ctx: Context, match: re.Match[str], query: Query) -> Response:
    with _open(ctx) as case:
        return _json(api.findings(case))


def _instructions(ctx: Context, match: re.Match[str], query: Query) -> Response:
    with _open(ctx) as case:
        return _json(api.instructions(case))


def _artifacts(ctx: Context, match: re.Match[str], query: Query) -> Response:
    with _open(ctx) as case:
        return _json(api.artifacts(case))


def _health(ctx: Context, match: re.Match[str], query: Query) -> Response:
    return _json({"afx_api": api.API_VERSION, "tool_version": __version__, "ok": True})


# The whole interface. One table, and the dispatcher below has no fallback: a path that is
# not in here is a 404, so there is no way to reach anything by naming it. Anchored
# patterns, because an unanchored one would let a longer path match a shorter route.
ROUTES: tuple[tuple[re.Pattern[str], Callable[[Context, re.Match[str], Query], Response]], ...] = (
    (re.compile(r"^/$"), _viewer),
    (re.compile(r"^/index\.html$"), _viewer),
    (re.compile(r"^/api/case$"), _case),
    (re.compile(r"^/api/projects$"), _projects),
    (re.compile(r"^/api/sessions/(?P<key>[0-9a-f]{32})/events$"), _session_events),
    (re.compile(r"^/api/events/(?P<event>[0-9a-f]{32})$"), _event),
    (re.compile(r"^/api/timeline$"), _timeline),
    (re.compile(r"^/api/findings$"), _findings),
    (re.compile(r"^/api/instructions$"), _instructions),
    (re.compile(r"^/api/artifacts$"), _artifacts),
    (re.compile(r"^/api/health$"), _health),
)


def _open(ctx: Context) -> Case:
    """The case, opened read-only, for the length of one request.

    Per request rather than once per process for two reasons. A SQLite connection belongs
    to the thread that made it, and this server is threaded; and a case can still be
    growing while it is served, which is what happens when an analyst starts reading a
    large collection before the ingest finishes. Opening a SQLite file costs microseconds,
    and a stale connection would cost a wrong answer.
    """
    return Case.open(ctx.case_path, create=False, read_only=True)


# ------------------------------------------------------------------------- the handler


def make_handler(
    ctx: Context, port: int, log: Callable[[str], None] | None
) -> type[BaseHTTPRequestHandler]:
    """The request handler class for one running server."""

    allowed_hosts = frozenset({f"{name}:{port}" for name in _ALLOWED_HOSTS} | set(_ALLOWED_HOSTS))
    allowed_origins = frozenset(
        {f"http://{name}:{port}" for name in _ALLOWED_HOSTS}
        | {f"http://{name}" for name in _ALLOWED_HOSTS}
    )

    class Handler(BaseHTTPRequestHandler):
        # HTTP/1.1 so a browser can reuse the connection for the many small API calls a
        # session view makes. Every response carries a Content-Length, which is what makes
        # that safe.
        protocol_version = "HTTP/1.1"
        # No version string. A server banner naming the Python build is free
        # reconnaissance, and this one is talking to exactly one browser.
        server_version = "afx"
        sys_version = ""

        def version_string(self) -> str:
            # The base class joins the two fields above with a space, so leaving
            # sys_version empty still sends a trailing space. Overridden so the header is
            # exactly what it claims to be.
            return "afx"

        def do_GET(self) -> None:
            self._handle(with_body=True)

        def do_HEAD(self) -> None:
            self._handle(with_body=False)

        # Written out rather than left absent. The base class answers an unknown method
        # with an error of its own shape, and every response from this server has to carry
        # the security headers above.
        def do_POST(self) -> None:
            self._refuse_method()

        def do_PUT(self) -> None:
            self._refuse_method()

        def do_PATCH(self) -> None:
            self._refuse_method()

        def do_DELETE(self) -> None:
            self._refuse_method()

        def do_OPTIONS(self) -> None:
            self._refuse_method()

        def _refuse_method(self) -> None:
            self._emit(
                Response(
                    405,
                    b'{"error": "this server answers GET and HEAD only", "status": 405}',
                    headers=(("Allow", "GET, HEAD"),),
                ),
                with_body=True,
                close=True,
            )

        def send_error(
            self, code: int, message: str | None = None, explain: str | None = None
        ) -> None:
            """Route the base class's own errors through our response path.

            The base class emits a malformed-request error before any of our code runs.
            Without this override that one response would be the only one without the
            security headers, and it is the one an attacker sees first.
            """
            self._emit(_error(code, message or "bad request"), with_body=True, close=True)

        def log_message(self, fmt: str, *args: Any) -> None:
            if log is not None:
                log(f"{self.address_string()} {fmt % args}")

        # ------------------------------------------------------------------ dispatch

        def _handle(self, *, with_body: bool) -> None:
            try:
                response, close = self._resolve()
            except Exception:  # a traceback must never reach the socket
                response, close = _error(500, "the server could not answer this request"), True
            self._emit(response, with_body=with_body, close=close)

        def _resolve(self) -> tuple[Response, bool]:
            """Apply the hardening list, then the route table. In that order."""
            # A body, refused without reading it. Unread bytes would desynchronise a reused
            # connection, so this answer also closes it.
            if self.headers.get("Transfer-Encoding"):
                return _error(411, "this server does not accept a chunked request"), True
            declared = self.headers.get("Content-Length")
            if declared and declared.strip() not in ("0", ""):
                return _error(413, "no endpoint here takes a request body"), True

            host = (self.headers.get("Host") or "").strip().lower()
            if host not in allowed_hosts:
                # The check that stops DNS rebinding: a hostile page resolving its own
                # name to 127.0.0.1 still sends its own name in this header.
                return _error(403, "this server answers requests addressed to loopback only"), True

            origin = (self.headers.get("Origin") or "").strip().lower()
            if origin and origin not in allowed_origins:
                return _error(403, "cross-origin requests are not answered"), True

            split = urlsplit(self.path)
            if len(split.query) > MAX_QUERY:
                return _error(414, "query string too long"), False
            path = split.path

            # The per-run token, as a path prefix. Checked before the route table so that a
            # request without it cannot even learn which paths exist.
            prefix = f"/{ctx.token}"
            if path == prefix:
                # One redirect, to put the trailing slash on, so the viewer's relative
                # fetches resolve under the token. Nothing is disclosed: the caller already
                # had the token.
                return Response(
                    308,
                    b"",
                    JSON_TYPE,
                    (("Location", prefix + "/"),),
                ), False
            if not path.startswith(prefix + "/"):
                return _error(404, "not found"), False
            path = path[len(prefix) :]

            for pattern, route in ROUTES:
                match = pattern.match(path)
                if match is None:
                    continue
                query = Query(parse_qs(split.query, keep_blank_values=True))
                try:
                    return route(ctx, match, query), False
                except CaseError as exc:
                    return _error(503, f"the case could not be read: {exc}"), False
            return _error(404, "not found"), False

        def _emit(self, response: Response, *, with_body: bool, close: bool = False) -> None:
            body = response.body if with_body else b""
            try:
                self.send_response(response.status)
                self.send_header("Content-Type", response.content_type)
                # Always sent, and always the real length of the entity, so HTTP/1.1
                # framing stays correct even for a HEAD with no body written.
                self.send_header("Content-Length", str(len(response.body)))
                for name, value in SECURITY_HEADERS:
                    self.send_header(name, value)
                for name, value in response.headers:
                    self.send_header(name, value)
                if close:
                    self.send_header("Connection", "close")
                    self.close_connection = True
                self.end_headers()
                if body:
                    self.wfile.write(body)
            except BrokenPipeError, ConnectionResetError:
                # The browser navigated away mid-response. Not an error worth a traceback,
                # and definitely not one worth taking the server down for.
                self.close_connection = True

    return Handler


# ---------------------------------------------------------------------------- startup


def read_viewer(path: Path | None = None) -> tuple[bytes, str]:
    """The viewer's bytes and their hash, read once.

    The hash is reported on the console and in /api/case. An analyst who is asked which
    build of the viewer produced a screenshot can then answer, which is the same reason
    every event in this suite carries the hash of the file it came from.
    """
    candidates = (path,) if path is not None else VIEWER_CANDIDATES
    for candidate in candidates:
        if candidate is not None and candidate.is_file():
            data = candidate.read_bytes()
            return data, hashlib.sha256(data).hexdigest()
    looked = ", ".join(str(candidate) for candidate in candidates if candidate)
    raise FileNotFoundError(f"cannot find the viewer. Looked in: {looked}")


def build(
    case_path: Path,
    *,
    port: int = 8765,
    token: str | None = None,
    viewer: Path | None = None,
    log: Callable[[str], None] | None = None,
) -> tuple[ThreadingHTTPServer, Context]:
    """Bind the socket and return the server, unstarted.

    Separated from `serve` so that a test can start it on a port the kernel picks, make
    requests and shut it down, which is how the hardening list above is pinned.
    """
    if not case_path.is_file():
        raise CaseError(f"no case at {case_path}")
    # Opened once before the socket exists, so that a case that cannot be read fails at
    # the command line rather than as a 503 in a browser.
    Case.open(case_path, create=False, read_only=True).close()

    data, digest = read_viewer(viewer)
    # 32 bytes of entropy in the URL. Long enough that it cannot be guessed by a page in
    # the analyst's own browser, which is the thing it defends against.
    ctx = Context(
        case_path=case_path, viewer=data, viewer_sha256=digest, token=token or token_urlsafe(24)
    )

    class Server(ThreadingHTTPServer):
        # Threads die with the process: a reader that hangs must not keep `afx serve` alive
        # after Ctrl-C.
        daemon_threads = True
        # So that restarting the server on the same port right after stopping it does not
        # fail on a socket still in TIME_WAIT.
        allow_reuse_address = True
        address_family = socket.AF_INET

    server = Server((HOST, port), make_handler(ctx, port, log))
    bound = int(server.server_address[1])
    if bound != port:
        # The kernel picked the port (port 0). The handler's Host check compares against
        # the port it was built with, so it has to be rebuilt with the real one.
        server.RequestHandlerClass = make_handler(ctx, bound, log)
    return server, ctx


def url(server: ThreadingHTTPServer, ctx: Context) -> str:
    return f"http://{HOST}:{server.server_address[1]}/{ctx.token}/"


def startup_lines(server: ThreadingHTTPServer, ctx: Context) -> list[str]:
    """What `afx serve` prints. The token is in the URL, so the URL is the whole notice."""
    return [
        f"serve: case {ctx.case_path}, opened read-only",
        f"serve: viewer sha256 {ctx.viewer_sha256}",
        f"serve: open {url(server, ctx)}",
        "serve: the path holds a one-time access token for this run. Nothing is served "
        "without it, and it changes when this command is restarted.",
        "serve: bound to 127.0.0.1 only. No network access, no telemetry. Ctrl-C to stop.",
    ]


def serve(
    case_path: Path,
    *,
    port: int = 8765,
    token: str | None = None,
    viewer: Path | None = None,
    log: Callable[[str], None] | None = None,
    announce: Callable[[Iterable[str]], None] | None = None,
) -> None:
    """Run until interrupted. Everything printed goes through the callers' own writer."""
    server, ctx = build(case_path, port=port, token=token, viewer=viewer, log=log)
    if announce is not None:
        announce(startup_lines(server, ctx))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


__all__ = [
    "CSP",
    "HOST",
    "ROUTES",
    "SECURITY_HEADERS",
    "VIEWER_CANDIDATES",
    "Context",
    "Query",
    "Response",
    "build",
    "make_handler",
    "read_viewer",
    "serve",
    "startup_lines",
    "url",
]
