# ADR 0006: The local UI uses the standard library, not a web framework

- **Status:** accepted
- **Date:** 2026-09-14

## Context

`agentforensics serve` needs to expose a read-only JSON API over a SQLite case database and
serve one static HTML file, bound to `127.0.0.1`. The endpoints are few: list bundles and
sessions, project one session into the viewer's event shape, query the timeline with
filters, list findings, show the catalogue.

The reflex choice is FastAPI. Its dependency tree is uvicorn, starlette, pydantic,
pydantic-core (a compiled Rust wheel), anyio, sniffio, idna, click, h11 and
typing-extensions. An analyst workstation may be air-gapped, so every one of those has to
be vendored, and the compiled wheel has to match the interpreter and the platform.

## Decision

`http.server.ThreadingHTTPServer` with an explicit route table. No web framework.

The standard library documentation warns that `http.server` is not for production use.
Loopback-only, single-analyst use makes that acceptable, but only with hardening, which is
part of this decision rather than a later concern:

- No `SimpleHTTPRequestHandler` path handling. The viewer is served from an in-process byte
  string or an explicit allowlist of files, so there is no filesystem path to traverse.
- An explicit method and path table with no fallback handler.
- A request body size cap.
- `Host` and `Origin` checks, so a page in the analyst's browser cannot reach the API by
  DNS rebinding.
- A random per-run path token, printed on the console, so a local process that guesses the
  port still cannot read the case.
- No CGI, no directory listing.
- `Content-Security-Policy` and `X-Content-Type-Options` on every response.

## Consequences

Buys: `uv sync` installs nothing for the web UI, offline install is trivial, and there is
no compiled dependency to match against an interpreter.

Costs: request validation, routing and error handling are hand-written, which is more code
to test than a framework's declarative equivalent. Streaming is worse, so the session
projection endpoint pages by event range instead of serving one large document. The
hardening list above must be maintained by hand, and it is the part most likely to rot, so
it has tests.

Revisit if the endpoint surface grows well past a dozen routes or needs genuine concurrent
streaming. The fallback is Starlette plus uvicorn, which is a much smaller tree than
FastAPI and needs no compiled wheel. Not FastAPI.

## Alternatives considered

- FastAPI plus uvicorn: ten or more transitive dependencies for features this API does not
  use.
- Flask plus waitress: smaller, still a dependency tree for routing that fits in a dict.
