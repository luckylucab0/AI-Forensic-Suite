"""The offline guarantee, enforced over a whole run rather than promised in a document.

It is the fourth non-negotiable and the one with the least standing between it and a
regression: no network at runtime, no telemetry, no update check, no call to a model. Every
other constraint in that list has a test or a guard. This one had a content security policy,
which tells a browser what it may do, and a socket that binds loopback, which says where the
server listens. Neither says anything about what this package does when it runs.

The difference matters because of what the package is for. It is run by an examiner against
evidence, often on a machine that is deliberately isolated, and a single outbound connection
is three separate failures at once: the run stops working where it is needed most, a host
under investigation is told that somebody is looking, and material from the evidence may
leave with the request.

So this blocks the network in the process and then does the work: read a collection, scan it
with every shipped rule, build a timeline, export it, and serve the case. A connection to
anything but loopback raises, and the test fails with the address that was reached.
"""

from __future__ import annotations

import socket
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from agentforensics.model import Case
from agentforensics.rules import load, scan

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests" / "fixtures"))

from generate import build_home  # noqa: E402

# What a connection is allowed to reach: this machine, through its own loopback interface.
# The web server binds there and its own tests connect to it, which is not network access in
# the sense this file is about.
LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class Reached(AssertionError):
    """Raised at the point of the connection, so the traceback names the caller."""


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Every way out of the process that this package could take, closed.

    The socket methods rather than a firewall, because the test has to run anywhere, and all
    four rather than `connect` alone: a library that reached out would as likely use
    `create_connection`, and a name lookup is itself a packet leaving the machine and a
    signal to whoever runs the resolver.
    """

    def host_of(address: object) -> str:
        if isinstance(address, tuple) and address:
            return str(address[0])
        return str(address)

    def refuse(name: str):
        def inner(self_or_address, *args, **kwargs):  # type: ignore[no-untyped-def]
            address = args[0] if args else self_or_address
            host = host_of(address)
            if host in LOOPBACK:
                return original[name](self_or_address, *args, **kwargs)
            raise Reached(f"{name} reached {host!r}, and this package runs offline")

        return inner

    original = {
        "connect": socket.socket.connect,
        "connect_ex": socket.socket.connect_ex,
        "create_connection": socket.create_connection,
    }
    monkeypatch.setattr(socket.socket, "connect", refuse("connect"))
    monkeypatch.setattr(socket.socket, "connect_ex", refuse("connect_ex"))
    monkeypatch.setattr(socket, "create_connection", refuse("create_connection"))

    def no_lookup(*args: object, **kwargs: object) -> object:
        host = str(args[0]) if args else ""
        if host in LOOPBACK:
            return original_getaddrinfo(*args, **kwargs)  # type: ignore[arg-type]
        raise Reached(f"a name lookup for {host!r} left this machine, and it runs offline")

    original_getaddrinfo = socket.getaddrinfo
    monkeypatch.setattr(socket, "getaddrinfo", no_lookup)
    yield


@pytest.mark.slow
def test_a_whole_case_is_built_and_served_with_the_network_blocked(
    no_network: None, tmp_path: Path
) -> None:
    """Import the package, read a collection, run the packs, build a timeline, serve it.

    The import is inside the test rather than at the top of the file on purpose: a module
    that opened a connection while being imported would do it before the fixture could
    watch, and that is exactly the shape a telemetry or update check takes.
    """
    from agentforensics import webui
    from agentforensics.catalog import load_catalogue
    from agentforensics.ingest import ingest
    from agentforensics.timeline import write as write_timeline

    home = tmp_path / "profile"
    build_home(home, with_edge_cases=False)

    case_path = tmp_path / "case.db"
    with Case.open(case_path) as case:
        report = ingest(case, home, load_catalogue(REPO_ROOT / "catalog"))
        assert report.events > 0, "the collection produced no events, so nothing was exercised"

        findings = scan(case, load(REPO_ROOT / "rules"), store=True)
        assert findings.findings, "no rule fired, so the packs were not exercised"

        for fmt in ("csv", "jsonl", "timesketch"):
            with (tmp_path / f"timeline.{fmt}").open("w", encoding="utf-8", newline="") as out:
                written, _ = write_timeline(case, out, fmt)
            assert written > 0, fmt

    server, _ = webui.build(case_path, port=0, token="0" * 32)
    try:
        assert server.server_address[0] in LOOPBACK
    finally:
        server.server_close()


@pytest.mark.slow
def test_the_block_itself_works(no_network: None) -> None:
    """Without this the test above passes on a broken fixture, which is the failure mode of
    every test that asserts something did not happen."""
    with pytest.raises(Reached):
        socket.create_connection(("example.org", 80), timeout=1)
    with pytest.raises(Reached):
        socket.getaddrinfo("example.org", 80)
    with pytest.raises(Reached), socket.socket() as sock:
        sock.connect(("198.51.100.1", 80))
