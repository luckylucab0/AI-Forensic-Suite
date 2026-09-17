"""The local web UI: a read-only API over one case, plus the viewer that reads it.

Two modules, split along the line that matters for testing. `api` turns a case into the
data a viewer shows and knows nothing about HTTP; `server` binds one loopback socket and
carries the hardening ADR 0006 made part of the decision to use the standard library.
"""

from __future__ import annotations

from agentforensics.webui.api import API_VERSION, ApiError
from agentforensics.webui.server import HOST, build, serve, startup_lines, url

__all__ = [
    "API_VERSION",
    "HOST",
    "ApiError",
    "build",
    "serve",
    "startup_lines",
    "url",
]
