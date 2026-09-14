"""Run the viewer's behavioral tests through pytest.

The assertions themselves live in tests/viewer/viewer_behavior.mjs, because the code under
test is JavaScript embedded in a single HTML file (ADR 0001) and the honest way to test it
is to execute it. This wrapper exists so `pytest` stays the one command a contributor and
CI both run.

Skipped rather than failed when node is absent: a contributor editing documentation should
not need a JavaScript runtime, and CI runners all have one.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).resolve().parents[1] / "viewer" / "viewer_behavior.mjs"


@pytest.mark.viewer
def test_viewer_logic_preserves_every_record(repo_root: Path) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed, so the viewer's JavaScript cannot be executed")

    result = subprocess.run(
        [node, str(HARNESS)],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert result.returncode == 0, result.stdout
    assert "checks passed" in result.stdout
