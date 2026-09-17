"""Run the viewer's behavioral tests through pytest.

The assertions themselves live in tests/viewer/viewer_behavior.mjs, because the code under
test is JavaScript embedded in a single HTML file (ADR 0001) and the honest way to test it
is to execute it. This wrapper exists so `pytest` stays the one command a contributor and
CI both run.

Skipped rather than failed when node is absent: a contributor editing documentation should
not need a JavaScript runtime, and CI runners all have one.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
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


@pytest.mark.viewer
def test_the_viewer_reads_a_log_this_suite_produced(repo_root: Path, tmp_path: Path) -> None:
    """The two ends of the unified format, meeting.

    The harness's other assertions use records written by hand, which proves the mapping
    and not the interface. This one normalizes the synthetic profile with this repository's
    own normalizer and hands the result to the viewer's, so a change to either side that
    breaks the other fails here rather than in front of an analyst.
    """
    if shutil.which("node") is None:
        pytest.skip("node is not installed, so the viewer's JavaScript cannot be executed")

    sys.path.insert(0, str(repo_root / "tests" / "fixtures"))
    from generate import build_home

    home = tmp_path / "profile"
    build_home(home)

    from agentforensics.catalog import load_catalogue
    from agentforensics.unified import write_log

    log = tmp_path / "agents.jsonl"
    with log.open("w", encoding="utf-8", newline="") as handle:
        report = write_log(home, load_catalogue(repo_root / "catalog"), handle)
    assert report.events > 0

    result = subprocess.run(
        ["node", str(HARNESS)],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "AFX_UNIFIED_LOG": str(log)},
    )
    assert result.returncode == 0, result.stderr
    assert "checks passed" in result.stderr
