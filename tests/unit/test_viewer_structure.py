"""Structural checks on the viewer, independent of any JavaScript runtime.

These catch the regressions that are invisible in a diff review: a tab whose panel was
renamed, a removed feature creeping back through a copy and paste, or the reappearance of
the truncation that used to hide unparsed lines.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECK = REPO_ROOT / "scripts" / "check_viewer.py"
VIEWER = REPO_ROOT / "viewer" / "index.html"


def test_check_viewer_passes() -> None:
    result = subprocess.run(
        [sys.executable, str(CHECK)],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert result.returncode == 0, result.stdout


def test_check_viewer_detects_a_regression(tmp_path: Path) -> None:
    """The check has to be able to fail, or passing means nothing."""
    broken = tmp_path / "index.html"
    text = VIEWER.read_text(encoding="utf-8")
    broken.write_text(
        text.replace("const SECRET_RULES=[", "const RENAMED_RULES=["), encoding="utf-8"
    )
    result = subprocess.run(
        [sys.executable, str(CHECK), "--path", str(broken)],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert result.returncode == 1
    assert "SECRET_RULES" in result.stdout


def test_viewer_is_self_contained() -> None:
    """No build step, no network at load time.

    The viewer's value in the field is that it opens on a machine where nothing may be
    installed, so an external script or stylesheet reference would break the promise, and
    a remote one would also break the offline guarantee.
    """
    text = VIEWER.read_text(encoding="utf-8")
    assert "<script src=" not in text
    assert '<link rel="stylesheet"' not in text
    assert "https://fonts." not in text
    assert "cdn." not in text


def test_viewer_writes_nothing_but_the_theme() -> None:
    """A read-only tool that quietly persists state would be a surprise worth avoiding."""
    text = VIEWER.read_text(encoding="utf-8")
    writes = text.count("localStorage.setItem")
    removes = text.count("localStorage.removeItem")
    assert writes == 1, "expected exactly one localStorage write, the theme choice"
    assert removes == 1, "expected exactly one localStorage removal, resetting the theme"
    assert "cc-theme" in text
