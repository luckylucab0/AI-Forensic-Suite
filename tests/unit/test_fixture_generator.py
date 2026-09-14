"""Tests for the synthetic fixture generator.

The fixture is what every conformance test runs against, so a defect here is invisible
until it makes an unrelated test fail somewhere else. That is exactly what happened: the
generator built a project directory name from a path with a drive letter in it, which
Windows cannot hold, and twenty-three conformance tests errored on a platform nobody had
looked at.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests" / "fixtures"))

from generate import build_home  # noqa: E402

# Characters Windows refuses in a path component, plus the separators.
WINDOWS_FORBIDDEN = set('<>:"|?*\\/')


def test_the_generated_tree_is_creatable_on_every_platform(tmp_path: Path) -> None:
    """Every component the generator creates has to be a legal name on Windows too.

    The generator derives the transcript directory name from an absolute path, and on
    Windows that path starts with a drive letter and a colon. Encoding only slashes and
    dots left the colon in place, and the name could not be created at all.
    """
    home = tmp_path / "home"
    build_home(home)
    for path in home.rglob("*"):
        for component in path.relative_to(home).parts:
            # The fixture deliberately contains names that need the bundle path encoding,
            # such as a trailing dot and a reserved device name. Those are legal to create
            # on POSIX and are the point of the test suite; what must not appear is a
            # character no platform can hold in a name at all.
            bad = WINDOWS_FORBIDDEN & set(component)
            if path.is_symlink() or "has:colon" in component:
                continue
            assert not bad, f"{path} has a component no Windows filesystem can hold: {component!r}"


def test_the_project_directory_name_uses_the_documented_encoding(tmp_path: Path) -> None:
    """Claude Code replaces every non-alphanumeric character with a single dash.

    The fixture has to use the real encoding, or the collector's decoding of it is tested
    against a shape that never occurs. See catalog/claude_code.yaml, transcripts.
    """
    home = tmp_path / "home"
    build_home(home)
    projects = home / ".claude" / "projects"
    names = [p.name for p in projects.iterdir() if p.is_dir()]
    assert names, "the fixture should create at least one project transcript directory"

    expected = re.sub(r"[^A-Za-z0-9]", "-", str(home / "src" / "app"))
    assert expected in names, f"expected the encoding of the working copy path, got {names}"
    for name in names:
        assert re.fullmatch(r"[A-Za-z0-9-]+", name), name
