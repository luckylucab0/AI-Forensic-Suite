"""The probe lists the two measurement scripts carry, held against the catalogue.

These scripts are handed to somebody with a real installation, and their answer decides
whether a catalogue path is confirmed, corrected or left alone. That makes two failures
possible and both are silent:

  * a probe for a path no entry claims, whose absence is then a finding about nothing;
  * a catalogue path with no probe, whose absence from the output is indistinguishable
    from a path that was probed and was not there.

The first measurement run of this project hit both. So the probe list is generated, and
these tests pin the properties that made it worth generating.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

from agentforensics.catalog import load_catalogue

REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATOR = REPO_ROOT / "scripts" / "gen_layout_probes.py"

SH = REPO_ROOT / "scripts" / "measure_layout.sh"
PS1 = REPO_ROOT / "scripts" / "measure_layout.ps1"


@pytest.fixture(scope="module")
def catalogue():
    return load_catalogue(REPO_ROOT / "catalog")


def _generator():
    """The generator, loaded by path rather than imported.

    scripts/ is not a package and is deliberately not on the path: it holds tools that run
    on whatever interpreter a contributor has, and putting it on sys.path would let a test
    shadow a real module with one of them.
    """
    spec = importlib.util.spec_from_file_location("gen_layout_probes", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sh_probes() -> dict[str, list[tuple[str, str, str]]]:
    """Every probe line in the POSIX script, per family, as the shell would read it.

    Per family rather than in one list, because the script measures one family per run and
    two families may legitimately claim the same tree at different depths: one agent's
    directory is another agent's skill store.
    """
    families: dict[str, list[tuple[str, str, str]]] = {}
    family = None
    for raw in SH.read_text(encoding="utf-8").splitlines():
        heading = re.match(r"^    ([a-z_]+)\)$", raw)
        if heading:
            family = heading.group(1)
            families.setdefault(family, [])
            continue
        if re.match(r"^(walk|check) ", raw) and family:
            how, ids, path = raw.split(" ", 2)
            families[family].append((how, ids, path))
    return {name: lines for name, lines in families.items() if lines}


def _ps1_probes() -> dict[str, list[tuple[str, str, str]]]:
    families: dict[str, list[tuple[str, str, str]]] = {}
    family = None
    for raw in PS1.read_text(encoding="utf-8").splitlines():
        heading = re.match(r"^    '([a-z_]+)' = @\($", raw)
        if heading:
            family = heading.group(1)
            families.setdefault(family, [])
            continue
        match = re.match(r"^\s+'(walk|check) (\S+) (.*)'$", raw)
        if match and family:
            families[family].append((match.group(1), match.group(2), match.group(3)))
    return {name: lines for name, lines in families.items() if lines}


def test_the_committed_probe_lists_are_current() -> None:
    """The same check CI runs, so a catalogue change with a stale script fails here too."""
    result = subprocess.run(
        [sys.executable, str(GENERATOR), "--check"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("reader", [_sh_probes, _ps1_probes], ids=["sh", "ps1"])
def test_every_probe_names_an_entry_that_exists(reader, catalogue) -> None:
    """The defect that started this: a probe nobody can trace back to the catalogue.

    A hand-written list had one, and its absence read as a finding until somebody checked
    which entry it was supposed to be about and found there was none.
    """
    known = {artifact.id for artifact in catalogue.artifacts}
    for lines in reader().values():
        for _how, ids, path in lines:
            for artifact_id in ids.split(","):
                assert artifact_id in known, (
                    f"{path} is probed for {artifact_id}, which is not an entry"
                )


@pytest.mark.parametrize(
    ("platform", "reader"), [("posix", _sh_probes), ("windows", _ps1_probes)], ids=["sh", "ps1"]
)
def test_every_probeable_path_reaches_a_probe(platform, reader, catalogue) -> None:
    """The worse defect: a catalogue path the script never looks at.

    The generator decides which paths it can probe at all, and says in the script how many
    it cannot and why. This asserts the rest: every path it can probe is covered by a probe
    that is that path or an ancestor of it, and the entry is named on that line.
    """
    families, _tokens, _skipped = _generator().collect(catalogue, platform)
    separator = "\\" if platform == "windows" else "/"
    committed = reader()
    for family, planned in families.items():
        assert family in committed, f"{family} has probes and no block in the script"
        for path, ids, _how in planned:
            covering = [
                line_ids
                for _how2, line_ids, line_path in committed[family]
                if line_path == path or path.startswith(line_path + separator)
            ]
            assert covering, f"{path} reached no probe in the script"
            assert any(set(ids) & set(one.split(",")) for one in covering), (
                f"{path} is probed but none of {ids} is named on its line"
            )


@pytest.mark.parametrize("reader", [_sh_probes, _ps1_probes], ids=["sh", "ps1"])
def test_no_probe_walks_a_directory_the_platform_owns(reader) -> None:
    """A walk of a container directory is a listing of every product on the machine.

    It is also somebody's private data, which is the reason this is a test and not a style
    preference: these scripts are run by a person on their own laptop, and the output is
    sent to somebody else.
    """
    forbidden = {
        "~/library",
        "~/library/application support",
        "~/library/caches",
        "~/library/preferences",
        "~/library/containers",
        "~/library/group containers",
        "~/library/logs",
        "~/.config",
        "~/.local",
        "~/.local/share",
        "~/.cache",
        "/applications",
        "/usr",
        "/etc",
        "/opt",
        "/var",
        "/tmp",
        "%appdata%",
        "%localappdata%",
        "%localappdata%\\packages",
        "%userprofile%",
        "%temp%",
    }
    for lines in reader().values():
        for how, _ids, path in lines:
            if how != "walk":
                continue
            assert path.lower().rstrip("/\\") not in forbidden, path


@pytest.mark.parametrize(
    ("separator", "reader"), [("/", _sh_probes), ("\\", _ps1_probes)], ids=["sh", "ps1"]
)
def test_a_walked_probe_is_never_inside_another_walked_probe(separator, reader) -> None:
    """Otherwise a tree appears twice in the output, once per probe that walks it.

    Two copies of the same tree are not just noise: an analyst counting files in the output
    counts them twice. The generator marks the inner one as a check for that reason, which
    still gives its entry its own present-or-absent line.
    """
    for family, lines in reader().items():
        walked = [path for how, _ids, path in lines if how == "walk"]
        for path in walked:
            for other in walked:
                if path == other:
                    continue
                assert not path.startswith(other + separator), f"{family}: {path} is inside {other}"


def test_both_scripts_are_pure_ascii() -> None:
    """Same reason as the collectors: PowerShell 5.1 reads a BOM-less file as the machine's
    ANSI code page, so one byte above 127 becomes two characters and a path stops matching.
    """
    for target in (SH, PS1):
        raw = target.read_bytes()
        offending = [index for index, byte in enumerate(raw) if byte > 127]
        assert not offending, (
            f"{target.name} has {len(offending)} byte(s) above 127, "
            f"first at offset {offending[0] if offending else 0}"
        )
        assert not raw.startswith(b"\xef\xbb\xbf"), f"{target.name} has a byte order mark"
