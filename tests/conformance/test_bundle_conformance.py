"""Conformance suite for the evidence bundle format.

Written once, against the format rather than against one implementation, because two
independent collectors have to produce the same thing and will not unless something checks.
Today it exercises collect.py; adding collect.ps1 means adding one entry to COLLECTORS and
nothing else.

The assertions are the promises docs/BUNDLE_FORMAT.md makes out loud. Where a promise is
about what does NOT happen, such as writing outside the output directory or copying
credential material, the test is written to fail if the guarantee is quietly dropped,
because nothing about the bundle itself would look wrong afterwards.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests" / "fixtures"))

from generate import build_home  # noqa: E402

from agentforensics.bundle import verify_bundle  # noqa: E402

COLLECT_PY = REPO_ROOT / "collector" / "collect.py"

# Fields that are allowed to differ between two runs, or between the two collectors. This
# list is part of the specification: see docs/BUNDLE_FORMAT.md, "Fields allowed to differ".
VOLATILE_COLLECTION_FIELDS = {
    "uuid",
    "started_utc",
    "finished_utc",
    "argv",
    "hostname",
    "collector_user",
    "os_version",
    "architecture",
    "elevated",
    "root",
}


def run_collect_py(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(COLLECT_PY), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


# Each entry is (name, runner). One today, two once the PowerShell collector lands.
COLLECTORS: list[tuple[str, Callable[[list[str]], subprocess.CompletedProcess[str]]]] = [
    ("collect.py", run_collect_py),
]


@pytest.fixture(scope="module")
def synthetic_home(tmp_path_factory: pytest.TempPathFactory) -> Path:
    home = tmp_path_factory.mktemp("profile") / "home"
    build_home(home)
    return home


@pytest.fixture(scope="module")
def bundle(synthetic_home: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("bundles") / "case-001"
    result = run_collect_py(["--out", str(out), "--root", str(synthetic_home), "--os", "linux"])
    assert result.returncode == 0, result.stderr
    return out


@pytest.fixture(scope="module")
def manifest(bundle: Path) -> dict[str, Any]:
    return json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))


# ------------------------------------------------------------------------------ layout


def test_bundle_has_the_three_required_parts(bundle: Path) -> None:
    assert (bundle / "manifest.json").is_file()
    assert (bundle / "chain_of_custody.jsonl").is_file()
    assert (bundle / "files").is_dir()


def test_manifest_declares_a_format_version(manifest: dict[str, Any]) -> None:
    assert manifest["format_version"] == 1


def test_manifest_records_what_produced_it(manifest: dict[str, Any]) -> None:
    """An analyst must be able to prove which build made the bundle."""
    tool = manifest["tool"]
    assert tool["name"]
    assert tool["version"]
    assert len(tool["sha256"]) == 64
    assert len(tool["catalogue_version"]) == 64


def test_manifest_records_the_collection_context(manifest: dict[str, Any]) -> None:
    collection = manifest["collection"]
    for key in (
        "uuid",
        "started_utc",
        "finished_utc",
        "local_timezone",
        "hostname",
        "os",
        "collector_user",
        "elevated",
        "argv",
        "include_secrets",
        "max_file_size",
    ):
        assert key in collection, key
    assert collection["started_utc"].endswith("Z")
    assert collection["finished_utc"].endswith("Z")


def test_every_file_entry_carries_its_original_path(manifest: dict[str, Any]) -> None:
    """The encoding is not fully reversible, so this is the only authoritative record."""
    assert manifest["files"]
    for entry in manifest["files"]:
        assert entry["original_path"]
        assert entry["artifact_id"]
        assert "collected" in entry


def test_timestamps_are_utc_with_microseconds_or_null(manifest: dict[str, Any]) -> None:
    for entry in manifest["files"]:
        for key in ("mtime_utc", "ctime_utc", "atime_utc", "birthtime_utc"):
            value = entry[key]
            if value is None:
                continue
            assert value.endswith("Z"), (key, value)
            assert len(value) == len("2026-01-01T00:00:00.000000Z"), (key, value)


def test_files_are_sorted_deterministically(manifest: dict[str, Any]) -> None:
    keys = [(e["artifact_id"], e["original_path"]) for e in manifest["files"]]
    assert keys == sorted(keys)


# -------------------------------------------------------------------------- integrity


def test_the_bundle_verifies(bundle: Path) -> None:
    report = verify_bundle(bundle)
    assert report.ok, report.summary()
    assert report.checked > 0


def test_every_collected_file_is_present_and_matches_its_hash(
    bundle: Path, manifest: dict[str, Any]
) -> None:
    collected = [e for e in manifest["files"] if e["collected"]]
    assert collected
    for entry in collected:
        target = bundle / Path(*entry["bundle_path"].split("/"))
        assert target.is_file(), entry["bundle_path"]
        assert target.stat().st_size == entry["size"]


def test_custody_chain_starts_unlinked_and_commits_to_the_manifest(bundle: Path) -> None:
    records = [
        json.loads(line)
        for line in (bundle / "chain_of_custody.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert records
    assert records[0]["seq"] == 0
    assert records[0]["prev_sha256"] is None
    assert records[0]["event"] == "collected"
    import hashlib

    manifest_sha = hashlib.sha256((bundle / "manifest.json").read_bytes()).hexdigest()
    assert records[0]["manifest_sha256"] == manifest_sha


# --------------------------------------------------------------- what must not happen


def test_credential_content_is_not_copied_by_default(
    bundle: Path, manifest: dict[str, Any]
) -> None:
    """The single most important default in the tool.

    Presence, identity and timestamps are recorded so an analyst knows the file existed
    and can match it against a known token. The bytes are not copied, because a bundle
    full of live credentials is a liability of its own. See SECURITY.md.
    """
    credentials = [e for e in manifest["files"] if e["category"] == "credentials"]
    assert credentials, "the fixture should contain credential material to test this"
    for entry in credentials:
        assert entry["collected"] is False
        assert entry["reason"] == "secret_policy"
        assert entry["bundle_path"] is None
        # Metadata is still there, which is the point of recording rather than skipping.
        assert len(entry["sha256"]) == 64
        assert entry["size"] > 0
        assert entry["mtime_utc"]
    # And nothing resembling the file made it into files/ under any name.
    for path in (bundle / "files").rglob("*"):
        assert ".credentials.json" not in path.name


def test_a_symlink_out_of_the_profile_is_recorded_and_not_followed(
    manifest: dict[str, Any],
) -> None:
    outside = [e for e in manifest["files"] if e["reason"] == "skipped_symlink"]
    assert outside, "the fixture should contain a symlink pointing out of the profile"
    for entry in outside:
        assert entry["symlink"], "the target must be recorded even though it was not read"
        assert entry["collected"] is False


def test_nothing_is_written_outside_the_output_directory(
    synthetic_home: Path, tmp_path: Path
) -> None:
    """The read-only guarantee, checked rather than asserted in prose.

    A snapshot of the profile is taken before and after a collection. Any difference means
    the collector wrote to, or deleted from, evidence.
    """

    def snapshot(root: Path) -> dict[str, tuple[int, int]]:
        out = {}
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                out[str(path)] = (-1, 0)
            elif path.is_file():
                stat = path.stat()
                out[str(path)] = (stat.st_size, int(stat.st_mtime))
        return out

    before = snapshot(synthetic_home)
    out = tmp_path / "bundle"
    result = run_collect_py(["--out", str(out), "--root", str(synthetic_home), "--os", "linux"])
    assert result.returncode == 0, result.stderr
    after = snapshot(synthetic_home)
    assert before == after, "the collector modified the evidence it was reading"


def test_dry_run_writes_nothing_at_all(synthetic_home: Path, tmp_path: Path) -> None:
    out = tmp_path / "should-not-exist"
    result = run_collect_py(["--dry-run", "--json", "--root", str(synthetic_home), "--os", "linux"])
    assert result.returncode == 0, result.stderr
    assert not out.exists()
    summary = json.loads(result.stdout)
    assert summary["dry_run"] is True
    assert summary["counts"]["hit"] > 0
    assert summary["counts"]["collected"] == 0


def test_refuses_to_write_into_a_non_empty_directory(synthetic_home: Path, tmp_path: Path) -> None:
    """Mixing two collections in one bundle makes both unusable as evidence."""
    out = tmp_path / "occupied"
    out.mkdir()
    (out / "something").write_text("x", encoding="utf-8")
    result = run_collect_py(["--out", str(out), "--root", str(synthetic_home), "--os", "linux"])
    assert result.returncode == 2
    assert "not empty" in result.stderr


# ------------------------------------------------------------------------ determinism


def test_two_collections_of_an_unchanged_tree_agree(synthetic_home: Path, tmp_path: Path) -> None:
    first, second = tmp_path / "a", tmp_path / "b"
    for out in (first, second):
        result = run_collect_py(["--out", str(out), "--root", str(synthetic_home), "--os", "linux"])
        assert result.returncode == 0, result.stderr

    def normalize(path: Path) -> dict[str, Any]:
        data = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
        for key in VOLATILE_COLLECTION_FIELDS:
            data["collection"].pop(key, None)
        data["tool"].pop("sha256", None)
        return data

    assert normalize(first) == normalize(second)


# ------------------------------------------------------------------------ exit codes


def test_empty_host_reports_nothing_found_rather_than_failure(tmp_path: Path) -> None:
    """A host with no agents is a valid result, and a fleet sweep has to tell it apart
    from a crash or it draws a wrong picture of where agents are in use."""
    empty = tmp_path / "empty-home"
    empty.mkdir()
    out = tmp_path / "empty-bundle"
    result = run_collect_py(["--out", str(out), "--root", str(empty), "--os", "linux"])
    assert result.returncode == 3, result.stderr


# ------------------------------------------------------------------------------- zip


def test_zip_and_sidecar(synthetic_home: Path, tmp_path: Path) -> None:
    import hashlib
    import zipfile

    out = tmp_path / "zipped"
    result = run_collect_py(
        ["--out", str(out), "--zip", "--root", str(synthetic_home), "--os", "linux"]
    )
    assert result.returncode == 0, result.stderr
    archive = Path(str(out) + ".zip")
    sidecar = Path(str(archive) + ".sha256")
    assert archive.is_file()
    assert sidecar.is_file()

    digest, name = sidecar.read_text(encoding="utf-8").split()
    assert name == archive.name
    assert digest == hashlib.sha256(archive.read_bytes()).hexdigest()

    with zipfile.ZipFile(archive) as zf:
        names = zf.namelist()
    assert any(n.endswith("manifest.json") for n in names)
    assert any(n.endswith("chain_of_custody.jsonl") for n in names)


# --------------------------------------------------------------- collector agreement


@pytest.mark.parametrize("name,runner", COLLECTORS)
def test_collector_produces_a_verifiable_bundle(
    name: str,
    runner: Callable[[list[str]], subprocess.CompletedProcess[str]],
    synthetic_home: Path,
    tmp_path: Path,
) -> None:
    """The one test every collector implementation has to pass.

    Parameterised so the PowerShell collector joins the suite by being added to
    COLLECTORS, rather than by getting a second set of assertions that can drift.
    """
    out = tmp_path / ("bundle-" + name.replace(".", "-"))
    result = runner(["--out", str(out), "--root", str(synthetic_home), "--os", "linux"])
    assert result.returncode == 0, result.stderr
    report = verify_bundle(out)
    assert report.ok, report.summary()


def test_collector_runs_on_python_38(synthetic_home: Path, tmp_path: Path) -> None:
    """The collector's whole point is running on an interpreter the endpoint already has.

    Skipped rather than failed when no 3.8 is available locally; CI provides one, so the
    claim is checked there on every push.
    """
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is not available to provide a Python 3.8 interpreter")
    probe = subprocess.run(
        [uv, "run", "--no-project", "--python", "3.8", "python", "-c", "print(1)"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    if probe.returncode != 0:
        pytest.skip("no Python 3.8 interpreter available")

    out = tmp_path / "py38-bundle"
    result = subprocess.run(
        [
            uv,
            "run",
            "--no-project",
            "--python",
            "3.8",
            "python",
            str(COLLECT_PY),
            "--out",
            str(out),
            "--root",
            str(synthetic_home),
            "--os",
            "linux",
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env={**os.environ},
    )
    assert result.returncode == 0, result.stderr
    assert verify_bundle(out).ok
