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

import hashlib
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

from generate import build_home, build_windows_home  # noqa: E402
from selftest_cases import compare  # noqa: E402

from agentforensics.bundle import verify_bundle  # noqa: E402

COLLECT_PY = REPO_ROOT / "collector" / "collect.py"
COLLECT_PS1 = REPO_ROOT / "collector" / "collect.ps1"

# text=True alone decodes with the locale encoding, which on a Windows runner is cp1252.
# Both collectors write UTF-8 on purpose, so that turned the serializer parity check into a
# comparison against mojibake and blamed the collector for the harness's own decoding.
DECODE_AS_UTF8 = {"text": True, "encoding": "utf-8", "errors": "replace"}

# The interpreter to run collect.ps1 with. powershell.exe first, because that is Windows
# PowerShell 5.1 and the only thing that proves the collector runs where it is meant to:
# pwsh is PowerShell 7 and differs in ways this file documents. pwsh is still worth using,
# since it catches logic errors on any platform, and the CI matrix runs the 5.1 job.
POWERSHELL_CANDIDATES = ("powershell.exe", "powershell", "pwsh", "/opt/pwsh/pwsh")


def find_powershell() -> str | None:
    # AFX_POWERSHELL pins the interpreter, which the Windows CI job uses so the suite
    # cannot quietly fall back to pwsh and report a pass for the wrong runtime.
    pinned = os.environ.get("AFX_POWERSHELL")
    if pinned:
        found = shutil.which(pinned)
        return str(found) if found else pinned
    for candidate in POWERSHELL_CANDIDATES:
        found = shutil.which(candidate) if "/" not in candidate else candidate
        if found and Path(found).exists():
            return str(found)
        if found and shutil.which(found):
            return str(found)
    return None


POWERSHELL = find_powershell()

# collect.ps1 takes PowerShell parameters, collect.py takes POSIX options. One translation
# table here keeps every test written once, against the format rather than against a
# command line.
PS1_OPTIONS = {
    "--out": "-Out",
    "--root": "-Root",
    "--os": "-TargetOs",
    "--zip": "-Zip",
    "--dry-run": "-DryRun",
    "--json": "-Json",
    "--all-users": "-AllUsers",
    "--include-secrets": "-IncludeSecrets",
    "--user": "-User",
    "--agents": "-Agents",
    "--max-file-size": "-MaxFileSize",
    "--max-files-per-artifact": "-MaxFilesPerArtifact",
    "--version": "-Version",
    "--selftest": "-SelfTest",
}

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
        **DECODE_AS_UTF8,
    )


def describe_run(out: Path, result: subprocess.CompletedProcess[str]) -> str:
    """Everything a failing collector run knows, for an assertion message.

    An exit code and a count of errors is not a diagnosis, and the platform where these
    tests fail is not the one they can be debugged on interactively.
    """
    lines = [f"exit {result.returncode}", result.stderr.strip()]
    manifest_path = out / "manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        lines.append(f"counts: {manifest['counts']}")
        lines.append(f"users: {manifest['users']}")
        lines.append(f"project_roots: {manifest['project_roots']}")
        for problem in manifest["errors"]:
            lines.append(f"  error: {problem}")
        for refusal in manifest["refused_patterns"][:5]:
            lines.append(f"  refused: {refusal}")
    return "\n".join(lines)


def run_collect_ps1(args: list[str]) -> subprocess.CompletedProcess[str]:
    """Run collect.ps1 with the same arguments the Python collector takes."""
    if POWERSHELL is None:
        raise RuntimeError("no PowerShell interpreter available")
    translated: list[str] = []
    for arg in args:
        translated.append(PS1_OPTIONS.get(arg, arg))
    return subprocess.run(
        [POWERSHELL, "-NoLogo", "-NoProfile", "-File", str(COLLECT_PS1), *translated],
        cwd=REPO_ROOT,
        capture_output=True,
        **DECODE_AS_UTF8,
    )


# Each entry is (name, runner). Every test written against this list runs against both
# implementations, so the format is what is tested rather than either collector.
COLLECTORS: list[tuple[str, Callable[[list[str]], subprocess.CompletedProcess[str]]]] = [
    ("collect.py", run_collect_py),
    ("collect.ps1", run_collect_ps1),
]


@pytest.fixture(scope="module")
def synthetic_home(tmp_path_factory: pytest.TempPathFactory) -> Path:
    home = tmp_path_factory.mktemp("profile") / "home"
    build_home(home)
    return home


@pytest.fixture(scope="module")
def windows_image(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A mounted Windows image, as a collection with --root expects to find one.

    A second tree rather than a second profile in the first one: the Windows patterns hang
    off application-data roots that the POSIX tree has no counterpart for, and collecting a
    Windows image is a different run with a different --os.
    """
    root = tmp_path_factory.mktemp("windows-image")
    build_windows_home(root / "Users" / "alice")
    return root


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


def test_a_path_claimed_by_a_secret_artifact_is_withheld_whatever_else_claims_it(
    bundle: Path, manifest: dict[str, Any]
) -> None:
    """Secret has to be a property of the path, not of whichever artifact matched first.

    The catalogue routinely claims one path twice: a specific entry for a credential file
    and a broad directory glob over the tree holding it. If the copy decision is taken as
    each match is found, the outcome depends on iteration order, which means a password
    database can end up in the bundle on one run and not on the next.
    """
    entries = [e for e in manifest["files"] if e["original_path"].endswith("secrets.json")]
    assert entries, "the fixture should contain a doubly claimed credential file"
    for entry in entries:
        assert entry["collected"] is False
        assert entry["reason"] == "secret_policy"
        assert entry["bundle_path"] is None
        assert len(entry["sha256"]) == 64
    for path in (bundle / "files").rglob("secrets.json"):
        raise AssertionError(f"credential content was copied to {path}")


def test_a_doubly_claimed_path_records_every_artifact_that_matched(
    manifest: dict[str, Any],
) -> None:
    """One entry per path, but no claim is dropped: never hide a record."""
    multi = [e for e in manifest["files"] if e.get("artifact_ids")]
    assert multi, "the fixture should produce at least one doubly claimed path"
    for entry in multi:
        ids = entry["artifact_ids"]
        assert ids == sorted(ids), "artifact_ids has to be ordered for a stable diff"
        assert len(ids) > 1, "the field is only written when there is more than one claim"
        assert entry["artifact_id"] in ids, "the attributed claim must be among them"
    paths = [e["original_path"] for e in manifest["files"]]
    assert len(paths) == len(set(paths)), "a path must appear exactly once in the manifest"


def test_a_pattern_the_collector_would_not_search_is_reported(
    manifest: dict[str, Any],
) -> None:
    """Coverage has to be auditable, not assumed.

    A pattern nobody searched produces the same bundle as an artifact that was not there.
    The manifest therefore carries every refusal, and on a normal run the list is empty:
    if it is not, something in the catalogue cannot be resolved and the analyst is told
    rather than left to infer it from a missing file.
    """
    assert "refused_patterns" in manifest, "the field is part of the format, always present"
    assert manifest["counts"]["refused_patterns"] == len(manifest["refused_patterns"])
    for refusal in manifest["refused_patterns"]:
        assert refusal["pattern"]
        assert refusal["reason"] in {
            "not_absolute",
            "wildcard_too_broad",
            "wildcard_only",
            "malformed_variable",
            "environment_unreadable_offline",
        }, refusal


def test_a_relocation_variable_is_followed_rather_than_guessed_at(
    synthetic_home: Path, tmp_path: Path
) -> None:
    """The case the catalogue records relocation variables for.

    An agent that moved its data tree with an environment variable is the scenario where a
    collection keyed on the default path returns nothing and reads as a clean host. The
    collector has to follow the variable when it is set, and say so when it cannot.
    """
    relocated = synthetic_home / "elsewhere" / "claude-config"
    (relocated / "projects" / "-src-app").mkdir(parents=True)
    moved = relocated / "projects" / "-src-app" / "relocated-session.jsonl"
    moved.write_text('{"type":"user","message":{"role":"user","content":"hi"}}\n')

    # No --root, because the collector deliberately ignores the environment when reading a
    # mounted image: the variable belongs to the endpoint, not to the workstation. HOME is
    # overridden instead, which keeps the run inside the synthetic fixture. Without that
    # this test would collect a contributor's own agent history into a temporary directory.
    out = tmp_path / "relocated-bundle"
    env = dict(
        os.environ,
        HOME=str(synthetic_home),
        CLAUDE_CONFIG_DIR=str(relocated),
    )
    result = subprocess.run(
        [sys.executable, str(COLLECT_PY), "--out", str(out), "--os", "linux"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert result.returncode in (0, 1), result.stderr
    manifest = json.loads((out / "manifest.json").read_text())
    # The manifest holds forward slashes on every platform, by design: see "Fields allowed
    # to differ" in docs/BUNDLE_FORMAT.md and the separator convention in the collector.
    collected = [e["original_path"] for e in manifest["files"]]
    assert moved.as_posix() in collected, (
        "a transcript in a relocated configuration directory was not collected; "
        "the bundle would read as a host where Claude Code had never run"
    )


def test_a_symlink_out_of_the_profile_is_recorded_and_not_followed(
    manifest: dict[str, Any],
) -> None:
    outside = [e for e in manifest["files"] if e["reason"] == "skipped_symlink"]
    assert outside, "the fixture should contain a symlink pointing out of the profile"
    for entry in outside:
        assert entry["symlink"], "the target must be recorded even though it was not read"
        assert entry["collected"] is False


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
    if name.endswith(".ps1") and POWERSHELL is None:
        pytest.skip("no PowerShell interpreter available")
    out = tmp_path / ("bundle-" + name.replace(".", "-"))
    result = runner(["--out", str(out), "--root", str(synthetic_home), "--os", "linux"])
    assert result.returncode == 0, describe_run(out, result)
    report = verify_bundle(out)
    assert report.ok, report.summary()


def assert_the_collectors_agree(tree: Path, os_name: str, tmp_path: Path) -> None:
    """Run both collectors over one tree and compare their manifests field by field.

    Only the fields docs/BUNDLE_FORMAT.md lists as allowed to differ are normalized away.
    """
    py_out = tmp_path / "differential-py"
    ps_out = tmp_path / "differential-ps1"
    for runner, out in ((run_collect_py, py_out), (run_collect_ps1, ps_out)):
        result = runner(["--out", str(out), "--root", str(tree), "--os", os_name])
        assert result.returncode == 0, describe_run(out, result)

    py_manifest = json.loads((py_out / "manifest.json").read_text(encoding="utf-8"))
    ps_manifest = json.loads((ps_out / "manifest.json").read_text(encoding="utf-8"))

    # Per-file: everything except the three timestamps the platforms genuinely disagree on.
    per_file_allowed = {"birthtime_utc", "ctime_utc", "atime_utc"}
    py_files = {e["original_path"]: e for e in py_manifest["files"]}
    ps_files = {e["original_path"]: e for e in ps_manifest["files"]}
    # Two collections that both found nothing agree perfectly, and a comparison that
    # accepts that proves nothing at all. It is the exact shape of the defect that made
    # --all-users return an empty bundle from a live Windows host for months.
    assert py_files, f"the collection over {tree} found no files, so nothing is compared"
    assert set(py_files) == set(ps_files), (
        "the collectors found different files.\n"
        f"only python={sorted(set(py_files) - set(ps_files))}\n"
        f"only powershell={sorted(set(ps_files) - set(py_files))}\n"
        # Project-anchored artifacts live inside a working copy that each collector
        # discovers for itself out of the agent's own state, so a disagreement about the
        # files usually starts as a disagreement about the roots.
        f"python project_roots={py_manifest['project_roots']}\n"
        f"powershell project_roots={ps_manifest['project_roots']}\n"
        f"python users={py_manifest['users']}\n"
        f"powershell users={ps_manifest['users']}"
    )
    for path in sorted(py_files):
        left = {k: v for k, v in py_files[path].items() if k not in per_file_allowed}
        right = {k: v for k, v in ps_files[path].items() if k not in per_file_allowed}
        assert left == right, f"{path} differs between the collectors"

    # Everything else that is not a platform fact or a per-run value.
    for section in ("counts", "errors", "refused_patterns", "project_roots", "users"):
        assert py_manifest[section] == ps_manifest[section], section
    assert py_manifest["format_version"] == ps_manifest["format_version"]

    allowed_collection = VOLATILE_COLLECTION_FIELDS | {"os", "local_timezone_name"}
    left = {k: v for k, v in py_manifest["collection"].items() if k not in allowed_collection}
    right = {k: v for k, v in ps_manifest["collection"].items() if k not in allowed_collection}
    assert left == right

    # The catalogue hash has to be the same, or the two were built from different data and
    # nothing above proves anything.
    assert py_manifest["tool"]["catalogue_version"] == ps_manifest["tool"]["catalogue_version"]

    # And both bundles verify with the one verifier.
    for out in (py_out, ps_out):
        report = verify_bundle(out)
        assert report.ok, report.summary()


def test_the_two_collectors_agree_on_the_same_tree(synthetic_home: Path, tmp_path: Path) -> None:
    """The differential test, and the reason the bundle format is written down.

    Two implementations of one format drift silently: each is self-consistent, each
    verifies, and an analyst comparing a Windows bundle with a macOS one sees differences
    that are artefacts of the collector rather than facts about the endpoints.

    Every real bug this found was of that kind: a culture-aware sort putting a
    case-collision suffix on the other file of a pair, a case-insensitive dictionary losing
    one of two names differing only in case, and a symlink described by its own metadata
    instead of its target's.
    """
    if POWERSHELL is None:
        pytest.skip("no PowerShell interpreter available")
    assert_the_collectors_agree(synthetic_home, "linux", tmp_path)


def test_the_two_collectors_agree_on_a_windows_application_data_tree(
    windows_image: Path, tmp_path: Path
) -> None:
    """The same differential where the two collectors have the most reason to disagree.

    The POSIX tree above exercises neither of the Windows application-data roots, and
    between the two collectors those roots are the place where one reads a value the other
    does not: %APPDATA% and %LOCALAPPDATA% are expanded by two separate implementations of
    the same table, one of which also has the live environment in reach. A difference there
    is a difference in which files a Windows collection returns, which is the answer this
    tool is for.
    """
    if POWERSHELL is None:
        pytest.skip("no PowerShell interpreter available")
    assert_the_collectors_agree(windows_image, "windows", tmp_path)


def test_the_powershell_serializer_matches_python_byte_for_byte() -> None:
    """The manifest is compared between the collectors, so the JSON has to agree exactly.

    collect.ps1 carries a hand-written serializer because ConvertTo-Json differs from
    Python in key order, indentation, non-ASCII escaping and number rendering, and defaults
    to -Depth 2 on PowerShell 5.1, which silently flattens nested structures into type
    names. -SelfTest prints a fixed set of structures so that claim is checked rather than
    taken on trust.

    The expectations live in selftest_cases.py because the Windows CI job checks the same
    output from real 5.1 through check_selftest.py, and two copies would drift.
    """
    if POWERSHELL is None:
        pytest.skip("no PowerShell interpreter available")
    result = run_collect_ps1(["--selftest"])
    assert result.returncode == 0, result.stderr
    problems = compare(result.stdout)
    assert not problems, "\n".join(problems)


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


# ---------------------------------------------------------------- the source is evidence


def snapshot(root: Path) -> dict[str, tuple[int, int, str]]:
    """Every file below `root` as (size, mtime in nanoseconds, content hash).

    Access time is left out on purpose and is the one thing a collection is allowed to
    change: the bundle format says the collector opens without updating it where the
    platform and the file's ownership permit, and records the original value where it
    cannot. Everything else has to come back identical.
    """
    out: dict[str, tuple[int, int, str]] = {}
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        if path.is_symlink():
            out[relative] = (-1, -1, "-> " + os.readlink(path))
        elif path.is_dir():
            out[relative] = (-1, -1, "directory")
        else:
            info = path.stat()
            out[relative] = (
                info.st_size,
                info.st_mtime_ns,
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
    return out


@pytest.mark.slow
@pytest.mark.collector
def test_collecting_leaves_the_source_tree_exactly_as_it_was(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """The third non-negotiable, and the one whose breach destroys the evidence itself.

    Nothing on the target is modified, moved, renamed or deleted. A test did check this and
    it was weaker than its own name: it compared a file's size and its modification time to
    the second, so a rewrite with the same length inside the same second was invisible to
    it, and it looked at neither content, nor symlink targets, nor directories. Its name
    said it checked that nothing is written outside the output directory, which is a
    different promise and the one the test below this covers.

    So: size, modification time to the nanosecond, and a hash of the content, plus the link
    target of every symlink and the set of directories. Nothing may appear, vanish or
    differ. Access time is left out and is the one thing a collection may change, which the
    bundle format already states and explains.

    A breach here is not a bug that produces a wrong answer. It is a collection that changes
    the thing it was run to preserve, which an opposing examiner can demonstrate from the
    timestamps and which makes the whole bundle arguable.

    A fresh profile rather than the module-scoped one, because this has to compare a tree
    against itself across one run and nothing else may have touched it in between.
    """
    home = tmp_path_factory.mktemp("readonly-profile") / "home"
    build_home(home)
    before = snapshot(home)
    assert len(before) > 100, "an empty tree would make this test pass and prove nothing"

    out = tmp_path_factory.mktemp("readonly-bundle") / "case"
    result = run_collect_py(["--out", str(out), "--root", str(home), "--os", "linux"])
    assert result.returncode == 0, result.stderr
    # Without this the test passes on a collector that reads nothing at all, which is the
    # failure mode of every test that asserts something did not happen.
    taken = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert taken["counts"]["collected"] > 20, taken["counts"]

    after = snapshot(home)
    appeared = sorted(set(after) - set(before))
    vanished = sorted(set(before) - set(after))
    changed = sorted(name for name in set(before) & set(after) if before[name] != after[name])
    assert not appeared, f"the collection created these under the source tree: {appeared}"
    assert not vanished, f"the collection removed these from the source tree: {vanished}"
    assert not changed, f"the collection altered these in the source tree: {changed}"


@pytest.mark.slow
@pytest.mark.collector
def test_collecting_writes_nothing_outside_the_output_directory(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """The promise the test above used to be named for: no temporary files elsewhere, no
    logs, no configuration.

    Checked by giving the run a home and a temporary directory of its own and asserting they
    are still empty afterwards. That is where a stray write would land, because it is where
    every library that writes one is told to look.
    """
    home = tmp_path_factory.mktemp("stray-profile") / "home"
    build_home(home, with_edge_cases=False)
    elsewhere = tmp_path_factory.mktemp("elsewhere")
    fake_home = elsewhere / "home"
    fake_tmp = elsewhere / "tmp"
    fake_home.mkdir()
    fake_tmp.mkdir()

    out = tmp_path_factory.mktemp("stray-bundle") / "case"
    environment = dict(os.environ, HOME=str(fake_home), TMPDIR=str(fake_tmp))
    result = subprocess.run(
        [sys.executable, str(COLLECT_PY), "--out", str(out), "--root", str(home), "--os", "linux"],
        capture_output=True,
        text=True,
        timeout=600,
        env=environment,
    )
    assert result.returncode == 0, result.stderr
    taken = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert taken["counts"]["collected"] > 20, taken["counts"]

    strays = sorted(str(p.relative_to(elsewhere)) for p in elsewhere.rglob("*"))
    assert strays == ["home", "tmp"], f"the collection wrote outside its output: {strays}"


# ------------------------------------------------- which profiles a run actually reads

# Measured rather than assumed: the collector was run under coverage over this whole
# suite, and the decisions below were among the ones no case had ever reached. They are
# not obscure. Each of them is the collector saying why a file is not in the bundle, and
# an analyst reads a file that is not in the bundle and not accounted for as a file that
# was not on the host.


def test_a_user_who_is_not_on_the_host_is_an_error_not_an_empty_collection(
    windows_image: Path, tmp_path: Path
) -> None:
    """The one answer this tool must never give by accident.

    A --user naming somebody who is not there, or a --all-users run on a platform whose
    profile parent the collector had wrong, searches nothing. Without this the result is a
    bundle with no files in it, which reads exactly like a host where no agent had ever
    run. The collector's own comment says so, and nothing had ever run the branch.
    """
    out = tmp_path / "nobody"
    result = run_collect_py(
        ["--out", str(out), "--root", str(windows_image), "--os", "windows", "--user", "nobody"]
    )
    # One, the code for a run that recorded an error, and not three: three means a host
    # with no agent artifacts on it, which is a real answer and not this one.
    assert result.returncode == 1, describe_run(out, result)
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["users"] == [], "nothing was searched, so no profile may be listed"
    errors = [e for e in manifest["errors"] if e.get("error") == "no_profiles_found"]
    assert errors, manifest["errors"]
    assert "nobody" in errors[0]["detail"]
    assert "no user profile was found" in result.stderr


def test_naming_a_user_collects_that_profile_and_not_the_tree_around_it(
    windows_image: Path, tmp_path: Path
) -> None:
    """A rooted run with --user has to filter, and this branch once kept a hardcoded POSIX
    profile parent after the other one was fixed, so it found nobody on Windows."""
    out = tmp_path / "just-alice"
    result = run_collect_py(
        ["--out", str(out), "--root", str(windows_image), "--os", "windows", "--user", "alice"]
    )
    assert result.returncode in (0, 1), describe_run(out, result)
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert [user["name"] for user in manifest["users"]] == ["alice"]
    assert any(entry["collected"] for entry in manifest["files"]), (
        "naming the user who is there must not come out the same as naming one who is not"
    )


def test_a_file_over_the_size_limit_says_so_rather_than_going_missing(
    synthetic_home: Path, tmp_path: Path
) -> None:
    """The limit exists so one enormous store cannot turn a live response into an outage.
    What it must not do is take a conversation database out of the bundle quietly."""
    out = tmp_path / "tiny-limit"
    result = run_collect_py(
        [
            "--out",
            str(out),
            "--root",
            str(synthetic_home),
            "--os",
            "linux",
            "--max-file-size",
            "16",
        ]
    )
    assert result.returncode in (0, 1, 3), describe_run(out, result)
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    oversize = [entry for entry in manifest["files"] if entry["reason"] == "too_large"]
    assert oversize, "a 16 byte limit over this tree has to leave something behind"
    for entry in oversize:
        assert entry["collected"] is False
        assert entry["sha256"] is None, "nothing was read, so nothing may claim a hash"
        assert entry["size"] > 16, "the size is what makes the reason checkable"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="this platform has no named pipes")
def test_something_that_is_not_a_regular_file_is_recorded_as_one_that_is_not(
    tmp_path: Path,
) -> None:
    """A path the catalogue claims can be a pipe, a socket or a device node.

    Opening one can block forever, which is why the collector stats before it reads, and
    the entry has to say which of the two happened. A silent skip here would be a settings
    file that reads as absent on a host that has one.
    """
    home = tmp_path / "piped"
    (home / ".claude").mkdir(parents=True)
    os.mkfifo(home / ".claude" / "settings.json")

    out = tmp_path / "pipe-bundle"
    result = run_collect_py(["--out", str(out), "--root", str(home), "--os", "linux"])
    assert result.returncode in (0, 1, 3), describe_run(out, result)
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    piped = [e for e in manifest["files"] if e["original_path"].endswith(".claude/settings.json")]
    assert piped, [e["original_path"] for e in manifest["files"]]
    assert piped[0]["reason"] == "not_a_file"
    assert piped[0]["collected"] is False


def test_a_profile_directory_that_is_a_link_is_refused_and_recorded(tmp_path: Path) -> None:
    """A profile that is a link could take a collection anywhere on the disk.

    Following it would read a tree the collection was never authorized to touch, and
    skipping it without a word would leave a user out of the bundle with nothing saying a
    user had been skipped. So it is refused and the refusal is in the manifest, where the
    analyzer turns it into a gap in the case.
    """
    root = tmp_path / "image"
    (root / "Users").mkdir(parents=True)
    build_home(root / "Users" / "alice")
    elsewhere = tmp_path / "somewhere-else"
    build_home(elsewhere)
    (root / "Users" / "bob").symlink_to(elsewhere, target_is_directory=True)

    out = tmp_path / "linked-profile"
    result = run_collect_py(["--out", str(out), "--root", str(root), "--os", "linux"])
    assert result.returncode in (0, 1), describe_run(out, result)
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))

    assert [user["name"] for user in manifest["users"]] == ["alice"]
    refused = [
        entry
        for entry in manifest["refused_patterns"]
        if entry.get("reason") == "profile_is_a_symlink"
    ]
    assert refused, manifest["refused_patterns"]
    assert any("bob" in str(entry) for entry in refused)
    assert not any("bob" in entry["original_path"] for entry in manifest["files"]), (
        "nothing behind the link may be read, whatever the link points at"
    )
