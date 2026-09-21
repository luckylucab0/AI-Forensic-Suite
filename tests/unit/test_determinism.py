"""Same evidence in, same bytes out, across two processes that agree on nothing else.

Non-negotiable 5 of this project is that a run is deterministic and traceable, and the
reason is not tidiness. Two analysts working the same bundle, or one analyst re-running a
case after a parser was fixed, have to get the same timeline. If they do not, the
difference between the two outputs is indistinguishable from a difference in the evidence,
and there is no way to tell which of the two runs to believe.

The suite already checks the halves of this: a parser handed the same store twice yields
the same events, and two exports of one case produce identical bytes. Neither covers the
failure this file is about, because both stay inside one process, and a process is the
thing that holds the variable.

That variable is hash randomisation. Python seeds `hash()` for strings and bytes from a
random value at interpreter start, so the iteration order of any `set`, and of anything
derived from one, differs between two runs of the same code on the same input. A pipeline
that lets that order reach its output is non-deterministic in exactly the way that matters
here, and it passes every test in this suite, because pytest runs one process and that
process has one seed. The bug would appear as two analysts comparing timelines that do not
match, with nothing in either file saying why.

So each case here builds one profile and reads it twice, in two subprocesses with
deliberately different PYTHONHASHSEED values, and compares the bytes. The comparison is
over the whole user-facing surface rather than one format, because the orders are not
shared: the timeline comes from a SQL ORDER BY, the findings list is sorted by the rule
engine, and the two can fail independently.

The profile is built once and both runs read the same tree, so the only difference between
them is the seed. A second tree would also differ in its path, and a path legitimately
reaches the output as provenance, which would make a real difference and a spurious one
look the same.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests" / "fixtures"))

from generate import build_home  # noqa: E402

# Two seeds that are certainly not each other. 0 disables randomisation entirely and any
# non-zero value fixes a different seed, so the pair is the widest spread available while
# staying reproducible: a random pair would make a failure impossible to repeat, which is
# a poor property for the test that exists to protect reproducibility.
SEEDS = ("0", "12345")

# What a child process runs. It is a string rather than a module beside this file because
# it has to be started with an environment this process cannot change after the fact: the
# seed is read once, at interpreter start, and `os.environ` set afterwards does nothing.
CHILD = """
import sys
from pathlib import Path

from agentforensics.catalog import load_catalogue
from agentforensics.cli import main
from agentforensics.ingest import ingest
from agentforensics.model import Case

home, case_path, out_dir, rules = (Path(argument) for argument in sys.argv[1:5])

with Case.open(case_path) as case:
    ingest(case, home, load_catalogue(rules.parent / "catalog"))

def run(*argv):
    # 0 is a clean run and 1 means the subcommand found something, which a scan over this
    # profile is supposed to do. 2 is an error, and without this check the parent would
    # happily compare two outputs that failed the same way and call them deterministic.
    code = main(list(argv))
    if code not in (0, 1):
        raise SystemExit("{} exited {}".format(argv[0], code))


for fmt, name in (("csv", "timeline.csv"), ("jsonl", "timeline.jsonl")):
    run("timeline", "--case", str(case_path), "--format", fmt,
        "--out", str(out_dir / name))

run("scan", "--case", str(case_path), "--rules", str(rules),
    "--out", str(out_dir / "findings.csv"), "--no-store")
"""

OUTPUTS = ("timeline.csv", "timeline.jsonl", "findings.csv")


def _run(home: Path, workspace: Path, seed: str) -> Path:
    """One full read of the profile, in its own process, under the given seed."""
    out_dir = workspace / f"seed-{seed}"
    out_dir.mkdir()
    subprocess.run(
        [
            sys.executable,
            "-c",
            CHILD,
            str(home),
            str(out_dir / "case.db"),
            str(out_dir),
            str(REPO_ROOT / "rules"),
        ],
        # PYTHONHASHSEED is the whole point of the subprocess. The rest of the environment
        # is inherited so the child finds the same installed package this test is running
        # from, rather than whatever is on a bare PATH.
        env={**os.environ, "PYTHONHASHSEED": seed},
        check=True,
        capture_output=True,
        text=True,
    )
    return out_dir


@pytest.fixture(scope="module")
def two_reads(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """The same synthetic profile read once under each seed."""
    home = tmp_path_factory.mktemp("profile")
    build_home(home, with_edge_cases=False)
    workspace = tmp_path_factory.mktemp("reads")
    return tuple(_run(home, workspace, seed) for seed in SEEDS)  # type: ignore[return-value]


@pytest.mark.slow
@pytest.mark.parametrize("name", OUTPUTS)
def test_two_processes_that_disagree_on_hashing_produce_one_answer(
    two_reads: tuple[Path, Path], name: str
) -> None:
    first, second = (directory / name for directory in two_reads)
    left = first.read_bytes()
    right = second.read_bytes()
    if left == right:
        return

    # A byte comparison that fails says only that. The first differing line is what an
    # analyst would be looking at, so the failure hands it over rather than making the
    # next person reproduce the run to find it.
    left_lines = left.decode("utf-8", "replace").splitlines()
    right_lines = right.decode("utf-8", "replace").splitlines()
    # strict=False on purpose: a length difference is the second failure below, and
    # reporting it as a zip error instead would lose the line that says what changed.
    pairs = zip(left_lines, right_lines, strict=False)
    for number, (one, other) in enumerate(pairs, start=1):
        if one != other:
            pytest.fail(
                f"{name} differs between two runs of the same evidence, first at line "
                f"{number}.\n  PYTHONHASHSEED={SEEDS[0]}: {one}\n"
                f"  PYTHONHASHSEED={SEEDS[1]}: {other}\n"
                "Something in the pipeline lets the iteration order of a set, or of "
                "something built from one, reach the output. Two analysts on one bundle "
                "would get timelines that do not match, with nothing saying why"
            )
    pytest.fail(
        f"{name} has {len(left_lines)} line(s) under PYTHONHASHSEED={SEEDS[0]} and "
        f"{len(right_lines)} under PYTHONHASHSEED={SEEDS[1]}, with the shared prefix "
        "identical. A record is being dropped or added depending on hash order"
    )


@pytest.mark.slow
def test_the_two_runs_actually_read_something(two_reads: tuple[Path, Path]) -> None:
    """A guard on the guard: two empty files are identical and prove nothing.

    This is the shape every comparison test in this repository has to defend against. If
    the child ever stops finding the profile, or a CLI flag is renamed and the export
    writes a header and no rows, the parametrised test above goes green over two empty
    outputs and the determinism it claims to protect is unprotected.
    """
    for directory in two_reads:
        for name in OUTPUTS:
            lines = (directory / name).read_text(encoding="utf-8").splitlines()
            assert len(lines) > 1, (
                f"{directory.name}/{name} carries no rows, so comparing it proves nothing"
            )
