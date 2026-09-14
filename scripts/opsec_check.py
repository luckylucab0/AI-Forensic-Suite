#!/usr/bin/env python3
"""Refuse to publish anything that names the operator.

This repository is public. A single occurrence of an employer name, an internal hostname,
a project code name or a colleague's name is not a cosmetic problem: it is permanent, it
is mirrored by forks and caches within minutes, and no later commit can take it back. So
the check runs before content can enter history, not after.

What it scans, depending on the mode: the files git tracks, the content staged for the next
commit, and the commit message itself. All three matter, because a string can reach history
through any of them.

Design constraints worth knowing:

  * The denylist is never committed. It names the very things we are hiding, so it lives
    outside git (.gitignore) and is supplied by the operator. Its absence is normal, not an
    error: a fresh clone, a CI run without the secret and an outside contributor all
    legitimately have no list, and the check exits 0 with a notice so it never becomes the
    reason a build fails for someone who could not have the list anyway.
  * A hit is reported as a location plus the index of the entry that matched. The matched
    text is never printed, because the output of this check ends up in terminals, CI logs
    and screenshots, and printing the secret to prove we found the secret would defeat the
    purpose.
  * This only sees the present. It does not scan history, so it cannot clear a repository
    for publication on its own. See CONTRIBUTING for the pre-publication procedure.

Standard library only and 3.8 compatible, so it runs in a pre-commit hook on whatever
interpreter the contributor happens to have.
"""

from __future__ import annotations

import argparse
import fnmatch
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

DEFAULT_DENYLIST = ".opsec-denylist"
DEFAULT_ALLOWLIST = ".opsec-allowlist"

# Files larger than this are reported as skipped rather than scanned. A denied string
# hiding in a multi-megabyte blob is possible but not worth the scan time on every commit,
# and the reported count keeps the omission visible instead of silent.
DEFAULT_MAX_BYTES = 5 * 1024 * 1024

# Tells the scanner to ignore one line, for the rare legitimate case: a test that must
# contain a denied string in order to prove the check works.
ALLOW_MARKER = "opsec-check: allow-line"

EXIT_CLEAN = 0
EXIT_HIT = 1
EXIT_ERROR = 2

Finding = Tuple[str, int, int]
Skip = Tuple[str, str]


def git(*args: str) -> Optional[bytes]:
    """Run a git command and return stdout, or None when git itself fails."""
    try:
        completed = subprocess.run(
            ("git", *args),
            capture_output=True,
            check=True,
        )
    except (subprocess.CalledProcessError, OSError):
        return None
    return completed.stdout


def load_terms(path: Path) -> List[str]:
    """Read the denylist: one term per line, '#' comments and blank lines ignored."""
    raw = path.read_bytes()
    terms = []
    for line in raw.decode("utf-8", "replace").splitlines():
        term = line.strip()
        if term and not term.startswith("#"):
            terms.append(term.lower())
    # Longest first, so a report points at the most specific entry that matched.
    terms.sort(key=len, reverse=True)
    return terms


def load_allowlist(path: Path) -> List[str]:
    """Read path globs that are exempt. A missing file means nothing is exempt."""
    if not path.exists():
        return []
    globs = []
    for line in path.read_bytes().decode("utf-8", "replace").splitlines():
        pattern = line.strip()
        if pattern and not pattern.startswith("#"):
            globs.append(pattern)
    return globs


def is_allowed(path: str, globs: Sequence[str]) -> bool:
    return any(fnmatch.fnmatch(path, g) for g in globs)


def looks_binary(data: bytes) -> bool:
    """A NUL byte in the first block is the usual, good-enough binary test."""
    return b"\x00" in data[:8192]


def scan_blob(
    label: str,
    data: bytes,
    terms: Sequence[str],
    findings: List[Finding],
    skipped: List[Skip],
    max_bytes: int,
) -> None:
    """Scan one blob, appending (label, line number, term index) tuples to findings."""
    if len(data) > max_bytes:
        skipped.append((label, f"larger than {max_bytes} bytes"))
        return
    if looks_binary(data):
        skipped.append((label, "binary"))
        return
    text = data.decode("utf-8", "replace")
    for lineno, line in enumerate(text.splitlines(), start=1):
        if ALLOW_MARKER in line:
            continue
        low = line.lower()
        for index, term in enumerate(terms):
            if term in low:
                findings.append((label, lineno, index))
                break


def _split_nul(out: bytes) -> List[str]:
    return [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]


def tracked_files() -> Optional[List[str]]:
    out = git("ls-files", "-z")
    return None if out is None else _split_nul(out)


def staged_files() -> Optional[List[str]]:
    out = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    return None if out is None else _split_nul(out)


def read_staged_blob(path: str) -> Optional[bytes]:
    """Read the staged version of a file, which can differ from the working tree."""
    return git("show", ":" + path)


def denylist_is_tracked(path: Path) -> bool:
    return git("ls-files", "--error-unmatch", str(path)) is not None


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Scan for operator-identifying strings.")
    parser.add_argument("--denylist", default=DEFAULT_DENYLIST)
    parser.add_argument("--allowlist", default=DEFAULT_ALLOWLIST)
    parser.add_argument(
        "--mode",
        choices=("tracked", "staged", "both", "none"),
        default="both",
        help=(
            "tracked scans what git tracks, staged scans what is about to be committed, "
            "none scans neither and is for the commit-msg hook, which only needs the "
            "message"
        ),
    )
    parser.add_argument(
        "--commit-msg",
        metavar="FILE",
        help="also scan this commit message file (the commit-msg hook argument)",
    )
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument(
        "--require-denylist",
        action="store_true",
        help="fail instead of skipping when no denylist is present",
    )
    args = parser.parse_args(argv)

    denylist = Path(args.denylist)

    if not denylist.exists():
        if args.require_denylist:
            sys.stderr.write(
                f"opsec-check: no denylist at {denylist} and --require-denylist was given\n"
            )
            return EXIT_ERROR
        sys.stderr.write(
            f"opsec-check: skipped, no denylist at {denylist}. This is expected in a fresh "
            "clone and in CI without the secret. See CONTRIBUTING.\n"
        )
        return EXIT_CLEAN

    # A committed denylist would publish exactly what it protects.
    if denylist_is_tracked(denylist):
        sys.stderr.write(
            f"opsec-check: {denylist} is tracked by git. It must never be committed: "
            "remove it from the index and confirm it is in .gitignore.\n"
        )
        return EXIT_ERROR

    terms = load_terms(denylist)
    if not terms:
        sys.stderr.write(f"opsec-check: denylist {denylist} has no entries\n")
        return EXIT_CLEAN

    globs = load_allowlist(Path(args.allowlist))
    findings: List[Finding] = []
    skipped: List[Skip] = []
    scanned = 0

    if args.mode in ("tracked", "both"):
        paths = tracked_files()
        if paths is None:
            sys.stderr.write("opsec-check: not a git repository\n")
            return EXIT_ERROR
        for path in paths:
            candidate = Path(path)
            if is_allowed(path, globs) or not candidate.is_file():
                continue
            scan_blob(
                f"tracked:{path}",
                candidate.read_bytes(),
                terms,
                findings,
                skipped,
                args.max_bytes,
            )
            scanned += 1

    if args.mode in ("staged", "both"):
        paths = staged_files()
        if paths is None:
            sys.stderr.write("opsec-check: cannot read the index\n")
            return EXIT_ERROR
        for path in paths:
            if is_allowed(path, globs):
                continue
            data = read_staged_blob(path)
            if data is None:
                continue
            scan_blob(f"staged:{path}", data, terms, findings, skipped, args.max_bytes)
            scanned += 1

    if args.commit_msg:
        message = Path(args.commit_msg)
        try:
            data = message.read_bytes()
        except OSError as exc:
            sys.stderr.write(f"opsec-check: cannot read commit message: {exc}\n")
            return EXIT_ERROR
        scan_blob("commit-msg", data, terms, findings, skipped, args.max_bytes)
        scanned += 1

    for label, reason in skipped:
        sys.stderr.write(f"opsec-check: skipped {label} ({reason})\n")

    if findings:
        sys.stderr.write(
            f"\nopsec-check: {len(findings)} location(s) match the denylist. The matched "
            "text is not printed on purpose.\n\n"
        )
        for label, lineno, index in findings:
            sys.stderr.write(f"  {label}:{lineno}  denylist entry #{index}\n")
        sys.stderr.write(
            f"\nRemove the string or, if it is genuinely required, add the "
            f"'{ALLOW_MARKER}' marker to that line or the path to {args.allowlist}.\n"
        )
        return EXIT_HIT

    sys.stderr.write(
        f"opsec-check: clean, {scanned} blob(s) scanned against {len(terms)} denylist entries\n"
    )
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
