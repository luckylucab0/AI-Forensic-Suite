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
  * The hook modes only see the present. `--mode history` is the one that reads what is
    already written, and it is not wired into any hook: it walks every object reachable
    from every ref, which is the wrong cost for a per-commit check and the right one once,
    before publishing. It still does not clear a repository on its own, because items 2 to
    6 of the pre-publication checklist in CONTRIBUTING are human review and no script can
    do them.

Standard library only and 3.8 compatible, so it runs in a pre-commit hook on whatever
interpreter the contributor happens to have.
"""

from __future__ import annotations

import argparse
import fnmatch
import subprocess
import sys
import tempfile
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
    binaries: bool = False,
) -> None:
    """Scan one blob, appending (label, line number, term index) tuples to findings.

    `binaries` is set by the history mode and by nothing else. A hook has no reason to
    decode a compiled artifact on every commit, but a screenshot committed two months ago
    can carry a hostname in a PNG text chunk, and a pre-publication scan that skipped
    every binary would miss exactly the mistake that is hardest to notice by eye. Decoded
    with replacement, so a run of plain ASCII inside a binary survives and the invalid
    bytes around it do not matter. The line number is then a weak locator, which is why the
    label carries the object id as well.
    """
    if len(data) > max_bytes:
        skipped.append((label, f"larger than {max_bytes} bytes"))
        return
    if looks_binary(data) and not binaries:
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


# ------------------------------------------------------------------ the history mode
#
# What "history" has to mean here is everything a clone of this repository would hand to
# somebody, which is more than `git log -p` shows. Three things are read, because a string
# can reach a reader through any of them:
#
#   * every blob reachable from every ref, at every version. Not the patches: a patch omits
#     binary files entirely, and a merge commit's content does not appear in one at all.
#     Walking objects has neither hole, and it also reads the versions of a file that were
#     later deleted, which is the case this whole mode exists for.
#   * every commit message, author and committer. Both identity fields are published and
#     they are separate, so a name that was only ever a git config value is still a name in
#     the history.
#   * every ref name. A branch called after a customer is as public as a file.


def history_objects() -> Optional[List[Tuple[str, str]]]:
    """Every object reachable from every ref, as (object id, path).

    Reachable rather than all: an unreachable object is in this clone and is not what a
    push publishes, so including it would raise alarms about things nobody can fetch.
    """
    out = git("rev-list", "--objects", "--all")
    if out is None:
        return None
    objects = []
    for line in out.decode("utf-8", "surrogateescape").splitlines():
        parts = line.split(" ", 1)
        objects.append((parts[0], parts[1] if len(parts) > 1 else ""))
    return objects


def _read_exactly(stream, size: int) -> bytes:
    """Read size bytes from a pipe, which can hand back less than asked for."""
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_blobs(object_ids: Sequence[str]):
    """Stream the content of many objects, yielding (object id, data) for the blobs.

    One `git cat-file --batch` for all of them rather than one process per object, which
    on a repository with a few thousand objects is the difference between a second and a
    minute.

    The identifiers go in through a temporary file rather than through a pipe on purpose.
    Writing them all to a pipe before reading any output deadlocks as soon as the list
    outgrows the pipe buffer, and that failure would appear only on large repositories,
    which are exactly the ones this mode matters for.
    """
    if not object_ids:
        return
    with tempfile.TemporaryFile() as handle:
        handle.write(("\n".join(object_ids) + "\n").encode("ascii"))
        handle.flush()
        handle.seek(0)
        process = subprocess.Popen(
            ("git", "cat-file", "--batch"),
            stdin=handle,
            stdout=subprocess.PIPE,
        )
        stream = process.stdout
        if stream is None:  # pragma: no cover - stdout=PIPE always gives one
            process.wait()
            return
        try:
            while True:
                header = stream.readline()
                if not header:
                    break
                fields = header.split()
                # "<id> missing" for an object this clone does not have. Skipped rather
                # than fatal: a shallow or partial clone legitimately lacks objects, and
                # the count at the end says how many were read.
                if len(fields) < 3:
                    continue
                object_id, kind, size = fields[0].decode(), fields[1].decode(), int(fields[2])
                data = _read_exactly(stream, size)
                stream.read(1)  # the newline the protocol puts after the payload
                if kind == "blob":
                    yield object_id, data
        finally:
            stream.close()
            process.wait()


def history_commits() -> Optional[List[Tuple[str, str, str, str, str, str]]]:
    """Every commit as (id, author name, author email, committer name, committer email,
    message).

    Separated by control characters rather than by newlines, because a commit message
    contains newlines and the whole point is to read it whole.
    """
    out = git("log", "--all", "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B%x1e")
    if out is None:
        return None
    commits = []
    for record in out.decode("utf-8", "surrogateescape").split("\x1e"):
        record = record.strip("\n")
        if not record:
            continue
        fields = record.split("\x1f")
        if len(fields) >= 6:
            commits.append(tuple(fields[:6]))  # type: ignore[arg-type]
    return commits


def ref_names() -> Optional[List[str]]:
    out = git("for-each-ref", "--format=%(refname)")
    return None if out is None else out.decode("utf-8", "surrogateescape").split()


def denylist_is_tracked(path: Path) -> bool:
    return git("ls-files", "--error-unmatch", str(path)) is not None


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Scan for operator-identifying strings.")
    parser.add_argument("--denylist", default=DEFAULT_DENYLIST)
    parser.add_argument("--allowlist", default=DEFAULT_ALLOWLIST)
    parser.add_argument(
        "--mode",
        choices=("tracked", "staged", "both", "history", "none"),
        default="both",
        help=(
            "tracked scans what git tracks, staged scans what is about to be committed, "
            "history scans every object, commit message, identity and ref name in the "
            "whole repository and is the pre-publication check rather than a hook, "
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

    if args.mode == "history":
        objects = history_objects()
        commits = history_commits()
        refs = ref_names()
        if objects is None or commits is None or refs is None:
            sys.stderr.write("opsec-check: not a git repository\n")
            return EXIT_ERROR

        paths = dict(objects)
        blobs = 0
        for object_id, data in read_blobs([object_id for object_id, _ in objects]):
            path = paths.get(object_id, "")
            if path and is_allowed(path, globs):
                continue
            # The path is the one this object was named by somewhere in history, which may
            # not be where it lives now or anywhere at all. The object id is what makes the
            # report actionable: `git cat-file -p <id>` shows it.
            label = "history:{}:{}".format(object_id[:12], path or "(no path)")
            scan_blob(label, data, terms, findings, skipped, args.max_bytes, binaries=True)
            blobs += 1
        scanned += blobs

        for commit_id, author, author_mail, committer, committer_mail, message_text in commits:
            short = commit_id[:12]
            scan_blob(
                "history:{}:message".format(short),
                message_text.encode("utf-8", "surrogateescape"),
                terms,
                findings,
                skipped,
                args.max_bytes,
            )
            # One line per commit rather than one per field, so a name that appears as both
            # author and committer is one finding and not two.
            identity = " ".join((author, author_mail, committer, committer_mail))
            scan_blob(
                "history:{}:identity".format(short),
                identity.encode("utf-8", "surrogateescape"),
                terms,
                findings,
                skipped,
                args.max_bytes,
            )
            scanned += 2

        scan_blob(
            "history:refs",
            "\n".join(refs).encode("utf-8", "surrogateescape"),
            terms,
            findings,
            skipped,
            args.max_bytes,
        )
        scanned += 1
        sys.stderr.write(
            "opsec-check: history mode read {} blob(s), {} commit(s) and {} ref(s)\n".format(
                blobs, len(commits), len(refs)
            )
        )

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
    if args.mode == "history":
        # Said every time, because a green run here is the easiest thing in this project to
        # mistake for permission to publish. It is one item of seven.
        sys.stderr.write(
            "opsec-check: that is item 1 of the pre-publication checklist in CONTRIBUTING. "
            "Items 2 to 6, the identities, the ref names, the commit timestamps, the "
            "screenshots and a generic secret scanner, are human review.\n"
        )
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
