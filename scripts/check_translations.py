#!/usr/bin/env python3
"""Keep the German documentation from silently falling behind the English.

Bilingual docs rot in a predictable way: someone edits the English file, the German one
keeps its old text, and a reader in German is now told something that is no longer true.
That is worse than having no translation at all, because it looks current.

The mechanism is a lock file. docs/translations.lock.json records the hash of every English
file that has a German sibling. Updating that hash is the explicit act of saying "I looked
at the German file and it matches". CI runs --check, so an English edit without that act
fails the build and the author has to either update the translation or state that nothing
needed changing by refreshing the lock.

Deliberately not automatic: nothing here tries to detect whether a translation is
*correct*, only whether somebody claimed to have looked. A machine cannot do the former,
and pretending otherwise would just move the rot somewhere harder to see.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

LOCK = Path("docs") / "translations.lock.json"

# Where to look for pairs. An English file X.md pairs with X.de.md in the same directory.
SEARCH_DIRS = [Path(), Path("docs")]

# English-only by decision, not by omission. Architecture decision records are an internal
# engineering log: translating them guarantees drift for no reader benefit.
ENGLISH_ONLY_DIRS = [Path("docs") / "adr"]
ENGLISH_ONLY_FILES: list[str] = []

# Documents whose German version is produced by a generator rather than written by hand.
# They are skipped entirely: there is nothing for a human to confirm, and a lock entry
# would demand a pointless refresh every time the catalogue changes. Their own generator
# has a --check mode, which is what CI uses to catch drift for these.
GENERATED_PAIRS = [
    Path("docs") / "ARTIFACTS.md",
    Path("docs") / "RULES.md",
]

EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_ERROR = 2

DE_SUFFIX = ".de.md"


def key(path: Path) -> str:
    """One spelling of a path, so the lock file is identical on every platform.

    git reports forward slashes everywhere, and the lock file is committed, so it must not
    acquire backslashes when somebody runs this on Windows.
    """
    return path.as_posix()


def sha256_of(path: Path) -> str:
    """Hash a document's content, with line endings normalized to LF.

    Not the raw bytes. A Windows checkout can convert LF to CRLF on the way to disk, which
    changed every hash and failed this check for files nobody had edited. The lock is about
    whether the English text moved, and a line ending is not the text moving.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def tracked_markdown() -> set[str] | None:
    """The Markdown files git tracks, or None outside a git checkout.

    Only published files matter here. A local, gitignored document such as private agent
    notes is nobody's translation obligation, and flagging it would train contributors to
    ignore this check.
    """
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z", "*.md", "**/*.md"],
            capture_output=True,
            check=True,
        ).stdout
    except (subprocess.CalledProcessError, OSError):
        return None
    return {p for p in out.decode("utf-8", "surrogateescape").split("\0") if p}


def candidates(tracked: set[str] | None) -> list[tuple[Path, Path]]:
    """Every English Markdown file in scope, paired with where its translation belongs."""
    found = []
    for directory in SEARCH_DIRS:
        if not directory.is_dir():
            continue
        for entry in sorted(directory.iterdir()):
            if entry.suffix != ".md" or entry.name.endswith(DE_SUFFIX):
                continue
            english = Path(*entry.parts)
            if key(english) in ENGLISH_ONLY_FILES:
                continue
            if english in GENERATED_PAIRS:
                continue
            if any(parent in ENGLISH_ONLY_DIRS for parent in english.parents):
                continue
            if tracked is not None and key(english) not in tracked:
                continue
            german = english.with_name(english.name[: -len(".md")] + DE_SUFFIX)
            found.append((english, german))
    return found


def load_lock() -> dict[str, str]:
    if not LOCK.exists():
        return {}
    with LOCK.open(encoding="utf-8") as handle:
        data = json.load(handle)
    hashes = data.get("english_hashes", {})
    return dict(hashes) if isinstance(hashes, dict) else {}


def write_lock(hashes: dict[str, str]) -> None:
    payload = {
        "_comment": (
            "sha256 of each English document whose German sibling was confirmed current. "
            "Refresh with scripts/check_translations.py --update after updating a "
            "translation, or after an English edit that needs none."
        ),
        "english_hashes": dict(sorted(hashes.items())),
    }
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with LOCK.open("w", encoding="utf-8") as handle:
        # Sorted keys and a trailing newline, so the committed file is diff-friendly.
        json.dump(payload, handle, indent=2, ensure_ascii=False, sort_keys=False)
        handle.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="fail on drift (the CI mode)")
    group.add_argument("--update", action="store_true", help="record the current state")
    parser.add_argument(
        "--allow-untranslated",
        action="store_true",
        help="do not fail on an English doc that has no German sibling yet",
    )
    args = parser.parse_args(argv)
    if not args.check and not args.update:
        args.check = True

    tracked = tracked_markdown()
    everything = candidates(tracked)
    pairs = [(en, de) for en, de in everything if de.exists()]
    untranslated = [en for en, de in everything if not de.exists()]

    if not pairs and not untranslated:
        sys.stderr.write("check-translations: no bilingual documents found\n")
        return EXIT_OK

    current = {key(en): sha256_of(en) for en, _ in pairs}

    if args.update:
        write_lock(current)
        sys.stderr.write(
            f"check-translations: recorded {len(current)} document(s) in {key(LOCK)}\n"
        )
        return EXIT_OK

    locked = load_lock()
    problems = []

    for english, german in pairs:
        name = key(english)
        if name not in locked:
            problems.append(f"{name} has a German sibling but no lock entry. Run --update.")
        elif locked[name] != current[name]:
            problems.append(
                f"{name} changed since the German version was last confirmed. "
                f"Update {key(german)}, then run --update."
            )

    for stale in sorted(set(locked) - set(current)):
        problems.append(
            f"{stale} is in the lock file but is no longer a bilingual document. Run --update."
        )

    if not args.allow_untranslated:
        for english in untranslated:
            problems.append(f"{key(english)} has no German sibling.")

    if problems:
        sys.stderr.write(f"check-translations: {len(problems)} problem(s)\n\n")
        for problem in problems:
            sys.stderr.write(f"  {problem}\n")
        sys.stderr.write(
            "\nThe point of this check is that somebody looked at the translation, not "
            "that a hash matches. Read the German file before refreshing the lock.\n"
        )
        return EXIT_DRIFT

    sys.stderr.write(f"check-translations: {len(pairs)} bilingual document(s) current\n")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
