#!/usr/bin/env python3
"""Generate the probe lists inside scripts/measure_layout.sh and scripts/measure_layout.ps1.

Why this is generated. The two measurement scripts ask a real machine which of the
catalogue's paths exist, and their first version carried the paths typed by hand. Held
against a real installation, that list did two things it must never do: it probed a path
that is in no catalogue entry, and it missed two paths that are. The first turns an absence
into a finding about nothing, and the second is worse, because a path nobody probed is
indistinguishable in the output from a path that was probed and was not there. The whole
value of the measurement is telling a wrong path apart from an uninstalled product, and a
hand-written probe list quietly destroys it.

So the probe list is catalogue output, and every line of it names the entries it came from.
An ABSENT line then means something exact: these entries claim this location and this
machine does not have it.

What is left out, and why each is left out rather than guessed:

  * a path anchored in a working copy (<project>, <repo-root>, a plugin or extension root),
    because the measurement does not know which directories on the machine are working
    copies, and walking the disk to find out is not a read-only layout probe any more;
  * a path anchored in an environment variable, because its value belongs to the machine
    being measured and an unset variable expands to nothing, which would probe the root of
    the filesystem;
  * a registry key, because neither script reads the registry;
  * a POSIX path for the Windows script and the other way round.

Each of those counts is written into the generated block, so the script itself says how
much of the catalogue it does not cover.

Truncation. A path with a placeholder or a wildcard in a directory component is probed at
the last literal directory above it, because the tree walk below a probe finds whatever is
there anyway. A pattern whose only wildcard is in the file name is kept whole and handed to
the shell, which expands it. A probe that is a prefix of another probe absorbs it, and
takes its entry ids with it.

Written to stay inside this directory's Python 3.8 lint target (see .ruff.toml), even
though importing the analyzer package means it only runs on 3.14 or newer.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentforensics.catalog import CatalogueError, load_catalogue

ROOT = Path(__file__).resolve().parents[1]
CATALOG_DIR = ROOT / "catalog"
SH = ROOT / "scripts" / "measure_layout.sh"
PS1 = ROOT / "scripts" / "measure_layout.ps1"

BEGIN = "# BEGIN generated probes -- scripts/gen_layout_probes.py"
END = "# END generated probes"

# A component is literal unless it carries one of these. `<name>` is the catalogue's own
# placeholder spelling and the rest are shell globs.
NOT_LITERAL = re.compile(r"[*?\[]|<")

# The reasons a catalogue path is not probed. The wording is what the generated block
# prints, so it is written for somebody reading the script rather than this file.
SKIP_PROJECT = "anchored in a working copy"
SKIP_VARIABLE = "anchored in an environment variable"
SKIP_REGISTRY = "a registry key"
SKIP_OTHER_OS = "for the other platform"
SKIP_SHARED = "in a scratch directory shared with every process on the machine"

# Directories every process on the machine writes into. A catalogue path that names a file
# there is probed as it stands, because the file name says whose it is. A path whose
# directory component is a placeholder cannot be: cutting it back leaves the shared root,
# and a walk of that is a listing of other people's temporary files. So it is refused, and
# the refusal is counted in the generated block like every other one.
SHARED_SCRATCH = (
    "/tmp",  # noqa: S108 - a path to refuse, not a path to write to
    "/var/tmp",  # noqa: S108
    "/private/tmp",
    "/private/var/folders",
    "/var/folders",
    "%TEMP%",
    "%TMP%",
)


# Words a by-name search may use, and the ones it may not. The search exists because a
# closed-source product's bundle identifier is sometimes the thing being measured: three of
# the entries added from the first real measurement were identifiers nobody had written
# down. A token has to be specific enough that a match says something, so a word that names
# a category rather than a product is dropped rather than searched for.
GENERIC_WORDS = frozenset(
    {
        "agent",
        "app",
        "assistant",
        "chat",
        "cli",
        "code",
        "coding",
        "desktop",
        "dev",
        "group",
        "ide",
        "inc",
        "labs",
        "llc",
        "ltd",
        "services",
        "software",
        "studio",
        "systems",
        "team",
        "technologies",
        "the",
        "tools",
    }
)


# The one entry in catalog/ that is not a product. Its paths belong to several agents at
# once, so there is no vendor to search for under a name.
NOT_A_PRODUCT = frozenset({"crosscutting"})


def tokens_of(agent):
    """The search words for one agent: its own name and its vendor's, minus the categories.

    Taken from the catalogue rather than typed for the same reason the probes are: a vendor
    that renames a product leaves a token behind that matches nothing, and a search that
    matches nothing looks exactly like a product that was never installed.

    Three characters is the floor. Two would match most of a home directory, and one agent
    in this catalogue has a two-letter name, so its identifiers have to be found through its
    probes instead.
    """
    if agent.agent in NOT_A_PRODUCT:
        return []
    words = []
    for word in re.split(r"[^A-Za-z0-9]+", agent.agent) + re.split(
        r"[^A-Za-z0-9]+", agent.vendor or ""
    ):
        word = word.lower()
        if len(word) >= 3 and word not in GENERIC_WORDS and word not in words:
            words.append(word)
    return words


def _platform_of(path):
    """Say which script can probe this path, or why neither can.

    The test is the path's own root rather than the entry's os list, because an entry lists
    every path it has for every platform it runs on: one entry carries the Windows spelling
    and the POSIX one side by side.
    """
    if path.startswith("<"):
        return None, SKIP_PROJECT
    if path.startswith("$") or path.startswith("${"):
        return None, SKIP_VARIABLE
    if path.startswith("HK"):
        return None, SKIP_REGISTRY
    if path.startswith("%"):
        return "windows", None
    if path.startswith("~") or path.startswith("/"):
        return "posix", None
    if re.match(r"^[A-Za-z]:", path):
        return "windows", None
    return None, SKIP_REGISTRY


def _truncate(path, separator):
    """Cut a pattern back to the deepest place a probe can stand.

    A placeholder in a directory component is cut away, because the walk below the probe
    reports whatever is under it. A wildcard in the file name is kept, because the shell
    expands that and a truncation there would probe the whole parent directory, which on
    macOS means listing every preferences file on the machine.
    """
    parts = path.rstrip("/\\").split(separator)
    for index, part in enumerate(parts):
        if NOT_LITERAL.search(part):
            if index == len(parts) - 1:
                return separator.join(parts), True
            return separator.join(parts[:index]), False
    return separator.join(parts), False


# Directory names that belong to the platform rather than to a product. A shared ancestor
# whose last component is one of these is not a probe: walking it would list every
# application on the machine, which is both useless and somebody's business.
PLATFORM_DIRS = frozenset(
    {
        ".cache",
        ".config",
        ".local",
        "appdata",
        "application scripts",
        "application support",
        "applications",
        "bin",
        "caches",
        "containers",
        "etc",
        "group containers",
        "home",
        "httpstorages",
        "library",
        "local",
        "locallow",
        "logs",
        "opt",
        "packages",
        "preferences",
        "program files",
        "programs",
        "roaming",
        "saved application state",
        "sbin",
        "share",
        "tmp",
        "user",
        "users",
        "usr",
        "var",
        "webkit",
        "windows",
    }
)

# How many named components a shared ancestor needs before it may be walked. Two is the
# home directory plus one name, which is the shape of every dot directory an agent owns.
# An absolute path's leading separator is not a name, so /usr needs one more before it
# counts, which is the point: nothing in this catalogue justifies walking /usr.
MIN_ANCESTOR_PARTS = 2


def _is_container(path, separator):
    """True for a directory that belongs to the platform rather than to a product.

    The catalogue claims a few of these on purpose: which program directories exist under
    the roaming profile is install evidence, and one entry says so. A probe still must not
    walk one, because a walk of the roaming profile is a listing of everything the person
    has installed, most of which is nobody's business here. It is answered present or
    absent instead, and the by-name search beside it lists the children that match the
    product.
    """
    named = [part for part in path.split(separator) if part]
    if len(named) < MIN_ANCESTOR_PARTS:
        return True
    return named[-1].lower() in PLATFORM_DIRS


def _ancestors(probes, separator):
    """The trees worth walking: a directory two or more catalogue paths share.

    A family's entries name the leaves they know about, and a walk of the leaves finds
    exactly what the catalogue already says is there. The discovery is one level up: a
    subdirectory nobody has written down sits next to the ones that are, and six entries in
    this catalogue exist because a walk of the shared tree found one. So the shared tree is
    a probe of its own, and the leaves under it become one-line answers rather than a second
    copy of the same walk.
    """
    counts = {}
    for path, ids, is_glob in probes:
        if is_glob:
            continue
        parts = path.split(separator)
        for cut in range(1, len(parts)):
            candidate = separator.join(parts[:cut])
            named = [part for part in parts[:cut] if part]
            if len(named) < MIN_ANCESTOR_PARTS:
                continue
            if named[-1].lower() in PLATFORM_DIRS:
                continue
            counts.setdefault(candidate, set()).update(ids)
    shared = {
        candidate: ids
        for candidate, ids in counts.items()
        if sum(1 for path, _, glob in probes if not glob and path.startswith(candidate + separator))
        >= 2
    }
    # Only the outermost of a nested pair, because the walk of that one already covers the
    # other.
    maximal = []
    for candidate in sorted(shared, key=len):
        if not any(candidate.startswith(kept + separator) for kept in maximal):
            maximal.append(candidate)
    return [(candidate, shared[candidate]) for candidate in maximal]


def _plan(probes, separator):
    """Every probe with the one thing the script needs to know: walk it, or just check it.

    A probe under a walked tree is reported present or absent and not walked, so no path
    appears twice in the output and every entry still gets its own line.
    """
    merged = {}
    for path, ids, is_glob in probes:
        key = (path, is_glob)
        merged.setdefault(key, set()).update(ids)
    for candidate, ids in _ancestors(
        [(path, ids, glob) for (path, glob), ids in merged.items()], separator
    ):
        merged.setdefault((candidate, False), set()).update(ids)

    walked = [
        path
        for (path, glob), _ in merged.items()
        if not glob and not _is_container(path, separator)
    ]
    planned = []
    for (path, _glob), ids in merged.items():
        covered = any(path != other and path.startswith(other + separator) for other in walked)
        how = "check" if covered or _is_container(path, separator) else "walk"
        planned.append((path, sorted(ids), how))
    return sorted(planned)


def collect(catalogue, platform):
    """Every probe one script needs, per agent, with the entry ids behind each."""
    separator = "\\" if platform == "windows" else "/"
    families = {}
    tokens = {}
    skipped = {}
    for agent in catalogue.agents:
        found = {}
        for artifact in agent.artifacts:
            for path in artifact.paths:
                where, reason = _platform_of(path)
                if where is None:
                    skipped[reason] = skipped.get(reason, 0) + 1
                    continue
                if where != platform:
                    skipped[SKIP_OTHER_OS] = skipped.get(SKIP_OTHER_OS, 0) + 1
                    continue
                probe, is_glob = _truncate(path, separator)
                if not is_glob and probe != path.rstrip("/\\"):
                    lowered = probe.lower()
                    if any(
                        lowered == root.lower() or lowered.startswith(root.lower() + separator)
                        for root in SHARED_SCRATCH
                    ):
                        skipped[SKIP_SHARED] = skipped.get(SKIP_SHARED, 0) + 1
                        continue
                if not probe or probe in ("~", "/"):
                    # A path whose first component is already a placeholder. Nothing here
                    # can be probed without walking the whole home directory.
                    skipped[SKIP_PROJECT] = skipped.get(SKIP_PROJECT, 0) + 1
                    continue
                key = (probe, is_glob)
                found.setdefault(key, set()).add(artifact.id)
        if found:
            families[agent.agent] = _plan(
                [(probe, ids, is_glob) for (probe, is_glob), ids in found.items()], separator
            )
            tokens[agent.agent] = tokens_of(agent)
    return families, tokens, skipped


def _sh_block(families, tokens, skipped):
    out = [
        BEGIN,
        "# Regenerate with: uv run python scripts/gen_layout_probes.py",
        "#",
        "# One line per probe: walk or check, the catalogue entries that claim it, then",
        "# the path. A walk lists the tree below it, a check answers present or absent",
        "# for a path some other walk already covers. A wildcard is expanded by the shell.",
        "#",
        "# Not probed from this catalogue, and the reasons are in the generator's docstring:",
    ]
    for reason in sorted(skipped):
        out.append("#   %4d path(s) %s" % (skipped[reason], reason))
    out.append("probes_for() {")
    out.append('    case "$1" in')
    for family in sorted(families):
        out.append("    %s)" % family)
        out.append("        cat <<'PROBES'")
        for probe, ids, how in sorted(families[family]):
            out.append("%s %s %s" % (how, ",".join(ids), probe))
        out.append("PROBES")
        out.append("        ;;")
    out.append("    *)")
    out.append("        return 1")
    out.append("        ;;")
    out.append("    esac")
    out.append("}")
    out.append("")
    out.append("tokens_for() {")
    out.append('    case "$1" in')
    for family in sorted(tokens):
        if tokens[family]:
            out.append("    %s) echo '%s' ;;" % (family, " ".join(tokens[family])))
    out.append("    *) return 1 ;;")
    out.append("    esac")
    out.append("}")
    out.append("")
    out.append("ALL_FAMILIES='%s'" % " ".join(sorted(families)))
    out.append(END)
    return "\n".join(out) + "\n"


def _ps1_block(families, tokens, skipped):
    out = [
        BEGIN,
        "# Regenerate with: uv run python scripts/gen_layout_probes.py",
        "#",
        "# One line per probe: walk or check, the catalogue entries that claim it, then",
        "# the path. A walk lists the tree below it, a check answers present or absent",
        "# for a path some other walk already covers. An environment variable in percent",
        "# signs is expanded at run time.",
        "#",
        "# Not probed from this catalogue, and the reasons are in the generator's docstring:",
    ]
    for reason in sorted(skipped):
        out.append("#   %4d path(s) %s" % (skipped[reason], reason))
    out.append("$Probes = @{")
    for family in sorted(families):
        out.append("    '%s' = @(" % family)
        for probe, ids, how in sorted(families[family]):
            # Single quotes, and a single quote inside a path would be doubled. No
            # catalogue path has one, and if one arrives this keeps the script parsable.
            out.append("        '%s %s %s'" % (how, ",".join(ids), probe.replace("'", "''")))
        out.append("    )")
    out.append("}")
    out.append("")
    out.append("$Tokens = @{")
    for family in sorted(tokens):
        if tokens[family]:
            out.append("    '%s' = @('%s')" % (family, "', '".join(tokens[family])))
    out.append("}")
    out.append(END)
    return "\n".join(out) + "\n"


def _replace(text, block):
    start = text.index(BEGIN)
    stop = text.index(END) + len(END) + 1
    return text[:start] + block + text[stop:]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; fail if the committed scripts differ (the CI mode)",
    )
    args = parser.parse_args(argv)

    try:
        catalogue = load_catalogue(CATALOG_DIR)
    except CatalogueError as exc:
        sys.stderr.write("gen-layout-probes: %s\n" % exc)
        return 2

    problems = 0
    for target, platform, render in ((SH, "posix", _sh_block), (PS1, "windows", _ps1_block)):
        families, tokens, skipped = collect(catalogue, platform)
        block = render(families, tokens, skipped)
        current = target.read_text(encoding="utf-8")
        if BEGIN not in current or END not in current:
            sys.stderr.write("gen-layout-probes: %s has no generated block\n" % target.name)
            return 2
        wanted = _replace(current, block)
        count = sum(len(probes) for probes in families.values())
        if args.check:
            if current != wanted:
                problems += 1
                sys.stderr.write("gen-layout-probes: %s is out of date\n" % target.name)
        else:
            if current != wanted:
                target.write_text(wanted, encoding="utf-8")
            sys.stderr.write(
                "gen-layout-probes: %s, %d probe(s) across %d agent(s)\n"
                % (target.name, count, len(families))
            )

    if problems:
        sys.stderr.write(
            "\nRun scripts/gen_layout_probes.py to regenerate. Never edit the probe block "
            "by hand: the catalogue is the source of truth, and a hand-written probe list "
            "is the defect this generator exists to prevent.\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
