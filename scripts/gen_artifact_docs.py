#!/usr/bin/env python3
"""Generate docs/ARTIFACTS.md and docs/ARTIFACTS.de.md from the catalogue.

The catalogue is the single source of truth (ADR 0003), so this document is output and
never input. CI regenerates it with --check and fails on any difference, which is the only
way a hand-edit could otherwise survive.

The document is organised by collection priority rather than alphabetically. That is a
deliberate choice about what an analyst needs at the moment they read it: under time
pressure the question is not "what exists" but "what disappears first", and a list sorted
by name buries the two artifacts that a clean shutdown destroys.

Written to stay inside this directory's Python 3.8 lint target (see .ruff.toml), even
though importing the analyzer package means it only runs on 3.14 or newer.
"""

from __future__ import annotations

import argparse
import difflib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

import yaml  # noqa: E402
from agentforensics.catalog import (  # noqa: E402
    COLLECT_PRIORITY_ORDER,
    AgentCatalog,
    Artifact,
    Catalogue,
    CatalogueError,
    load_catalogue,
    resolve_text,
)

CATALOG_DIR = REPO_ROOT / "catalog"
DOCS_DIR = REPO_ROOT / "docs"
LOCALES_DIR = DOCS_DIR / "locales"

OS_LABELS = {"macos": "macOS", "windows": "Windows", "linux": "Linux"}

# Explanations of the collection-priority groups. These are the point of the document, so
# they live here next to the layout rather than in the locale file with the column headings.
PRIORITY_TEXT = {
    "en": {
        "live_only": (
            "**Collect from a running machine or not at all.** These exist only while the "
            "agent or the session is running, or are destroyed by a clean shutdown. They "
            "cannot be recovered from a powered-off image, so if the endpoint is still up, "
            "start here."
        ),
        "first": (
            "**Collect first.** Rotated or swept aggressively, by count or on every sweep "
            "rather than after a comfortable interval. Some of these can be destroyed by "
            "the user simply starting another session."
        ),
        "normal": (
            "**Collect normally.** Subject to the agent's ordinary retention period, which "
            "for several agents defaults to 30 days."
        ),
        "durable": (
            "**Usually still there.** Not covered by the retention sweep, so these "
            "routinely outlive the transcripts they describe. When the transcripts are "
            "already gone, this group is what is left, and it is often enough to establish "
            "that an agent ran, what it was allowed to do, and what the user asked."
        ),
    },
    "de": {
        "live_only": (
            "**Nur am laufenden System zu holen.** Diese Artefakte existieren nur, solange "
            "der Agent oder die Sitzung läuft, oder werden beim saubern Herunterfahren "
            "zerstört. Aus einem abgeschalteten Abbild sind sie nicht wiederherstellbar. "
            "Läuft das Endgerät noch, dann hier anfangen."
        ),
        "first": (
            "**Zuerst sichern.** Rotieren oder verfallen aggressiv, nach Anzahl oder bei "
            "jedem Aufräumlauf statt nach einer bequemen Frist. Einige davon zerstört die "
            "Benutzerin schon dadurch, dass sie eine weitere Sitzung startet."
        ),
        "normal": (
            "**Normal sichern.** Unterliegen der üblichen Aufbewahrungsfrist des Agenten, "
            "die bei mehreren Agenten standardmässig 30 Tage beträgt."
        ),
        "durable": (
            "**Meist noch vorhanden.** Vom Aufräumlauf nicht erfasst und überleben damit "
            "regelmässig die Transkripte, die sie beschreiben. Sind die Transkripte schon "
            "weg, ist diese Gruppe das, was bleibt, und sie genügt oft, um zu belegen, dass "
            "ein Agent lief, was er durfte und was gefragt wurde."
        ),
    },
}


def load_locale(lang: str) -> dict[str, str]:
    path = LOCALES_DIR / ("%s.yaml" % lang)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data["artifacts"]


def esc(text: str) -> str:
    """Make free text safe inside a Markdown table cell.

    Newlines would break the row and a pipe would create a phantom column, which silently
    shifts every later cell in that row into the wrong heading.
    """
    return text.replace("|", "\\|").replace("\n", " ").strip()


def code_list(values: tuple[str, ...]) -> str:
    return "<br>".join("`%s`" % esc(v) for v in values) if values else ""


def path_list(artifact: Artifact, loc: dict[str, str]) -> str:
    """The paths, with the ones the cited source does not state marked as such.

    A verified artifact can still carry a leaf path its source says nothing about. Showing
    the marker per path rather than per entry is the only way an analyst can tell which of
    the two an empty result belongs to.
    """
    marked = []
    for value in artifact.paths:
        cell = "`%s`" % esc(value)
        if value in artifact.unsourced_paths:
            cell += " %s" % loc["unsourced_marker"]
        marked.append(cell)
    return "<br>".join(marked)


def artifact_row(artifact: Artifact, loc: dict[str, str], lang: str) -> str:
    name = artifact.title or artifact.id.split(".", 1)[1].replace("_", " ")
    status = loc["status_verified"] if artifact.is_verified else loc["status_unverified"]
    if not artifact.is_verified:
        status = "**%s**" % status
    source = artifact.source
    link = "[%s](%s)" % (artifact.source_kind, source) if source.startswith("http") else esc(source)

    volatility, translated = resolve_text(artifact.volatility, lang)
    if volatility and not translated:
        volatility = "%s %s" % (loc["untranslated_marker"], volatility)

    cells = [
        "`%s`" % artifact.id,
        esc(name),
        artifact.category,
        ", ".join(OS_LABELS.get(o, o) for o in artifact.os),
        path_list(artifact, loc),
        artifact.format,
        artifact.sensitivity,
        esc(volatility),
        status,
        link,
    ]
    return "| " + " | ".join(cells) + " |"


def agent_section(agent: AgentCatalog, loc: dict[str, str], lang: str) -> list[str]:
    out = ["## %s" % agent.title, ""]
    if agent.vendor:
        out.append("Vendor: %s" % agent.vendor)
        out.append("")
    description, translated = resolve_text(agent.description, lang)
    if description:
        if not translated:
            description = "%s %s" % (loc["untranslated_marker"], description)
        out.extend([description, ""])
    if agent.references:
        out.append(", ".join("<%s>" % r for r in agent.references))
        out.append("")

    if agent.env_overrides:
        out.append(
            "### %s" % ("Relocating variables" if lang == "en" else "Verschiebende Variablen")
        )
        out.append("")
        for env in agent.env_overrides:
            effect, translated = resolve_text(env.effect, lang)
            if not translated:
                effect = "%s %s" % (loc["untranslated_marker"], effect)
            out.append("- `%s`: %s" % (env.name, effect))
        out.append("")

    header = "| %s |" % " | ".join(
        [
            loc["col_id"],
            "Name",
            loc["col_category"],
            loc["col_os"],
            loc["col_paths"],
            loc["col_format"],
            loc["col_sensitivity"],
            loc["col_volatility"],
            loc["col_status"],
            loc["col_source"],
        ]
    )
    divider = "| " + " | ".join(["---"] * 10) + " |"

    for priority in COLLECT_PRIORITY_ORDER:
        group = [a for a in agent.artifacts if a.collect_priority == priority]
        if not group:
            continue
        out.append("### %s" % priority)
        out.append("")
        out.append(PRIORITY_TEXT[lang][priority])
        out.append("")
        out.append(header)
        out.append(divider)
        for artifact in sorted(group, key=lambda a: a.id):
            out.append(artifact_row(artifact, loc, lang))
        out.append("")

    legacy = [a for a in agent.artifacts if a.legacy]
    if legacy:
        label = (
            "Paths below are no longer written or read by current versions. They are still "
            "collected, because they are evidence of an older installation, but the "
            "analyzer must never present them as live state."
            if lang == "en"
            else "Die folgenden Pfade werden von aktuellen Versionen nicht mehr geschrieben "
            "oder gelesen. Sie werden trotzdem gesammelt, weil sie eine ältere Installation "
            "belegen, dürfen aber nie als aktueller Zustand dargestellt werden."
        )
        out.append("### %s" % ("Legacy paths" if lang == "en" else "Veraltete Pfade"))
        out.append("")
        out.append(label)
        out.append("")
        for a in sorted(legacy, key=lambda a: a.id):
            out.append("- `%s`: %s" % (a.id, code_list(a.paths).replace("<br>", ", ")))
        out.append("")
    return out


def render(catalogue: Catalogue, lang: str) -> str:
    loc = load_locale(lang)
    other = "ARTIFACTS.de.md" if lang == "en" else "ARTIFACTS.md"
    other_label = "Deutsch" if lang == "en" else "English"
    this_label = "English" if lang == "en" else "Deutsch"

    verified = sum(1 for a in catalogue.artifacts if a.is_verified)
    total = len(catalogue.artifacts)

    out = [
        "# %s" % loc["title"],
        "",
        ("%s | [%s](%s)" % (this_label, other_label, other))
        if lang == "en"
        else ("[%s](%s) | %s" % (other_label, other, this_label)),
        "",
        "<!-- Generated file. Do not edit. -->",
        "",
        loc["generated_note"],
        "",
        (
            "%d artifacts across %d agent(s), %d of them resting on a fetched vendor source."
            % (total, len(catalogue), verified)
            if lang == "en"
            else "%d Artefakte über %d Agent(en), davon %d auf einer abgerufenen "
            "Herstellerquelle beruhend." % (total, len(catalogue), verified)
        ),
        "",
        loc["unverified_warning"],
        "",
        loc["unsourced_warning"],
        "",
        # Said in the generated reference rather than only in an ADR, because this is the
        # file an analyst reads while deciding whether a missing artifact means anything.
        loc["verified_meaning"],
        "",
    ]
    for agent in catalogue:
        out.extend(agent_section(agent, loc, lang))
    text = "\n".join(out).rstrip() + "\n"
    return text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; fail if the committed file differs (the CI mode)",
    )
    args = parser.parse_args(argv)

    try:
        catalogue = load_catalogue(CATALOG_DIR)
    except CatalogueError as exc:
        sys.stderr.write("gen-artifact-docs: %s\n" % exc)
        return 2

    problems = 0
    for lang, name in (("en", "ARTIFACTS.md"), ("de", "ARTIFACTS.de.md")):
        target = DOCS_DIR / name
        text = render(catalogue, lang)
        if args.check:
            current = target.read_text(encoding="utf-8") if target.exists() else ""
            if current != text:
                problems += 1
                sys.stderr.write("gen-artifact-docs: %s is out of date\n" % name)
                diff = difflib.unified_diff(
                    current.splitlines(), text.splitlines(), "committed", "generated", lineterm=""
                )
                for line in list(diff)[:40]:
                    sys.stderr.write("  %s\n" % line)
        else:
            target.write_text(text, encoding="utf-8")
            sys.stderr.write("gen-artifact-docs: wrote %s\n" % name)

    if problems:
        sys.stderr.write(
            "\nRun scripts/gen_artifact_docs.py to regenerate. Never edit these files by "
            "hand: the catalogue is the source of truth.\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
