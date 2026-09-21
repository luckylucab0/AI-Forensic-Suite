#!/usr/bin/env python3
"""Generate docs/SUPPORT.md and docs/SUPPORT.de.md from the catalogue and the readers.

The question this page answers is the first one anybody asks of a forensic tool and the
one a feature list answers badly: which agents does it read, how completely, and what does
it not read. A hand-written answer to that goes stale the week after it is written, and a
stale answer here is worse than none, because somebody will conclude an agent was not used
from a tool that never looked.

So the page is output. Every number in it is counted from `catalog/` and from the reader
registry at generation time, and CI regenerates it with --check and fails on a difference.
The only prose is the part that explains what the numbers mean.

Four kinds of gap are reported separately, because they are four different answers to
"nothing came out for this agent" (see src/agentforensics/parsers/coverage.py):

  * a credential store, where the collector takes metadata and a hash by design;
  * a container in a format nobody has read, which is binary or a directory here;
  * an entry in a format this suite does read, with the reason written down;
  * unfinished work, which is the class this file exists to make visible. An entry in a
    readable format with no reason declared fails a test, so the page cannot understate it.

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

from agentforensics.catalog import (  # noqa: E402
    AgentCatalog,
    Artifact,
    Catalogue,
    CatalogueError,
    load_catalogue,
)
from agentforensics.model.event import EVENT_KINDS  # noqa: E402
from agentforensics.parsers import PARSERS, for_artifact  # noqa: E402
from agentforensics.parsers.coverage import (  # noqa: E402
    GENERIC_READERS,
    HANDED_OVER,
    READABLE_AND_UNREAD,
    READABLE_FORMATS,
)

CATALOG_DIR = REPO_ROOT / "catalog"
DOCS_DIR = REPO_ROOT / "docs"

OS_LABELS = {"macos": "macOS", "windows": "Windows", "linux": "Linux"}

# The prose. It sits here rather than in docs/locales because every sentence of it is about
# this page's own layout, and a label file is for the words that recur across documents.
TEXT = {
    "en": {
        "title": "Supported agents",
        "generated": "<!-- Generated file. Do not edit. Run scripts/gen_support_docs.py. -->",
        "intro": (
            "What this suite reads, per agent, counted from the catalogue and the reader "
            "registry rather than written down. The numbers move when the code does."
        ),
        "how_to_read": (
            "**How to read an empty result.** An agent listed here with artifacts read "
            "means the paths were searched and the files that were there were parsed, so "
            "an empty result is evidence that those paths held nothing. It is never "
            "evidence that the agent was not used: the data tree may have been relocated "
            "by a variable, the retention period may have swept it, the paths may be the "
            "unverified ones, or the user may have worked in a profile nobody collected. "
            "Where an entry is unverified, `docs/ARTIFACTS.md` says so per artifact and "
            "the analyzer repeats it in its output."
        ),
        "totals": (
            "%(agents)d catalogue files, %(products)d of them a product and one "
            "cross-cutting. %(read)d of %(total)d artifacts are read by %(readers)d reader "
            "modules, into %(kinds)d event kinds. %(verified)d artifacts rest on a fetched "
            "vendor source."
        ),
        "table_title": "## Per agent",
        "table_note": (
            "`transcripts` counts the entries filed as a conversation store. `read` counts "
            "every entry of the agent a reader claims, whatever its category: instruction "
            "files, MCP configuration, permission state, prompt and shell history, "
            "memories and logs are in that number and are often what answers the question "
            "when the transcripts are gone. `at the floor` counts the entries read by a "
            "generic reader, which returns the content and decides nothing about what a "
            "record means."
        ),
        "columns": ("Agent", "OS", "Transcripts", "Read", "At the floor", "Not read"),
        "gaps_title": "## What is not read, and why",
        "gaps_intro": (
            "Every artifact in the catalogue is collected and appears in a case, whether a "
            "reader claims it or not: an entry with no reader still produces one filesystem "
            "event carrying its path, hash and timestamps. What follows is what is missing "
            "beyond that, in four groups, because they are four different answers."
        ),
        "credentials_title": "### Credential stores: metadata and a hash, by design",
        "credentials": (
            "%(count)d entries. The collector records the path, the size, the timestamps and "
            "the hash, and copies no content unless it is told to, so there is nothing for a "
            "reader to read. That is a decision rather than a gap: the file is evidence that "
            "an agent was authenticated and to which provider, and the token in it is not "
            "what an investigation needs."
        ),
        "handed_title": "### Collected and handed to the reader that is better at it",
        "handed": (
            "%(count)d entries. Each is collected whole and deliberately not parsed here, "
            "because a reader for that format already exists and is the one a report will "
            "be challenged on."
        ),
        "unknown_title": "### Containers in a format nobody here has read",
        "unknown": (
            "%(count)d entries, binary or directory layouts with no documented format. Each "
            "one is collected whole and is on the timeline as a filesystem event. Reading "
            "one means writing a format implementation, not finishing an unfinished reader."
        ),
        "declared_title": "### Readable formats with a reason",
        "declared": (
            "%(count)d entries are in a format this suite reads and are claimed by no "
            "reader, each with the reason recorded in the code beside the decision. A new "
            "entry in this state fails a test until somebody either reads it or writes the "
            "reason down, which is what keeps this list from becoming the unfinished-work "
            "list by accident."
        ),
        "unfinished_title": "### Unfinished work on a format that is already read",
        "unfinished_none": (
            "None as of this generation. The check behind this section looks for a "
            "catalogue entry in a format this suite already reads, with no reader and no "
            "reason: that is the shape unfinished work takes here, and there is none."
        ),
        "unfinished_some": (
            "These entries are in a format this suite already reads, have no reader and no "
            "recorded reason. That is unfinished work and it is named here rather than left "
            "for somebody to infer from a thin case:"
        ),
        "thin_title": "## Where the reading is thin",
        "thin": (
            "%(count)d artifacts are read by a generic reader. The file is read completely "
            "and every record is in the case with its content; what the record means is not "
            "decided, and each one says so on itself. Two kinds of record carry that "
            "statement: `unparsed.record` for something nothing could read, and a record "
            "marked as returned uninterpreted for something read whose format nobody has "
            "mapped. The counts are separate in every summary this suite prints, because a "
            "store nobody has a schema for and a half-written file are opposite problems."
        ),
        "next_title": "## Where to look next",
        "next": (
            "`docs/ARTIFACTS.md` for every path of every artifact with its source and "
            "verification state, `docs/UNIFIED_FORMAT.md` for the format the readers produce, "
            "`docs/COLLECTION.md` for what a collection takes."
        ),
        "none": "none",
    },
    "de": {
        "title": "Unterstützte Agenten",
        "generated": "<!-- Generierte Datei. Nicht bearbeiten. scripts/gen_support_docs.py ausführen. -->",
        "intro": (
            "Was diese Suite pro Agent liest, gezählt aus dem Katalog und der "
            "Leser-Registrierung statt aufgeschrieben. Die Zahlen bewegen sich mit dem Code."
        ),
        "how_to_read": (
            "**Wie ein leeres Ergebnis zu lesen ist.** Steht ein Agent hier mit gelesenen "
            "Artefakten, dann wurden die Pfade durchsucht und die vorhandenen Dateien "
            "ausgewertet, also ist ein leeres Ergebnis ein Befund über diese Pfade. Es ist "
            "nie ein Befund darüber, dass der Agent nicht benutzt wurde: der Datenbaum kann "
            "über eine Variable verschoben sein, die Aufbewahrungsfrist kann ihn gelöscht "
            "haben, die Pfade können die unverifizierten sein, oder die Person hat in einem "
            "Profil gearbeitet, das niemand gesammelt hat. Wo ein Eintrag unverifiziert ist, "
            "sagt `docs/ARTIFACTS.de.md` es pro Artefakt, und der Analyzer wiederholt es in "
            "seiner Ausgabe."
        ),
        "totals": (
            "%(agents)d Katalogdateien, davon %(products)d ein Produkt und eine "
            "übergreifende. %(read)d von %(total)d Artefakten werden von %(readers)d "
            "Leser-Modulen gelesen, in %(kinds)d Ereignisarten. %(verified)d Artefakte "
            "beruhen auf einer abgerufenen Herstellerquelle."
        ),
        "table_title": "## Pro Agent",
        "table_note": (
            "`Transkripte` zählt die Einträge, die als Konversationsspeicher geführt sind. "
            "`Gelesen` zählt jeden Eintrag des Agenten, den ein Leser beansprucht, egal in "
            "welcher Kategorie: Instruktionsdateien, MCP-Konfiguration, Berechtigungszustand, "
            "Prompt- und Shell-Historie, Erinnerungen und Logs stecken in dieser Zahl und "
            "sind oft das, was die Frage beantwortet, wenn die Transkripte weg sind. `Am "
            "Boden` zählt die Einträge, die ein generischer Leser liest, der den Inhalt "
            "zurückgibt und nichts darüber entscheidet, was ein Record bedeutet."
        ),
        "columns": ("Agent", "OS", "Transkripte", "Gelesen", "Am Boden", "Nicht gelesen"),
        "gaps_title": "## Was nicht gelesen wird, und warum",
        "gaps_intro": (
            "Jedes Artefakt im Katalog wird gesammelt und erscheint im Fall, ob ein Leser es "
            "beansprucht oder nicht: ein Eintrag ohne Leser erzeugt weiterhin ein "
            "Dateisystem-Ereignis mit Pfad, Hash und Zeitstempeln. Was folgt, ist das, was "
            "darüber hinaus fehlt, in vier Gruppen, weil es vier verschiedene Antworten sind."
        ),
        "credentials_title": "### Credential-Speicher: Metadaten und Hash, absichtlich",
        "credentials": (
            "%(count)d Einträge. Der Collector hält Pfad, Grösse, Zeitstempel und Hash fest "
            "und kopiert keinen Inhalt, solange es ihm nicht gesagt wird, also gibt es für "
            "einen Leser nichts zu lesen. Das ist eine Entscheidung und keine Lücke: die "
            "Datei belegt, dass ein Agent authentisiert war und bei welchem Anbieter, und "
            "das Token darin ist nicht, was eine Untersuchung braucht."
        ),
        "handed_title": "### Gesammelt und dem Leser übergeben, der es besser kann",
        "handed": (
            "%(count)d Einträge. Jeder wird ganz gesammelt und hier absichtlich nicht "
            "ausgewertet, weil für dieses Format schon ein Leser existiert und es der ist, "
            "an dem ein Bericht gemessen wird."
        ),
        "unknown_title": "### Container in einem Format, das hier niemand gelesen hat",
        "unknown": (
            "%(count)d Einträge, binäre oder Verzeichnis-Layouts ohne dokumentiertes Format. "
            "Jeder wird ganz gesammelt und steht als Dateisystem-Ereignis auf der Zeitlinie. "
            "Einen davon zu lesen heisst, eine Formatimplementierung zu schreiben, und nicht, "
            "einen unfertigen Leser fertigzustellen."
        ),
        "declared_title": "### Lesbare Formate mit einer Begründung",
        "declared": (
            "%(count)d Einträge liegen in einem Format, das diese Suite liest, und werden von "
            "keinem Leser beansprucht, jeder mit der Begründung im Code neben der "
            "Entscheidung. Ein neuer Eintrag in diesem Zustand lässt einen Test scheitern, "
            "bis jemand ihn entweder liest oder die Begründung hinschreibt, und genau das "
            "verhindert, dass diese Liste versehentlich die Liste der unfertigen Arbeiten wird."
        ),
        "unfinished_title": "### Unfertige Arbeit an einem Format, das schon gelesen wird",
        "unfinished_none": (
            "Zum Zeitpunkt dieser Generierung keine. Die Prüfung hinter diesem Abschnitt "
            "sucht einen Katalogeintrag in einem Format, das diese Suite schon liest, ohne "
            "Leser und ohne Begründung: so sieht unfertige Arbeit hier aus, und es gibt keine."
        ),
        "unfinished_some": (
            "Diese Einträge liegen in einem Format, das diese Suite schon liest, haben keinen "
            "Leser und keine festgehaltene Begründung. Das ist unfertige Arbeit, und sie steht "
            "hier, statt dass jemand sie aus einem dünnen Fall erschliessen muss:"
        ),
        "thin_title": "## Wo die Lesung dünn ist",
        "thin": (
            "%(count)d Artefakte werden von einem generischen Leser gelesen. Die Datei wird "
            "vollständig gelesen und jeder Record steht mit seinem Inhalt im Fall; was der "
            "Record bedeutet, ist nicht entschieden, und jeder sagt das an sich selbst. Zwei "
            "Arten von Record tragen diese Aussage: `unparsed.record` für etwas, das niemand "
            "lesen konnte, und ein als uninterpretiert zurückgegebener Record für etwas "
            "Gelesenes, dessen Format niemand abgebildet hat. In jeder Zusammenfassung dieser "
            "Suite sind die beiden getrennt gezählt, denn ein Speicher ohne Schema und eine "
            "halb geschriebene Datei sind entgegengesetzte Probleme."
        ),
        "next_title": "## Wo es weitergeht",
        "next": (
            "`docs/ARTIFACTS.de.md` für jeden Pfad jedes Artefakts mit Quelle und "
            "Verifikationsstand, `docs/UNIFIED_FORMAT.md` für das Format, das die Leser "
            "erzeugen, `docs/COLLECTION.md` für das, was eine Sammlung mitnimmt."
        ),
        "none": "keine",
    },
}


def reader_name(artifact: Artifact) -> str:
    """The reader that claims this artifact, or "" when none does."""
    parser = for_artifact(artifact.id)
    return parser.name if parser is not None else ""


def unread_group(artifact: Artifact) -> str:
    """Which of the five answers applies to an artifact no reader claims."""
    if artifact.id in HANDED_OVER:
        return "handed_over"
    if artifact.sensitivity == "secret":
        return "credentials"
    if artifact.format not in READABLE_FORMATS:
        return "unknown_format"
    if artifact.id in READABLE_AND_UNREAD:
        return "declared"
    return "unfinished"


def agent_row(agent: AgentCatalog, lang: str) -> str:
    transcripts = [a for a in agent.artifacts if a.category == "transcript"]
    read = [a for a in agent.artifacts if reader_name(a)]
    floor = [a for a in read if reader_name(a) in GENERIC_READERS]
    unread = len(agent.artifacts) - len(read)
    systems = sorted({os_name for a in agent.artifacts for os_name in a.os})
    return "| %s | %s | %s | %d / %d | %d | %d |" % (
        agent.title,
        ", ".join(OS_LABELS.get(name, name) for name in systems),
        (
            "%d / %d" % (sum(1 for a in transcripts if reader_name(a)), len(transcripts))
            if transcripts
            else TEXT[lang]["none"]
        ),
        len(read),
        len(agent.artifacts),
        len(floor),
        unread,
    )


def render(catalogue: Catalogue, lang: str) -> str:
    text = TEXT[lang]
    other = "SUPPORT.de.md" if lang == "en" else "SUPPORT.md"
    other_label = "Deutsch" if lang == "en" else "English"
    this_label = "English" if lang == "en" else "Deutsch"

    artifacts = list(catalogue.artifacts)
    read = [a for a in artifacts if reader_name(a)]
    groups = {
        "credentials": [],
        "handed_over": [],
        "unknown_format": [],
        "declared": [],
        "unfinished": [],
    }
    for artifact in artifacts:
        if not reader_name(artifact):
            groups[unread_group(artifact)].append(artifact)

    out = [
        "# %s" % text["title"],
        "",
        ("%s | [%s](%s)" % (this_label, other_label, other))
        if lang == "en"
        else ("[%s](%s) | %s" % (other_label, other, this_label)),
        "",
        text["generated"],
        "",
        text["intro"],
        "",
        text["totals"]
        % {
            "agents": len(catalogue),
            "products": len(catalogue) - 1,
            "read": len(read),
            "total": len(artifacts),
            "readers": len(PARSERS),
            "kinds": len(EVENT_KINDS),
            "verified": sum(1 for a in artifacts if a.is_verified),
        },
        "",
        text["how_to_read"],
        "",
        text["table_title"],
        "",
        text["table_note"],
        "",
        "| " + " | ".join(text["columns"]) + " |",
        "| " + " | ".join("---" for _ in text["columns"]) + " |",
    ]
    for agent in sorted(catalogue, key=lambda a: a.title.lower()):
        out.append(agent_row(agent, lang))
    out.extend(["", text["gaps_title"], "", text["gaps_intro"], ""])

    out.extend(
        [
            text["credentials_title"],
            "",
            text["credentials"] % {"count": len(groups["credentials"])},
            "",
            text["handed_title"],
            "",
            text["handed"] % {"count": len(groups["handed_over"])},
            "",
        ]
    )
    for artifact in sorted(groups["handed_over"], key=lambda a: a.id):
        out.append("- `%s`: %s" % (artifact.id, HANDED_OVER[artifact.id]))
    out.extend(
        [
            "",
            text["unknown_title"],
            "",
            text["unknown"] % {"count": len(groups["unknown_format"])},
            "",
        ]
    )
    for artifact in sorted(groups["unknown_format"], key=lambda a: a.id):
        out.append("- `%s` (%s)" % (artifact.id, artifact.format))
    out.extend(
        [
            "",
            text["declared_title"],
            "",
            text["declared"] % {"count": len(groups["declared"])},
            "",
        ]
    )
    for artifact in sorted(groups["declared"], key=lambda a: a.id):
        out.append("- `%s`: %s" % (artifact.id, READABLE_AND_UNREAD[artifact.id].reason))
    out.extend(["", text["unfinished_title"], ""])
    if groups["unfinished"]:
        out.append(text["unfinished_some"])
        out.append("")
        for artifact in sorted(groups["unfinished"], key=lambda a: a.id):
            out.append("- `%s` (%s)" % (artifact.id, artifact.format))
    else:
        out.append(text["unfinished_none"])
    floor = [a for a in read if reader_name(a) in GENERIC_READERS]
    out.extend(
        [
            "",
            text["thin_title"],
            "",
            text["thin"] % {"count": len(floor)},
            "",
            text["next_title"],
            "",
            text["next"],
        ]
    )
    return "\n".join(out).rstrip() + "\n"


def main(argv: list | None = None) -> int:
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
        sys.stderr.write("gen-support-docs: %s\n" % exc)
        return 2

    problems = 0
    for lang, name in (("en", "SUPPORT.md"), ("de", "SUPPORT.de.md")):
        target = DOCS_DIR / name
        text = render(catalogue, lang)
        if args.check:
            current = target.read_text(encoding="utf-8") if target.exists() else ""
            if current != text:
                problems += 1
                sys.stderr.write("gen-support-docs: %s is out of date\n" % name)
                diff = difflib.unified_diff(
                    current.splitlines(), text.splitlines(), "committed", "generated", lineterm=""
                )
                for line in list(diff)[:40]:
                    sys.stderr.write("  %s\n" % line)
        else:
            target.write_text(text, encoding="utf-8")
            sys.stderr.write("gen-support-docs: wrote %s\n" % name)

    if problems:
        sys.stderr.write(
            "\nRun scripts/gen_support_docs.py to regenerate. Never edit these files by "
            "hand: the catalogue and the readers are the source of truth.\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
