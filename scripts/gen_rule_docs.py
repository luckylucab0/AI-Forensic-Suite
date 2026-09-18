#!/usr/bin/env python3
"""Generate docs/RULES.md and docs/RULES.de.md from the rule files.

The rule files are the source of truth, so this document is output and never input. CI
regenerates it with --check and fails on any difference, which is the only way a hand-edit
would otherwise survive.

Two things this document does that a list of rule titles would not.

It prints each rule's condition in words, rendered from the compiled condition rather than
from the YAML. So the reference cannot drift from what the rule actually does: if the two
disagreed, the compiled form is the one that runs, and it is the one shown here.

It prints each rule's rationale and its known false positives, at the same level as the
condition. That is the honest shape for a detection reference. A reader deciding whether to
act on a finding needs to know what the rule fires on wrongly at least as much as what it
fires on, and a pack that buried the false positives would be a pack that gets trusted too
much and then not at all.

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
from agentforensics.rules import PACKS, RuleError, load  # noqa: E402

RULES_DIR = REPO_ROOT / "rules"
DOCS_DIR = REPO_ROOT / "docs"
LOCALES_DIR = DOCS_DIR / "locales"

# What each pack is for, in one sentence. Here rather than in a file next to the rules
# because it is documentation about the layout, and because a pack with no rules in it yet
# still has to appear in the reference: a reader has to be able to tell a pack that found
# nothing from a pack that does not exist.
PACK_INTROS = {
    "secrets": {
        "en": "Credentials that reached a transcript. These rules search the whole record "
        "rather than the mapped fields, because a credential can sit anywhere in one, "
        "including in a field no parser understood. None of them quotes what it matched.",
        "de": "Zugangsdaten, die in ein Transkript geraten sind. Diese Regeln durchsuchen "
        "den ganzen Datensatz statt der abgebildeten Felder, denn ein Zugangsdatum kann "
        "überall darin stehen, auch in einem Feld, das kein Parser verstanden hat. Keine "
        "von ihnen zitiert, worauf sie getroffen hat.",
    },
    "dangerous_commands": {
        "en": "Commands whose effect is hard to undo or hard to establish afterwards. Two "
        "of these are about destruction and one is about a timeline that can no longer be "
        "trusted, which is a different kind of loss and just as relevant.",
        "de": "Befehle, deren Wirkung schwer rückgängig zu machen oder hinterher schwer "
        "festzustellen ist. Zwei davon betreffen Zerstörung, eine eine Zeitachse, der "
        "nicht mehr zu trauen ist, und das ist ein anderer Verlust und genauso relevant.",
    },
    "sensitive_paths": {
        "en": "Paths an agent read that hold credentials or the map to them. What makes a "
        "read a finding is the destination: the contents went into a conversation with a "
        "model provider and onto disk in a transcript.",
        "de": "Pfade, die ein Agent gelesen hat und die Zugangsdaten oder die Karte dorthin "
        "enthalten. Was ein Lesen zum Fund macht, ist das Ziel: der Inhalt ging in eine "
        "Konversation mit einem Modellanbieter und auf die Platte in ein Transkript.",
    },
    "exfil_indicators": {
        "en": "Data leaving the device. These rules report the shape of a transfer, not its "
        "contents, so each one is a question about what was sent rather than an answer.",
        "de": "Daten, die das Gerät verlassen. Diese Regeln melden die Form einer "
        "Übertragung, nicht ihren Inhalt, jede ist also eine Frage danach, was gesendet "
        "wurde, und keine Antwort.",
    },
    "permission_bypass": {
        "en": "Safety controls that were turned off rather than controls that failed. Both "
        "halves of the question are here: what was set at startup, and what was changed "
        "afterwards.",
        "de": "Sicherheitskontrollen, die abgeschaltet wurden, nicht Kontrollen, die "
        "versagt haben. Beide Hälften der Frage stehen hier: was beim Start gesetzt war, "
        "und was danach geändert wurde.",
    },
    "anti_forensics": {
        "en": "Steps that shorten or remove the record. The most productive finding in this "
        "pack is the one that is documented as incomplete, because it establishes intent "
        "and names the directories still worth reading.",
        "de": "Schritte, die den Nachweis verkürzen oder entfernen. Der ergiebigste Fund in "
        "diesem Paket ist der, der als unvollständig dokumentiert ist, denn er belegt die "
        "Absicht und nennt die Verzeichnisse, die noch zu lesen lohnen.",
    },
    "prompt_injection": {
        "en": "Whether the agent was manipulated by instructions it read rather than "
        "instructions it was given. The scope of these rules is the point: the first one "
        "looks only at what came back from a tool, never at a user prompt, because a user "
        "is entitled to instruct the agent and a web page is not.",
        "de": "Ob der Agent durch Anweisungen manipuliert wurde, die er gelesen hat, statt "
        "durch Anweisungen, die er bekommen hat. Der Geltungsbereich dieser Regeln ist der "
        "Punkt: die erste betrachtet nur, was von einem Werkzeug zurückkam, und nie einen "
        "Nutzer-Prompt, denn ein Nutzer darf den Agenten anweisen und eine Webseite nicht.",
    },
    "supply_chain": {
        "en": "Code the agent loaded, and code configured to run without anyone asking. An "
        "MCP server is both a dependency and a tool surface, which is why what it is "
        "matters as much as what it did.",
        "de": "Code, den der Agent geladen hat, und Code, der so konfiguriert ist, dass er "
        "ohne Nachfrage läuft. Ein MCP-Server ist beides, Abhängigkeit und "
        "Werkzeugoberfläche, deshalb zählt was er ist genauso wie was er getan hat.",
    },
    "third_party_endpoints": {
        "en": "Where the conversation actually went. An endpoint override changes the answer "
        "to which data left the device for a whole session, and nothing in a transcript "
        "says which endpoint served it.",
        "de": "Wohin die Konversation tatsächlich ging. Eine Endpunkt-Umleitung ändert die "
        "Antwort darauf, welche Daten das Gerät verlassen haben, für eine ganze Sitzung, "
        "und kein Transkript sagt, welcher Endpunkt sie bedient hat.",
    },
    "data_volume": {
        "en": "Shape rather than content. These rules say where in a timeline to look "
        "deliberately, and nothing about what will be found there.",
        "de": "Form statt Inhalt. Diese Regeln sagen, wo in einer Zeitachse bewusst "
        "hinzusehen ist, und nichts darüber, was dort zu finden sein wird.",
    },
}

SEVERITY_LABELS = {
    "en": {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    },
    "de": {
        "critical": "kritisch",
        "high": "hoch",
        "medium": "mittel",
        "low": "niedrig",
        "info": "Info",
    },
}


def load_locale(lang):
    # type: (str) -> dict
    path = LOCALES_DIR / ("%s.yaml" % lang)
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)["rules"]


def esc(text):
    # type: (str) -> str
    """Escape a value for a Markdown table cell.

    A pipe inside a regex would otherwise split the cell, and a regex full of pipes is the
    normal case in this document rather than the exception.
    """
    return str(text).replace("|", "\\|").replace("\n", " ")


def code_list(values):
    # type: (tuple) -> str
    return ", ".join("`%s`" % value for value in values) if values else "-"


def anchor(rule_id):
    # type: (str) -> str
    return rule_id.lower()


def mark(rule, field, text, loc):
    # type: (object, str, str, dict) -> str
    """Prefix a paragraph that fell back to English.

    The rule files are English, so most of a German reference is English prose inside a
    German layout. Saying so on each paragraph is the difference between a documented gap
    and a quiet lie, and it is the same thing the artifact reference does.
    """
    if field in getattr(rule, "untranslated", frozenset()):
        return "%s %s" % (loc["untranslated_marker"], text)
    return text


def rule_section(rule, loc, lang):
    # type: (Rule, dict, str) -> list
    """One rule, in full."""
    severity = SEVERITY_LABELS[lang][rule.severity]
    lines = [
        "#### %s" % rule.id,
        "",
        "**%s**" % rule.title,
        "",
        "| | |",
        "| --- | --- |",
        "| %s | %s |" % (loc["col_severity"], severity),
        "| %s | `%s` |" % (loc["col_pack"], rule.pack),
        "| %s | %s |" % (loc["col_agents"], code_list(rule.agents)),
        "| %s | %s |" % (loc["col_kinds"], code_list(rule.kinds)),
        "| %s | %s |" % (loc["col_fields"], code_list(rule.fields)),
    ]
    if rule.tags:
        lines.append("| %s | %s |" % (loc["col_tags"], code_list(rule.tags)))
    lines.extend(["", mark(rule, "description", rule.description, loc), ""])

    # Rendered from the compiled condition, not from the YAML, so this cannot drift from
    # what actually runs.
    lines.extend(
        [
            "*%s:* `%s`" % (loc["section_condition"], esc(rule.condition.describe())),
            "",
        ]
    )
    if rule.aggregate is not None:
        window = ""
        if rule.aggregate.window_minutes is not None:
            window = ", %s min" % rule.aggregate.window_minutes
        lines.extend(
            [
                "*%s* %s, n >= %d%s."
                % (
                    loc["aggregate_note"],
                    code_list(rule.aggregate.group_by),
                    rule.aggregate.min_count,
                    window,
                ),
                "",
            ]
        )
    if rule.redact:
        lines.extend([loc["redact_note"], ""])

    lines.extend(
        ["*%s:* %s" % (loc["section_rationale"], mark(rule, "rationale", rule.rationale, loc)), ""]
    )

    if rule.false_positives:
        lines.append("*%s:*" % loc["section_false_positives"])
        lines.append("")
        for item in rule.false_positives:
            lines.append("- %s" % mark(rule, "false_positives", item, loc))
        lines.append("")
    if rule.references:
        lines.append("*%s:*" % loc["section_references"])
        lines.append("")
        for item in rule.references:
            lines.append("- <%s>" % item)
        lines.append("")

    positives = sum(1 for test in rule.tests if test.should_match)
    negatives = len(rule.tests) - positives
    lines.extend(
        [
            "*%s:* %d / %d (+/-)" % (loc["section_tests"], positives, negatives),
            "",
        ]
    )
    return lines


def render(rules, lang):
    # type: (list, str) -> str
    loc = load_locale(lang)
    by_pack = {}
    for rule in rules:
        by_pack.setdefault(rule.pack, []).append(rule)

    lines = [
        "<!-- Generated file. Do not edit. -->",
        "",
        "# %s" % loc["title"],
        "",
        "*%s*" % loc["generated_note"],
        "",
        loc["intro"],
        "",
        "> %s" % loc["heuristic_warning"],
        "",
        loc["tests_note"],
        "",
        loc["findings_note"],
        "",
        "## %s" % loc["toc"],
        "",
        "| %s | %s | %s |" % (loc["col_pack"], loc["col_id"], loc["col_severity"]),
        "| --- | --- | --- |",
    ]
    for pack in PACKS:
        inpack = by_pack.get(pack, [])
        if not inpack:
            # A pack with no rules still appears, so a reader can tell a pack that found
            # nothing from a pack that does not exist.
            lines.append("| [`%s`](#%s) | - | - |" % (pack, pack.replace("_", "-")))
            continue
        for index, rule in enumerate(inpack):
            cell = "[`%s`](#%s)" % (pack, pack.replace("_", "-")) if index == 0 else ""
            lines.append(
                "| %s | [%s](#%s) | %s |"
                % (cell, rule.id, anchor(rule.id), SEVERITY_LABELS[lang][rule.severity])
            )
    lines.extend(["", loc["severity_order_note"], ""])
    if lang != "en":
        # Only in a translated document, where it explains the markers below. In the
        # English one there is nothing to explain.
        lines.extend([loc["translation_note"], ""])

    for pack in PACKS:
        lines.extend(["## %s" % pack.replace("_", " "), ""])
        intro = PACK_INTROS.get(pack, {}).get(lang)
        if intro:
            lines.extend([intro, ""])
        inpack = by_pack.get(pack, [])
        if not inpack:
            lines.extend(["*(no rules yet)*", ""])
            continue
        for rule in inpack:
            lines.extend(rule_section(rule, loc, lang))

    return "\n".join(lines).rstrip("\n") + "\n"


def main(argv=None):
    # type: (list) -> int
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; fail if the committed file differs (the CI mode)",
    )
    args = parser.parse_args(argv)

    try:
        rules = load(RULES_DIR)
    except RuleError as exc:
        sys.stderr.write("gen-rule-docs: %s\n" % exc)
        return 2

    problems = 0
    for lang, name in (("en", "RULES.md"), ("de", "RULES.de.md")):
        target = DOCS_DIR / name
        # Reloaded per language, because a rule's prose may carry a translation and the
        # loader resolves it when it reads the file.
        try:
            localised = load(RULES_DIR, lang=lang)
        except RuleError as exc:
            sys.stderr.write("gen-rule-docs: %s\n" % exc)
            return 2
        text = render(localised, lang)
        if args.check:
            current = target.read_text(encoding="utf-8") if target.exists() else ""
            if current != text:
                problems += 1
                sys.stderr.write("gen-rule-docs: %s is out of date\n" % name)
                diff = difflib.unified_diff(
                    current.splitlines(), text.splitlines(), "committed", "generated", lineterm=""
                )
                for line in list(diff)[:40]:
                    sys.stderr.write("  %s\n" % line)
        else:
            target.write_text(text, encoding="utf-8")
            sys.stderr.write("gen-rule-docs: wrote %s\n" % name)

    if problems:
        sys.stderr.write(
            "\nRun scripts/gen_rule_docs.py to regenerate. Never edit these files by hand: "
            "the rule files are the source of truth.\n"
        )
        return 1
    sys.stderr.write("gen-rule-docs: %d rule(s) across %d pack(s)\n" % (len(rules), len(PACKS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
