#!/usr/bin/env python3
"""Check the single-file viewer without a browser.

The viewer is one HTML file with inline JavaScript, which means nothing type-checks it and
nothing imports it, so a broken edit is only noticed by opening it. This script closes that
gap in two ways:

  * structural assertions in pure Python, which always run: the tabs and their panels must
    line up, the pieces that must exist must exist, and the pieces that must not exist must
    not exist.
  * two stylesheet assertions, for the kind of CSS mistake that is invisible until somebody
    opens the page: a button whose rule sets no background renders as a platform button
    face, and a layout class that sets `display` silently beats `.hidden`. Both of these
    shipped once.
  * a real parse, by handing each script block to node when node is available. Skipped with
    a notice otherwise, because a contributor without node should not be blocked from
    committing a documentation change.

Behavioral tests live in tests/viewer/ and run through pytest.
"""

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

VIEWER = Path("viewer") / "index.html"

# Markup and code that must be present. Each entry is a reminder of a property somebody
# relied on, not a style rule.
REQUIRED = [
    ("const SECRET_RULES=[", "the built-in secret rule pack"),
    ("function scanSecrets(", "the secret scanner"),
    ("function normalizeCodex(", "the Codex normalizer"),
    ("function normalizeCopilot(", "the Copilot normalizer"),
    ("function summarize(", "session metadata derivation"),
    ("function buildTimeline(", "assistant turn grouping"),
    # ADR 0009: these three are how the viewer avoids hiding evidence.
    ("'parse-error'", "unparsed lines kept as their own record kind"),
    ("'unstructured-record'", "non-object JSON lines kept as their own record kind"),
    ("'unknown-record'", "unknown record types kept rather than dropped"),
    ("summary.unparsed", "the unparsed-line counter in the session header"),
]

# Things whose presence means a regression. ADR 0010 removed the organization scope scan,
# and it is the kind of feature that comes back by copy and paste.
FORBIDDEN = [
    ("ORG_SCOPE_RULES", "the organization scope rules were removed, see ADR 0010"),
    ("scanOrgScope", "the organization scope scanner was removed, see ADR 0010"),
    ("scopeFindings", "the organization scope findings array was removed, see ADR 0010"),
    ("viewer.html", "stale reference to the file's former name"),
    ("t.slice(0, 2000)", "truncating an unparsed line hides evidence, see ADR 0009"),
]


def script_blocks(text):
    return re.findall(r"<script>(.*?)</script>", text, re.S)


def style_block(text):
    """The stylesheet with its comments removed.

    Removed because a comment sits inside the selector text a naive block split captures,
    so `/* ---- tabs ---- */\n.tabs` never compares equal to `.tabs`. That silently turned
    the rule lookup below into a lookup that found nothing, which made the check pass on a
    file it was written to reject.
    """
    found = re.search(r"<style>(.*?)</style>", text, re.S)
    if not found:
        return ""
    return re.sub(r"/\*.*?\*/", "", found.group(1), flags=re.S)


def rules_for(css, selector):
    """Every declaration block whose selector list contains exactly this selector."""
    out = []
    for selectors, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
        if selector in [part.strip() for part in selectors.split(",")]:
            out.append(body)
    return out


def style_problems(text):
    """Two CSS mistakes that are invisible until somebody opens the page.

    Both of these happened. A <button> whose rule sets no background renders with the
    platform's button face, which on a dark page is a light grey slab where a label should
    be. And a layout class that sets `display` overrides `.hidden` whenever it is written
    later in the stylesheet, so an element with class="tabs hidden" is visible: equal
    specificity, and the last rule wins.
    """
    css = style_block(text)
    problems = []
    if not css:
        return ["no <style> block found"]

    buttons = set(re.findall(r"<button[^>]*class=\"([^\"]+)\"", text))
    buttons |= set(re.findall(r"el\(\s*'button'\s*,\s*\{\s*class\s*:\s*'([^']+)'", text))
    for names in buttons:
        for name in names.split():
            if name == "hidden":
                continue
            bodies = rules_for(css, "." + name)
            if not bodies:
                problems.append("button class %r has no rule of its own" % name)
            elif not any("background" in body for body in bodies):
                problems.append(
                    "button class %r sets no background, so it renders as a platform "
                    "button face" % name
                )

    for names in re.findall(r'class="([^"]*\bhidden\b[^"]*)"', text):
        for name in names.split():
            if name == "hidden":
                continue
            bodies = rules_for(css, "." + name)
            if any(re.search(r"(^|;)\s*display\s*:", body) for body in bodies) and not rules_for(
                css, ".%s.hidden" % name
            ):
                problems.append(
                    "class %r sets display and is used together with .hidden, so it needs "
                    "a .%s.hidden rule or .hidden will not hide it" % (name, name)
                )
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--path", default=str(VIEWER))
    args = ap.parse_args(argv)

    path = Path(args.path)
    if not path.exists():
        print("check-viewer: %s not found" % path, file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8")

    problems = []

    for needle, why in REQUIRED:
        if needle not in text:
            problems.append("missing: %s (%s)" % (needle, why))

    for needle, why in FORBIDDEN:
        if needle in text:
            problems.append("present but must not be: %s (%s)" % (needle, why))

    # Every tab other than the transcript view needs a panel, and every panel needs a tab.
    # A mismatch shows up as a tab that switches to a blank screen, which is easy to ship.
    tabs = set(re.findall(r'data-view="([a-z-]+)"', text))
    panels = {m[: -len("-panel")] for m in re.findall(r'<div id="([a-z-]+-panel)"', text)}
    for tab in sorted(tabs - panels - {"sessions"}):
        problems.append("tab %r has no matching panel" % tab)
    for panel in sorted(panels - tabs):
        problems.append("panel %r has no matching tab" % panel)

    problems.extend(style_problems(text))

    blocks = script_blocks(text)
    if not blocks:
        problems.append("no <script> block found")

    node = shutil.which("node")
    if node:
        with tempfile.TemporaryDirectory() as tmp:
            for i, block in enumerate(blocks):
                js = Path(tmp) / ("block%d.js" % i)
                js.write_text(block, encoding="utf-8")
                proc = subprocess.run(
                    [node, "--check", str(js)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                if proc.returncode != 0:
                    problems.append(
                        "script block %d does not parse:\n%s"
                        % (i, proc.stdout.decode("utf-8", "replace"))
                    )
    else:
        print(
            "check-viewer: node not found, skipping the JavaScript parse check",
            file=sys.stderr,
        )

    if problems:
        print("check-viewer: %d problem(s)\n" % len(problems), file=sys.stderr)
        for p in problems:
            print("  %s" % p, file=sys.stderr)
        return 1

    print(
        "check-viewer: ok, %d script block(s), %d tab(s), %d panel(s)"
        % (len(blocks), len(tabs), len(panels)),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
