#!/usr/bin/env python3
"""Take the screenshots that illustrate docs/WEBUI.md.

Kept in the repository so that the images in the documentation can be regenerated rather
than being pictures nobody can reproduce. Deliberately not run by CI and not part of the
test suite: it needs a browser, and Playwright is not a dependency of this project.

It needs a case to photograph, and that case must be synthetic. Never point this at a real
case: the images are committed to a public repository, and a screenshot is the easiest way
there is to publish somebody's prompts by accident.

    uv run python -c "import sys; sys.path.insert(0, 'tests/fixtures'); \
        from pathlib import Path; from generate import build_home; build_home(Path('/tmp/alice'))"
    uv run afx ingest /tmp/alice --case /tmp/case.db
    uv run afx scan --case /tmp/case.db
    uv run --with playwright python scripts/shot_webui.py --case /tmp/case.db
"""

import argparse
import sys
import threading
from pathlib import Path

from agentforensics.webui import server as webui

# The five case views, each photographed after its tab is clicked. The session view is
# handled separately because it needs a session opened first.
VIEWS = ("case", "timeline", "findings", "instructions", "artifacts")

# Where Playwright's Chromium usually sits when the browsers are installed outside the
# package, which is how a sandbox or a CI image normally does it.
DEFAULT_CHROMIUM = "/opt/pw-browsers/chromium"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--case", required=True, help="a SYNTHETIC case database to photograph")
    ap.add_argument("--out", default="docs/images", help="directory for the PNG files")
    ap.add_argument("--chromium", default=DEFAULT_CHROMIUM, help="path to a Chromium binary")
    ap.add_argument("--width", type=int, default=1440)
    ap.add_argument("--height", type=int, default=900)
    args = ap.parse_args(argv)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(
            "shot-webui: playwright is not installed. Run this with "
            "`uv run --with playwright python scripts/shot_webui.py ...`",
            file=sys.stderr,
        )
        return 2

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    # No fixed token and no fixed port: the images are of the page, not of the URL bar,
    # and a token written into a committed script is a token somebody reuses in earnest.
    server, ctx = webui.build(Path(args.case), port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = webui.url(server, ctx)
    print("shot-webui: serving %s" % url, file=sys.stderr)

    try:
        with sync_playwright() as play:
            browser = play.chromium.launch(executable_path=args.chromium, args=["--no-sandbox"])
            # Dark, because that is the viewer's own default and the theme the tool is read
            # in. A headless browser reports a light preference and would otherwise
            # photograph a theme nobody chose.
            page = browser.new_page(
                viewport={"width": args.width, "height": args.height}, color_scheme="dark"
            )
            page.goto(url, wait_until="networkidle")
            page.wait_for_timeout(1500)

            # The session with the most in it, so that the transcript screenshot shows a
            # transcript rather than an empty one.
            sessions = page.locator("#project-list .session")
            best, best_count = 0, -1
            for index in range(sessions.count()):
                words = sessions.nth(index).inner_text().split()
                count = sum(
                    int(words[i - 1])
                    for i, word in enumerate(words)
                    if word in ("msg", "tools") and i and words[i - 1].isdigit()
                )
                if count > best_count:
                    best, best_count = index, count
            sessions.nth(best).click()
            page.wait_for_timeout(1200)
            page.screenshot(path=str(out / "webui-sessions.png"))

            # The same session with its own filter set, which is the one screenshot that
            # has to show the hidden-row count: a filter that takes rows off the screen is
            # only honest while it says how many.
            tools_chip = page.locator("#turn-filters .tfilter", has_text="tool use")
            if tools_chip.count():
                tools_chip.first.click()
                page.wait_for_timeout(700)
                page.screenshot(path=str(out / "webui-filter.png"))
                page.locator("#turn-filters .tfilter", has_text="everything").first.click()
                page.wait_for_timeout(400)

            for view in VIEWS:
                page.locator('.tab[data-view="%s"]' % view).click()
                page.wait_for_timeout(1400)
                if view == "instructions":
                    # Filtered to the files that grant tools, hide characters or are
                    # executed rather than read, which is what an analyst opens this for.
                    chips = page.locator("#instructions-filters .tfilter")
                    for index in range(chips.count()):
                        if chips.nth(index).inner_text().startswith("worth a look"):
                            chips.nth(index).click()
                            page.wait_for_timeout(600)
                            break
                if view == "artifacts":
                    # Filtered to the files a parser did not understand, which is the
                    # distinction this view exists for.
                    chips = page.locator("#artifacts-filters .tfilter")
                    for index in range(chips.count()):
                        if chips.nth(index).inner_text().startswith("unsupported"):
                            chips.nth(index).click()
                            page.wait_for_timeout(600)
                            break
                page.screenshot(path=str(out / ("webui-%s.png" % view)))
            browser.close()
    finally:
        server.shutdown()
        server.server_close()

    print("shot-webui: wrote %d image(s) to %s" % (len(VIEWS) + 2, out), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
