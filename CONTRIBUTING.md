# Contributing

English | [Deutsch](CONTRIBUTING.de.md)

Thanks for looking. This is forensic tooling, so a few things matter more here than in an
average project. Please read the two sections that follow before opening a pull request.

## The two rules that are not style preferences

### 1. Nothing organization-specific, ever

This repository is public, and its main audience is people who will run it inside a
company. That means a real domain, an internal hostname, a project code name, a ticket id
or a colleague's name would leak the operator, permanently, to anyone who clones or forks
the repository. Git makes it permanent: a later commit does not remove it from history,
and forks, mirrors and code search caches keep their copy.

So: placeholders only. `example.org`, `example.internal`, `ACME`, `alice`, `PROJECT-FALCON`.
This applies to code, comments, docs, test fixtures, ADRs, commit messages and branch
names. Detection rules deserve special attention, because an internal hostname pattern in
a rule is exactly as much of a leak as one in a comment.

Relatedly, the suite does not ship a feature for finding one organization's own data. Rules
describe agent behavior: what was run, what was read, where data went, whether a control was
bypassed. A rule that hunts for a specific company's domains or code names would have to
carry those strings, which is precisely what must not be published, and it would pull the
tool away from the question it exists to answer.

### 2. Never make a record disappear

A parser that drops a record type it does not recognize, a renderer that returns nothing
for an unknown event, a log line silently truncated: in a forensic tool these are not
minor bugs. They make an analyst conclude that nothing was there, which is worse than a
crash, because a crash is visible. Preserve anything you cannot interpret, surface it as
unknown, and count it. There are tests that enforce this, and new parsers need one.

## The OpSec guard

`scripts/opsec_check.py` scans the files git tracks, the content staged for the next
commit, and the commit message itself, case-insensitively, against a list of strings that
must never be published.

That list, `.opsec-denylist`, is **not in the repository** and never will be. It names the
very things it protects, so committing it would defeat it. It is one string per line, with
`#` comments, maintained by whoever is publishing from this checkout:

```
# .opsec-denylist, one string per line, never committed
example-employer-name
example.internal
some-code-name
```

Set the hooks up once:

```bash
uv run pre-commit install --hook-type pre-commit --hook-type commit-msg
```

From then on a commit that would introduce a listed string fails locally. Behaviors worth
knowing:

- **No denylist present is normal.** A fresh clone, an outside contributor and a CI run
  without the secret all legitimately have no list. The check exits 0 with a notice
  instead of failing, because failing there would only teach people to skip the hook.
- **A hit never prints the matched string.** You get a path, a line number and the index
  of the denylist entry that matched. Printing the secret to prove the secret was found
  would defeat the purpose, and this output ends up in terminals, CI logs and screenshots.
- **A tracked denylist is a hard error.** If `.opsec-denylist` ever gets committed, the
  check refuses to run at all rather than pretending things are fine.
- **Legitimate exceptions exist.** A test that proves the guard works has to contain a
  denied string. Put `opsec-check: allow-line` on that line, or add the path to
  `.opsec-allowlist`, which is gitignored as well.
- **The check only sees the present.** It does not scan history. This is the important
  limitation, and it is why the procedure below exists.

CI runs the same script, reading the denylist from a repository secret when one is
configured and skipping cleanly otherwise. With a secret configured it goes one step
further than the local hook can and greps the whole history, because history is what
actually gets published.

Leaked credentials are a different problem from a leaked identity and need a different
tool. What is wired up today is pre-commit's `detect-private-key`, which catches the
obvious case of a committed key block. A full secret scanner such as gitleaks is part of
the pre-publication checklist below rather than of every commit, because running it over
history is where it earns its time.

## Before making a repository like this public

The pre-commit hook is not sufficient, because it never looked at history. Run this in
order, with the real denylist present:

1. `git log -p --all | grep -i -f .opsec-denylist` and confirm it produces nothing. Note
   `--all`, so tags and every branch are included, not just the current one.
2. `git log --format='%an <%ae> | %cn <%ce>'  | sort -u` and review every identity. Author
   and committer are separate fields and both are published.
3. `git branch -a` and `git tag`, and review the names.
4. Review the commit timestamps. A full history of commits at 09:00 to 18:00 in one fixed
   timezone offset describes a working pattern and a rough location.
5. Check issue and pull request text, CI logs and any screenshot. Screenshots are the
   usual mistake: they carry window titles, hostnames, paths and sometimes metadata.
6. Run a generic secret scanner over history, not just the working tree.
7. Confirm `.opsec-denylist` and `.opsec-allowlist` are untracked.

If something is found after publication, assume it is already copied. Rewriting history
does not retract a fork, a mirror or a cached search result. Depending on what leaked, a
new repository with a fresh history is the honest answer, and whoever is affected should
be told rather than left to find out.

## Working in the repository

Set up, then check your work with the same commands CI runs:

```bash
uv sync --all-extras
uv run pre-commit install --hook-type pre-commit --hook-type commit-msg

uv run ruff check .                   # lint
uv run ruff format --check .          # formatting
uv run mypy src                       # type check, src only
uv run pytest                         # tests
```

Generated artifacts. Each of these has a `--check` mode that CI uses to fail on drift, so
run the generator whenever you change its input:

```bash
uv run python scripts/build_collectors.py    # embed catalog/ into both collectors
uv run python scripts/gen_artifact_docs.py   # regenerate docs/ARTIFACTS{,.de}.md
uv run python scripts/gen_rule_docs.py       # regenerate docs/RULES{,.de}.md
uv run python scripts/check_translations.py  # German docs lagging their English source
uv run python scripts/opsec_check.py --mode both
```

The CLI itself is `agentforensics`, with `afx` as a shorter alias:

```bash
uv run agentforensics --help
```

Conventions, in short.

- Code, identifiers, comments, commit messages and ADRs in English. Docs bilingual, with
  the English file canonical and a `.de.md` sibling. `scripts/check_translations.py` fails
  CI when the English text moved and the German one did not.
- Conventional Commits, small and self-contained. Lint and tests green before every
  commit.
- Comments explain why, not what. Modules open with a docstring naming the design
  constraint they serve, and every non-obvious regex, path encoding or format quirk gets a
  comment with its reason, plus a source link when it comes from vendor documentation.
- One ADR per decision, short, under `docs/adr/`.
- Ask before adding a dependency, changing a data format, or anything security relevant.
- Generated files are never hand-edited: `docs/ARTIFACTS.md`, `docs/RULES.md`, everything
  under `exporters/generated/`, and the embedded catalogue block inside each collector.
  Change `catalog/` or `rules/` and regenerate. CI compares.

## Contributing an artifact to the catalogue

This is the most valuable contribution and the easiest one to get wrong.

An entry is `status: verified` only if `source` is a URL that actually states the path,
and you fetched it. Vendor documentation and the agent's own published source code both
count. One blog post quoting another blog post does not. If you know a path from your own
system, that is fine and useful, but it is `status: unverified` with
`source: "observed on <os> <version>"` and no identifying detail.

Unverified entries are not second-class: they are still collected, and they are flagged in
analyzer output so an analyst knows a negative result is inconclusive rather than proof.
What is genuinely harmful is a plausible-looking path that nobody ever saw. It makes a
collection come back empty and an analyst conclude the agent was never used.

Never include real content from a transcript, a config or a credential file. Fixtures are
synthetic and generated by `tests/fixtures/generate.py`.
