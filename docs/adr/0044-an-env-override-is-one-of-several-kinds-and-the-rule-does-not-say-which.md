# ADR 0044: An env_override is one of several kinds, and the generated rule does not say which

- **Status:** accepted, deferred
- **Date:** 2026-09-21

## Context

Each catalogue file declares the environment variables an agent reads in `env_overrides`,
and `scripts/gen_relocation_rule.py` renders all of them into one rule,
`AFX-COLLECTIONINTEGRITY-001`, with one title, one severity and one pair of tags. There are
96 of them across 21 agents, which is why the rule is generated rather than written: a list
of catalogue facts copied into a rule file is a list that stops being true without anybody
noticing.

The variables are not all the same kind of thing, and the single rule presents them as if
they were. Six kinds are in the list today:

- a variable that moves a directory, which is most of them: `CLAUDE_CONFIG_DIR`,
  `GOOSE_PATH_ROOT`, `QWEN_HOME`, `HERMES_HOME`
- one that decides whether a record exists at all: `GOOSE_DISABLE_KEYRING` turns a keyring
  entry into a plaintext file, `CLAUDE_CODE_SKIP_PROMPT_HISTORY` stops the history being
  written
- one that carries the instructions themselves rather than a path, so there is nothing
  further to collect: `GOOSE_MOIM_MESSAGE_TEXT`, `OPENCODE_CONFIG_CONTENT`
- one that replaces the filenames that count as instruction files: `CONTEXT_FILE_NAMES`
- one that points the agent at a remote source: `GOOSE_RECIPE_GITHUB_REPO`
- one whose whole effect is to defeat attribution: `AMP_DISABLE_AMP_THREAD_TRAILER` and its
  co-author sibling, which stop the agent writing the trailers that link a commit to the
  conversation behind it
- and several that are behaviour or logging only: `Q_LOG_LEVEL`, `KIRO_LOG_NO_COLOR`,
  `AMP_SKIP_UPDATE_CHECK`

This was noticed because the pass that read one vendor's manual added variables of the
fifth and sixth kinds to a list whose rule said, in its title and its description, that its
variables change where an agent keeps its data or whether it keeps it. A finding then
explained a variable with a sentence that was not about it.

## Decision

The classification is the right fix and it is deferred rather than done. The rule's wording
was corrected instead: its title, description and rationale now say that a variable in the
list changes where an agent keeps its data, whether it keeps it, or what it obeys, and its
generated header says so too and names the one kind that has a rule of its own.

When it is done, it is an optional `kind` field on `env_override` in
`catalog/schema/catalog.schema.json`, and `gen_relocation_rule.py` emits one rule per kind,
each with its own title, severity, tags and false-positive list.

## Consequences

What the deferral costs is precision in a report. A variable that defeats attribution and a
variable that moves a cache are reported at the same severity, under a title that fits the
second and not the first, and an analyst reading the finding has to go to the catalogue to
learn which they have. That cost is bounded today because the sharpest case has a rule of
its own: `AFX-ANTIFORENSICS-006` reports the two commit-trailer variables at their own
severity with their own reasoning.

What the deferral buys is that the schema every consumer relies on does not move for a
tidying. Both collectors embed the catalogue, five exporters render it, and the schema is
validated in CI against every file; a new field is cheap to add and not cheap to add
wrongly.

The work is mostly not code. Classifying 96 variables means reading 96 effect statements and
deciding which kind each is, and a wrong classification is worse than no classification,
because a rule whose title fits its list is the whole point of doing this.

We revisit it when a second kind needs its own severity, when a pack grows a rule that
would rather match one kind than the whole list, or when the count grows enough that the
single rule's false-positive list stops being honest about all of them.

## Alternatives considered

- Narrow `env_overrides` to relocation only and drop the rest. Lost because the rest is
  evidence: a variable that carries the instructions in the process, or that decides whether
  a credential exists as a file, is exactly what an analyst has to read off the environment
  before concluding anything from an empty result.
- Leave the single rule and its old wording alone. Lost because the wording was not true of
  a dozen of its own names, which is the defect this project treats most seriously: a
  sentence that outlives what it describes.
- Hand-write a rule per sharp variable and keep the generated one broad. Partly taken, and
  it is what bounds the cost above, but it does not scale: every new catalogue pass finds
  more variables, and a hand-written rule per variable is the list that stops being true.
