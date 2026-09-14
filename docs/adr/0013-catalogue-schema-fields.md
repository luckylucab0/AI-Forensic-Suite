# ADR 0013: Four fields added to the artifact entry beyond the original list

- **Status:** accepted
- **Date:** 2026-09-14
- **Extends:** the artifact entry described in the original project brief

## Context

The brief specified the artifact entry as `id`, `agent`, `category`, `os`, `paths`,
`format`, `parser`, `sensitivity`, `volatility`, `status`, `source` and `notes`. Building
the first real catalogue, for Claude Code, surfaced four things that list cannot express,
each of which changes behavior rather than presentation.

**The data tree moves.** `CLAUDE_CONFIG_DIR` relocates the entire Claude Code
configuration directory, taking transcripts, prompt history and plugins with it. A
collection keyed on `~/.claude` finds nothing on such a host, and nothing distinguishes
that from the agent never having been installed. The same pattern exists for other agents
through their own variables.

**Volatility has to be machine-readable.** The brief requires the catalogue to document
volatility "so analysts know what to collect first", but prose cannot order a collector's
work. On a live endpoint the difference matters: one artifact is destroyed by a clean
shutdown, another is wiped for every session but the current one on each retention sweep,
and a third outlives the sweep entirely and is where to look when transcripts are gone.

**Some paths are evidence of the past, not statements about the present.** Current Claude
Code reads managed policy from `C:\Program Files\ClaudeCode\managed-settings.json` and
explicitly does not read the older `C:\ProgramData\ClaudeCode\managed-settings.json`. Both
are worth collecting. Presenting the second as effective policy would invert the conclusion
of an investigation.

**`source` conflated two things.** It was specified as "URL, or observed on <os> <version>",
which makes the honesty rule unenforceable: no check can tell whether a `verified` entry
rests on vendor documentation or on somebody's recollection.

## Decision

Four fields, plus one file-level addition:

- `collect_priority`: `live_only`, `first`, `normal` or `durable`. The collectors order
  their work by it, and `docs/COLLECTION.md` groups its guidance by it. `live_only` means
  unrecoverable from a powered-off image.
- `legacy`: boolean, default false. Collect it, never present it as live state.
- `source_kind`: `official`, `source_code`, `community`, `observed` or `recollection`. The
  schema now rejects `status: verified` unless `source_kind` is `official` or
  `source_code`, so the honesty rule is mechanical rather than a matter of discipline.
- `title`: a human-readable name, because the generated documentation needs one and the
  id is not it.
- At file level, `env_overrides`: the environment variables that relocate the agent's tree,
  each with its effect and its source.

Two existing fields are documented more tightly rather than changed. `sensitivity` is
operational: `secret` means the collector records metadata and a hash but does not copy the
content, so it is reserved for credential stores. The first research pass read it as a
description of how personal the content is and marked transcripts, prompt histories and
pre-edit file snapshots as secret, which would have made the collector skip the primary
evidence and hand the analyst an empty bundle. `category` carries the descriptive half, and
is what a report uses to warn that a bundle contains personal data.

Free-text fields accept either a plain string, treated as English, or an
`{en: ..., de: ...}` mapping, so the bilingual documentation requirement does not force a
contributor to write German in order to add an artifact.

## Consequences

Buys: a collector that can find a relocated tree, collection ordered by what disappears
first, legacy paths that cannot be mistaken for policy, and a verification rule a schema
can enforce.

Costs: five more fields to fill in per agent, and `collect_priority` is a judgement that
has to be made per artifact from its retention behavior. It was tempting to derive it
mechanically from the volatility text; doing so produced confidently wrong answers,
including marking transcripts `durable` because the text mentioned that desktop sessions
are kept at any age. The values are therefore set deliberately, and the ones that are not
`normal` are the ones worth reviewing in a pull request.

`sensitivity` remains a binary, which means a transcript full of personal data and a
public README are both `normal`. That is correct for the question the field answers, which
is whether to copy the bytes, and the personal-data question is answered by `category`.

## Alternatives considered

- A third `sensitivity` value for personal-but-collectable: it would put two unrelated
  questions in one field, and `category` already answers the second one.
- Prose-only volatility: cannot order a collection, which is the thing it exists to inform.
- Dropping `source_kind` and trusting `status`: the discipline it replaces is exactly the
  discipline that fails under time pressure.
