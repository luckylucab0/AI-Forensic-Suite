# ADR 0023: The instruction surface is its own event kind

- **Status:** accepted
- **Date:** 2026-09-18

## Context

One of the questions this suite exists to answer is whether an agent was manipulated by
instructions somebody planted. Half of that was answerable: a rule pack matches an injection
arriving in a tool result, a fetched page or an MCP response, which is the delivery.

The other half was collected and never read. Sixty-three catalogue artifacts hold the
standing instructions an agent runs under: CLAUDE.md and AGENTS.md and their per-vendor
equivalents, skills, commands, output styles, rules and steering files, plans, souls,
presets, and hook scripts. Each produced exactly one `artifact.fs` event. The case held the
file names and nothing about what the files said, so a poisoned project instruction file, a
skill granting itself a shell, and a rules file with an order hidden in zero-width
characters were all invisible to every rule and every view.

Two shapes of wrong answer were available. Folding these into `config.snapshot` would make a
timeline unable to say whether a hit was a setting or an order to the model, and the
injected-instruction question is only about the second. Calling the result "the system
prompt" would be worse: for nearly every agent here the vendor's base prompt is compiled
into the binary or arrives from the vendor's server and is not on the endpoint at all, so a
reconstruction presented as the prompt is a confident answer to a question the evidence
cannot answer, which is the same defect as an invented catalogue path.

## Decision

A new event kind, `instruction.source`: one event per instruction file that was in force on
the endpoint, carrying the file's whole text, its scope, and what could be read out of it
literally. It is added to the closed vocabulary in `agentlog.v1`, which ADR 0018 names as
the way a new kind arrives. The name says source rather than prompt, and the documentation
says plainly that the vendor's base prompt is not on the endpoint.

Scope is `managed`, `local`, `project`, `user` or `unknown`, and it is decided from recorded
data: a machine-wide path prefix, the documented `.local.` override convention, and the
working copies the collector found and wrote into the manifest. A collection that did not
record working copies yields `unknown` with the reason on the event, because "we could not
tell" and "this was the user's own file" are different answers and the difference is the
finding.

The event carries no timestamp. The `artifact.fs` event for the same path already carries
the filesystem's times, attributed to the filesystem, and a copy date presented as the
moment the agent was instructed would be evidence the suite invented.

One module reads all of it, because this is a format and not an agent: every vendor writes
prose in Markdown or text, a document with YAML front matter, or a settings file with a
prompt in one named field. A skill's front matter is lifted, including the tools it grants
itself, which is a permission change written as a document. Characters a reviewer cannot see
are counted per file.

## Consequences

The injected-instruction question is answerable from the disk side now, for every catalogued
agent at once. `facet_instructions` fills from real collections rather than only from the one
agent that names its instruction files in its own transcript, and the existing prompt
injection rules reach instruction files without being rewritten.

The cost is case size and a new kind for every consumer to learn. An instruction surface is
prose, and a developer machine carries a lot of it, so a case grows by roughly the size of
the collected instruction files. The text limit is a million characters per file, reported on
the event when reached rather than applied quietly.

The second cost is that these events have no time and will sit at the undated end of a
timeline. That is what a file with no internal timestamp honestly looks like, and the
`artifact.fs` event beside it is where the temporal question is answered.

The scope answer depends on the collector having found the working copies. Where it did not,
the honest `unknown` is less useful than a guess would have looked, which is the trade this
project makes everywhere else too.

## Alternatives considered

- **Reuse `config.snapshot`.** No format change, and the rules would have worked at once. It
  also makes a timeline unable to separate a setting from an order to the model, and the
  separation is the point of the view.
- **Call it `system_prompt.*` and reconstruct one per agent.** The most useful-looking
  answer and the least defensible: the base prompt is not on the endpoint, the assembly
  order is the agent's runtime behaviour rather than a fact on disk, and a reader would
  quote the reconstruction as the prompt.
- **A module per agent.** Twenty copies of one reader, and the copy nobody wrote would be
  the silent gap. The shapes are the same across vendors; the scope rules are not per-agent
  either.
- **Derive scope from the path's shape.** Guessing exactly where a wrong answer reverses the
  finding about who instructed the agent.
