# ADR 0002: The package and CLI are named agentforensics

- **Status:** accepted
- **Date:** 2026-09-14
- **Supersedes:** the working name used in the original project brief

## Context

A name was needed for the PyPI package and the command. The brief proposed a four-letter
acronym of the project's descriptive title and asked for PyPI availability to be checked.

PyPI availability was not the problem: the acronym was free. The problem is that the same
four letters are the acronym of the largest forensic science organization in the world, a
body that has existed since the 1940s. A DFIR tool carrying that name competes with an
institution in search results, in conversation and potentially in trademark terms, in
exactly the field it is built for.

## Decision

- Repository: `ai-agent-forensic-suite`
- Python package and import name: `agentforensics`
- CLI: `agentforensics`, with `afx` as a short alias

Both console scripts are declared in `[project.scripts]`. The old working name appears
nowhere in the repository, so there is no half-renamed state to clean up later.

## Consequences

Buys: a name that is unambiguous in a search, reads correctly when cited in a report, and
does not invite a conversation with anyone's legal department. `afx` keeps daily typing
short.

Costs: longer to type in full, and less catchy than a four-letter acronym. Names are also
expensive to change once a tool is cited in reports, which is the reason to get it right
before the first release rather than after.

## Alternatives considered

- `aidfir`: free and legible to the target audience, awkward to say out loud.
- `agenthist`: accurate about what is recovered, undersells the collection and rules side.
- Keeping the acronym: rejected on the collision above.
