# ADR 0010: The suite does not look for one organization's own data

- **Status:** accepted
- **Date:** 2026-09-14
- **Supersedes:** the `org_scope` rule pack described in the original project brief

## Context

The inherited viewer had a second heuristic scan hardcoded to one organization's domains,
flagging its repositories and any connection to its hosts. The first plan was to keep the
capability and generalize it: a neutral rules array, empty by default, fed from an
operator-supplied config file that stays out of git.

That would have worked, and it was still the wrong shape for this tool. Three reasons
became clear once written down.

The strings such rules need, internal domains, hostname patterns, project code names, are
exactly the strings that must never be published. Keeping the feature means keeping a
config mechanism, a template file, a generator, and a documented workflow whose only job is
to handle content the repository is built to exclude.

The capability is also a different product. "Did our data appear here" is a data loss
prevention question. This suite answers "what did the agent do", and every artifact,
parser, event kind and rule pack is shaped around agent behavior.

And an empty feature is a liability. A tab that shows nothing until configured, a rule pack
with no rules, a template config: all of it is surface to maintain and explain, for
something no user of the published tool can use out of the box.

## Decision

The organization scope scan is removed entirely, not generalized. No tab, no rules array,
no `config/org.yaml`, no `org.example.yaml`, no `org_scope` rule pack, no generator.

Repository hygiene, making sure no organization-specific content is published, is handled
once before publication by a development-time script and a documented procedure. See
ADR 0008. That is a property of the repository, not a feature of the tool.

The heuristic secret scan stays. Credentials that reached an agent transcript are squarely
within the question this suite answers: a key pasted into a prompt has left the developer's
control and may have gone to a model provider.

The rule packs stay focused on agent behavior: secrets, dangerous commands, sensitive
paths, exfiltration indicators, permission bypass, anti-forensics, prompt injection, supply
chain, third-party endpoints and data volume.

## Consequences

Buys: a smaller and more coherent tool, one less config file that must not be committed,
and no public documentation explaining how to feed a public tool private identifiers.

Costs: an operator who genuinely wants that scan has to do it elsewhere. That is the right
place for it: a DLP tool, a secret scanner, or a one-off grep over an export, all of which
already exist and do it better.

## Alternatives considered

- Generalize into a configurable, empty-by-default feature: maintained surface and a
  documented private-config workflow, for a capability outside the tool's question.
- Keep it hardcoded: never an option in a public repository.
