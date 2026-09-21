# ADR 0041: A pattern's anchor is a property of the pattern, not of its entry

- **Status:** accepted
- **Date:** 2026-09-21

## Context

A catalogue entry carries a `root`: `user_profile`, `system`, `project`, `repo_root`,
`plugin` or `registry`. Project, repository and plugin roots are the ones no static rule can
name, because only the agent's own state file says which directories the user had open, so
the collector substitutes a leading `<project>` placeholder with each working copy it
discovered.

Both collectors and all five collection-rule exporters asked the entry. The collector
substituted every pattern of a project-rooted entry with the discovered working copies and
skipped the entry whole when there were none; the exporters reported such an entry as
covered by nothing at all.

Sixty entries are one logical thing at two scopes, which is what the catalogue is designed
to hold: the working copy's own instruction file and the profile or system wide one the same
agent reads beside it. 191 paths in those entries are anchored at neither a project nor a
repository. Among them: a user's own `CLAUDE.md` and the machine-wide one under `/etc` and
`%PROGRAMDATA%`, `~/.cursor/hooks.json`, `~/.gemini/policies/**`, `~/.aider.conf.yml`, the
user-level MCP configurations of four products, and the managed settings of two.

So a host where no working copy was discovered collected none of them, and a generated KAPE
or osquery or Velociraptor rule never contained them. Neither said so. A profile whose
repositories live somewhere the discovery heuristic does not look produced a bundle with no
global instruction surface in it, which reads as an agent that was never configured.

## Decision

Anchoring is decided per pattern. A pattern that begins with a placeholder other than
`<vscode-user>`, which the expander resolves from the profile itself, needs a discovered
root; every other pattern is searched as it stands, whatever the entry's `root` says.

The collectors substitute only those patterns, and when there is no working copy to
substitute, the pattern is reported in the manifest's `refused_patterns` with the reason
`no_project_root` rather than dropped. A bundle with no project tier in it now says that
nothing was searched for one, and why.

The exporters render every pattern that is not anchored, and report the rest in the file's
own header with one line naming the entries whose working-copy half is missing. An entry is
reported as covered by nothing only when every one of its paths is anchored.

`root` stays as it is. It says what the entry is about, which is what the documentation and
the collection order use it for, and it is still the field that decides whether the
collector has to read an agent's state file at all.

## Consequences

191 paths are collectable and expressible that were neither. Where a working copy is
discovered nothing changes: the same patterns are substituted with the same roots.

Two costs. A run with no discovered working copy now records a few hundred refusals, one
per anchored pattern, which is a larger manifest and an honest one: each line is a pattern
this collection could not look for. And a generated rule is longer, because the profile half
of sixty entries is now in it.

What would make us revisit it: nothing about the rule itself. The next question in the same
area is whether `root` should be per path rather than per entry, which would let the
generated documentation say the scope of each path. That is a data-format change and the
current split answers the evidence question without it.

## Alternatives considered

- **Split the sixty entries into a project half and a profile half.** Sixty new artifact
  ids, referenced from rules, tests and stored cases, and it breaks the rule that one
  artifact is one logical thing. The catalogue was right; the consumers were wrong.
- **Search anchored patterns against the profile when no working copy was found.** It would
  look for `<project>/.clinerules` under the home directory, find whatever happened to be
  there and file it as a project artifact. A wrong scope on an instruction file is worse
  than a missing one.
- **Leave the collector and fix only the exporters.** The collector is the one that produces
  evidence; a generated rule is a convenience beside it.
- **Report nothing for an unanchored project pattern.** That is today's behaviour, and it is
  the silence this project treats as the worst outcome.
