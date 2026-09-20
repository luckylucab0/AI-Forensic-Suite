# ADR 0036: A settings file is read the way its own product reads it

- **Status:** accepted
- **Date:** 2026-09-20

## Context

Forty-one catalogue entries are JSON documents whose paths end in `settings.json`, `mcp.json`
or `.jsonc`. They are the most valuable configuration evidence this suite collects: the
permissions an agent was granted, the MCP servers it could reach, the endpoints its traffic
went to, the hooks the endpoint runs by itself.

None of them is strict JSON. Every editor in this catalogue writes its settings in the
dialect with line comments, block comments and trailing commas in it, and VS Code's own
default settings file ships with comments in it. The reader used `json.loads`, so a settings
file with one comment in it produced exactly one event: an `unparsed.record` whose reason was
"not valid JSON" and whose `raw` was `None`. The file was in the bundle and none of it was in
the case. No rule could match it, no view could show it, and the analyst was told the file was
unreadable when the product that wrote it reads it every time it starts.

The second half of the same defect: even where the document really was broken, the failure
branch carried the reason and not the text. A settings file killed mid-write reached an
analyst as a sentence about itself, with the part that had been written in no event at all.

## Decision

A JSON document that does not parse strictly is offered the relaxed reading its own product
uses, and only then reported as unreadable. The relaxations are the two that dialect adds:

- line and block comments are blanked out, not deleted, so every byte offset stays where it
  was and a decoder error still points at the place in the file an analyst would open;
- one comma before a closing brace or bracket is allowed.

Both passes track string state, so `"https://example.org/a//b"` is a URL and not a comment,
which is the mistake that would otherwise cut a value in half.

The event says which relaxation was needed, in the same sentence that says the text as it
stood on disk is on the event too. That second part is not decoration: a comment in a
settings file is somebody's note about why a setting is what it is, and a reading that
silently dropped the comments would lose the most human piece of evidence in the file.

Where a document does not parse even relaxed, the event now carries its text.

## Consequences

The settings files this suite exists to read are read. The synthetic profile's own settings
file is written in that dialect now, with a comment above the file, a comment beside the line
it explains and a trailing comma, so the whole path is a regression test: reverting the reader
turns seven tests red, four of them rules that fire on the permissions in that file.

A document that needed the relaxed reading carries a parse problem saying so. That is
deliberate, and it is a statement about the file rather than about the reading: a `.json`
file that is not JSON is worth an analyst's attention, and the same sentence tells them that
nothing was lost.

The relaxed reading can accept a file that a strict tool elsewhere rejects, which means a
case can hold a parsed document that some other tool in the chain would refuse. That is the
right way round for a forensic tool: the product on the endpoint accepted it, so what it
meant to the agent is what matters.

## Alternatives considered

- **Leave it strict.** The state it was in. The forty-one most important configuration
  entries in this catalogue read as unreadable whenever somebody had written a comment.
- **Add a dependency that parses the dialect.** One import, and a dependency in a tool that
  has to be vendorable offline, for a hundred lines of state machine. ADR 0012 keeps the
  dependency list at two on purpose.
- **Strip comments with a regular expression.** It gets `"a//b"` wrong, which is the one
  case that matters, because it fails by producing a value rather than an error.
- **Read relaxed first and say nothing.** Cheaper, and it throws away the fact that a file
  claiming to be JSON is not, which on a settings file somebody hand-edited is evidence.
- **Keep the failure branch as it was.** A file whose content is in the bundle and in no
  event is the failure this project is built around.
