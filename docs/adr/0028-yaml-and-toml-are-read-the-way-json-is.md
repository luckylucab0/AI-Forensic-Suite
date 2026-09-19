# ADR 0028: YAML and TOML documents are read the way JSON documents are

- **Status:** accepted
- **Date:** 2026-09-19

## Context

ADR 0027 decided how a whole JSON document with no verified shape is read: split it by
structure one level deep, never by meaning, and read out of a record only what the record
literally names. That reader covers 142 catalogue entries.

It left two formats out, and the omission was not a decision anybody made. Fifteen
catalogue entries are YAML and four are TOML, and nothing read any of them. Among them are
one agent family's configuration, its MCP server list and its permissions file, another's
permission file, a third's recipes and cron entries, and two products' settings. Those are
configurations in the sense the rule engine uses the word: a rule that asks what an agent
was allowed to do looks for `config.snapshot` events, and for these agents there were
none. So the packs could say nothing about the products whose settings are not JSON, and
nothing in a case said why.

The formats also differ from JSON in ways a reader has to answer for rather than ignore. A
YAML file can hold several documents in one file, a YAML mapping key does not have to be a
string, and both formats have real date values that the case's record format does not.

## Decision

The reading decided in ADR 0027 moves into one module, `parsers/structured_generic.py`,
and three readers use it: `json_generic`, `yaml_generic` and `toml_generic`. Each one owns
only what is specific to its format: which catalogue entries it claims, which of them the
catalogue calls a configuration, and how bytes become a value.

The format-specific answers:

- A YAML file of several documents produces events for all of them. A single-document file
  is located at `$`; a multi-document file at `$doc[0]`, `$doc[1]` and so on.
- A YAML mapping key that is not a string is stored as the text of itself, and every record
  out of that document says so.
- A value that is a date or a datetime is kept as the loader returned it. The case already
  renders a value no JSON encoder knows as its text, and that rendering is stable.
- YAML is loaded with the safe loader, so a file carrying a tag it does not know is
  reported as unread rather than constructed.
- One TOML entry is declined in the code with its reason: an install-evidence directory of
  a tool installer, whose files are mostly not TOML and whose thousands of cache files
  would bury a case in events saying only that.

## Consequences

Every configuration in the catalogue that is not a credential store now reaches a case as
`config.snapshot`, whatever format it is written in, so a rule about a setting sees the
same shape for every agent. Two rules found evidence on the day this landed that they could
not have found before.

The cost is the cost ADR 0027 named, now paid three times: the reading is thin, and an
event out of it says on itself that nobody has mapped this format. A document that nests
its records deeper than one level keeps them inside the document event rather than getting
one event each, which is a visibly partial reading rather than a wrong one.

The second cost is new. Three formats now share one code path, so a change to the reading
changes all three at once. That is the point, and it is also the risk: the drift tests that
tie each reader's set to the catalogue are what keeps a format from quietly falling out.

We revisit this when an agent's configuration format earns a verified parser, which takes
the artifact over exactly the way a verified parser takes a JSON document over today.

## Alternatives considered

- **Convert YAML and TOML to JSON and hand them to the existing reader.** Loses the
  multi-document case and the non-string key, both of which would then be a crash or a
  silent drop rather than a note.
- **Write a verified parser per agent configuration.** Right eventually, and it does not
  scale to nineteen entries across eight products, which is how they came to be unread.
- **Leave them unread and rely on the file being in the bundle.** That is what the case
  already did, and it produced cases where a permission file was collected, hashed and
  invisible to every rule about permissions.
