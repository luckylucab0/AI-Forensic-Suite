# ADR 0003: The artifact catalogue is the single source of truth

- **Status:** accepted
- **Date:** 2026-09-14

## Context

The same knowledge, where each agent stores its data, is needed in at least eight places:
both collectors, five collection-rule exporters (Velociraptor, KAPE, Defender live
response, KQL, osquery), the analyzer's parsers, and the documentation. Written out by
hand, those copies diverge, and the failure is silent: a path fixed in the collector but
stale in the KAPE target means a fleet-wide hunt quietly returns nothing.

## Decision

One YAML file per agent under `catalog/`, validated against
`catalog/schema/catalog.schema.json`. Everything that needs a path is generated from it:

- `scripts/build_collectors.py` renders it into a JSON blob between marker comments inside
  each collector
- the exporters render it into `exporters/generated/`
- `scripts/gen_artifact_docs.py` renders `docs/ARTIFACTS.md` and `docs/ARTIFACTS.de.md`

Every generator has a `--check` mode, and CI runs all of them and fails on any difference.
Generated files are committed so a reader can see them without running anything.

The schema lives under `catalog/`, not inside the Python package, so CI and a collector can
validate without importing `agentforensics`.

Every entry carries `status` and `source`. `verified` requires a source URL that actually
states the path. Everything else is `unverified`, is still collected by glob, and is
flagged as unverified in analyzer output.

## Consequences

Buys: a path can never be right in one place and wrong in another, and adding an agent is a
data change rather than a code change across eight files.

Costs: a generation step in the workflow that contributors must remember, mitigated by the
`--check` modes failing loudly. Committed generated output also makes some diffs larger
than the change that caused them.

The `status` field carries real weight: without the unverified flag reaching analyzer
output, an empty collection result would be indistinguishable from "the agent was never
used". That distinction is the difference between an answer and a wrong answer.

## Alternatives considered

- Paths in Python, exporters importing the package: collectors must stay dependency-free
  single files, so they cannot import anything.
- A database: needless for a few hundred entries that want to be reviewed in pull requests.
