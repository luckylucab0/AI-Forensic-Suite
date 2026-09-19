# Architecture decision records

One short record per decision, in English. Each says what forced the decision, what was
decided, and what it costs. An ADR without a cost section is usually a decision nobody
examined.

Add one with the next free number, using [0000-template.md](0000-template.md).

| ADR | Decision |
| --- | --- |
| [0001](0001-a-suite-around-the-existing-viewer.md) | Build a suite around the existing viewer rather than replacing it |
| [0002](0002-package-and-cli-name.md) | The package and CLI are named `agentforensics` |
| [0003](0003-catalogue-is-the-single-source-of-truth.md) | The artifact catalogue is the single source of truth |
| [0004](0004-two-single-file-collectors.md) | Two single-file collectors, Python 3.8 and PowerShell 5.1 |
| [0005](0005-bundle-mirrors-original-paths.md) | The evidence bundle mirrors original paths, custody is a hash chain |
| [0006](0006-standard-library-web-server.md) | The local UI uses the standard library, not a web framework |
| [0007](0007-bilingual-documentation.md) | Documentation is bilingual, code is English |
| [0008](0008-opsec-guard-and-fresh-history.md) | Fresh history, and an OpSec guard against identity leakage |
| [0009](0009-never-drop-a-record.md) | No record is ever dropped, truncated or hidden |
| [0010](0010-no-organization-scope-feature.md) | The suite does not look for one organization's own data |
| [0011](0011-agent-guidance-stays-local.md) | Agent guidance and the original brief are not published |
| [0012](0012-runtime-dependencies.md) | Two runtime dependencies, both pure Python |
| [0013](0013-catalogue-schema-fields.md) | Five fields added to the artifact entry beyond the original list |
| [0014](0014-one-path-one-manifest-entry.md) | One path is one manifest entry, and the strictest claim on it wins |
| [0015](0015-verified-means-the-vendor-said-so.md) | verified means the vendor said so, not that somebody wrote it down |
| [0016](0016-one-sqlite-file-per-case.md) | One SQLite file per case, with every event keyed by its provenance |
| [0017](0017-unattributed-evidence-is-a-finding.md) | A file the catalogue does not claim is a finding, not a non-event |
| [0018](0018-one-unified-log-format.md) | One unified log format, and it is the event model on the wire |
| [0019](0019-rules-are-data-with-their-own-tests.md) | A rule is data, carries its own tests, and findings live in the case |
| [0020](0020-the-case-is-read-as-a-unified-log.md) | The local UI reads a case as a unified log, under a per-run token |
| [0021](0021-source-available-licence.md) | The licence is the Elastic License 2.0, not MIT |
| [0022](0022-an-unknown-sqlite-store-is-read-uninterpreted.md) | A SQLite store with no verified schema is read uninterpreted, never guessed |
| [0023](0023-the-instruction-surface-is-its-own-event-kind.md) | The instruction surface is read into its own event kind, and is never called a system prompt |
| [0024](0024-the-python-floor-is-3-14.md) | The analyzer requires Python 3.14, so zstd comes from the standard library |
| [0025](0025-the-attribution-of-a-file-is-a-hint-not-a-verdict.md) | The entry a source attributed a file to is a hint, and the best claimant wins |
| [0026](0026-a-store-comparison-is-a-view-not-a-rule.md) | Comparing an agent's stores against each other is a view, and produces no findings |
| [0027](0027-a-json-document-is-split-by-structure-not-meaning.md) | A whole JSON document is split by its structure, one level deep, and never by a guess at its meaning |
| [0028](0028-yaml-and-toml-are-read-the-way-json-is.md) | The YAML and TOML documents are read by the same rule, from one shared reader |
