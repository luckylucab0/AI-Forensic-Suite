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
| [0013](0013-catalogue-schema-fields.md) | Four fields added to the artifact entry beyond the original list |
