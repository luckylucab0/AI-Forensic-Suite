# ADR 0012: Two runtime dependencies, both pure Python

- **Status:** accepted
- **Date:** 2026-09-14

## Context

The analyzer needs to read the YAML artifact catalogue and the YAML rule files, and to
validate both against a JSON Schema. The brief requires few, permissively licensed
dependencies, and the offline constraint sharpens that: an analyst workstation may be
air-gapped, so every wheel has to be vendored, and a compiled wheel has to match the
interpreter version, the platform and the architecture.

That last point rules out the obvious choices. The widely used `jsonschema` pulls `attrs`,
`referencing` and `rpds-py`, and `rpds-py` is a compiled Rust extension. `pydantic` has the
same problem through `pydantic-core`. Neither is a bad library; both would turn "copy the
wheels onto the offline box" into "copy the right wheels for the right Python on the right
architecture".

## Decision

Exactly two runtime dependencies:

- **PyYAML**, MIT licensed, for reading the catalogue and the rules. It has no
  dependencies, and while it ships an optional C extension it falls back to a pure Python
  implementation, so a source install works anywhere. Only `yaml.safe_load` is used;
  `yaml.load` deserializes arbitrary Python objects, which in a tool that reads files from
  a potentially compromised endpoint would be a remote code execution path.
- **fastjsonschema**, BSD-3 licensed, pure Python, no dependencies, for schema validation.
  It compiles a schema into a Python function, which is both faster than interpreting the
  schema and, more importantly here, one file to vendor.

Nothing else at runtime. The web UI uses the standard library (ADR 0006). The collectors
have no dependencies at all (ADR 0004). Development dependencies (ruff, mypy, pytest) are
in a dependency group and are not installed by a user.

Adding a runtime dependency is an ADR, not a commit.

## Consequences

Buys: `pip download` plus a USB stick is a complete offline install, on any platform, with
no architecture matching. The licence audit is two permissive licences.

Costs: `fastjsonschema` is less widely deployed than `jsonschema` and its error messages
are terser, so a schema violation in a catalogue file reports less context. It also
supports fewer draft revisions, so the catalogue schema stays within a well-supported
draft rather than using the newest keywords. Both are acceptable for schemas we write
ourselves and validate in CI.

If a schema feature is ever genuinely needed that `fastjsonschema` lacks, the honest fix is
to change the schema, not to add a compiled dependency to the collection path of a forensic
tool.

## Alternatives considered

- `jsonschema`: three transitive dependencies, one compiled.
- `pydantic`: a compiled core, and it solves a modelling problem we do not have, since the
  catalogue is data on disk and not an API boundary.
- Hand-written validation with no schema: the published schema is itself useful as a
  contract for contributors, and hand-written checks drift from it.
- `ruamel.yaml`: round-trip fidelity we do not need, since nothing writes YAML back.
