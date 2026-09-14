# ADR 0007: Documentation is bilingual, code is English

- **Status:** accepted
- **Date:** 2026-09-14
- **Supersedes:** the English-only rule in the original project brief

## Context

The brief specified English for everything. The project owner subsequently asked for German
documentation alongside the English. Both are reasonable: English is what an
international contributor and a DFIR audience read, German is what the primary users read.

Bilingual documentation has one predictable failure: someone edits the English file, the
German one keeps its old text, and a German reader is now confidently told something untrue.
That is worse than no translation, because it looks current.

## Decision

- Code, identifiers, comments, commit messages and ADRs stay English. ADRs in particular
  are an internal engineering log, and translating them would guarantee drift for no
  reader benefit.
- Documentation is bilingual. The English file is canonical, a `.de.md` sibling carries the
  German version, and each file opens with a one-line language switcher.
- Generated documents are produced in both languages by the same script. Structural labels
  come from `docs/locales/{en,de}.yaml`. Free-text fields in the catalogue and rule YAML
  accept either a plain string, treated as English, or an `{en: ..., de: ...}` mapping, so
  German can be added entry by entry without blocking a contribution, and the generator
  marks untranslated text visibly rather than pretending.
- Drift is caught by `scripts/check_translations.py`, which keeps
  `docs/translations.lock.json` mapping each English file to its SHA-256. CI fails when an
  English file changed and the lock was not refreshed. Refreshing the lock is the explicit
  act of saying "I read the German file and it matches".
- The check only considers files git tracks, so a local, gitignored document is nobody's
  translation obligation.

German text uses Swiss orthography, `ss` rather than the sharp s.

## Consequences

Buys: German readers get documentation that is either current or loudly flagged as not
current, and the mechanism is honest about what it verifies.

Costs: a translation must be updated in the same commit as the English text, which slows
documentation changes. Nothing here checks whether a translation is *correct*, only whether
someone claimed to have looked. A machine cannot do the former, and pretending otherwise
would move the rot somewhere harder to see.

## Alternatives considered

- German only: excludes contributors and most of the DFIR audience.
- Machine translation in CI: produces text nobody has read, in a document whose whole value
  is that it is accurate.
- A documentation site with an i18n framework: a dependency and a build step for four files.
