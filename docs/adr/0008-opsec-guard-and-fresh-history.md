# ADR 0008: Fresh history, and an OpSec guard against identity leakage

- **Status:** accepted
- **Date:** 2026-09-14

## Context

This repository is public. Its predecessor contained a scan hardcoded to one organization's
domains, references to internal hostnames, and a hosted-instance URL on a subdomain
carrying a personal name. Git makes any of that permanent: a later commit does not remove
it from history, and forks, mirrors and code search caches keep their own copy within
minutes.

The audience makes this worse rather than better. People run this tool inside companies, so
a leaked internal identifier is not just embarrassing, it tells anyone who looks which
company the author works for and what its infrastructure is named.

## Decision

The repository starts from a fresh history containing only sanitized files. The previous
history is never imported.

`scripts/opsec_check.py` scans the files git tracks, the content staged for the next
commit, and the commit message, case-insensitively, against a gitignored
`.opsec-denylist`. It is wired as a `pre-commit` and a `commit-msg` hook, and runs in CI
reading the denylist from a repository secret when one exists.

Four behaviors are deliberate:

- A missing denylist exits 0 with a notice. A fresh clone, an outside contributor and CI
  without the secret all legitimately have no list, and failing there would only teach
  people to bypass the hook.
- A hit prints a path, a line number and the index of the entry that matched, never the
  matched text. This output lands in terminals, CI logs and screenshots.
- A tracked `.opsec-denylist` is a hard error, because a committed denylist publishes
  exactly what it protects.
- An `opsec-check: allow-line` marker and a gitignored `.opsec-allowlist` exist for the
  real exception, a test that must contain a denied string to prove the guard works.

A second, independent CI layer scans for generic secrets such as keys and tokens, which is
a different problem from identity leakage.

## Consequences

Buys: a mechanical barrier in front of the mistake that cannot be undone.

Costs: the guard only sees the present. It does not scan history, so it cannot clear a
repository for publication on its own, and `CONTRIBUTING.md` carries an ordered
pre-publication procedure for that. The guard also depends on the denylist being complete,
which is a human judgement: it catches the strings somebody thought of.

The honest limit is worth stating: if something leaks and is published, rewriting history
does not retract a fork or a cached search result. The mitigation is to not publish it,
which is why the check runs before the commit rather than after the push.

## Alternatives considered

- Manual review only: the failure mode is a tired person at the end of a long change.
- A generic secret scanner alone: those look for credentials, not for the name of a company.
