# Security

English | [Deutsch](SECURITY.de.md)

## Reporting a vulnerability

Please report privately first, through GitHub's private vulnerability reporting on this
repository (the Security tab, "Report a vulnerability"). That keeps the report out of
public issues until there is a fix.

Include what you did, what happened, and what you expected. A minimal reproduction, ideally
with a synthetic fixture rather than real data, helps most. Please do not attach real agent
transcripts, evidence bundles or anything from a live investigation: they contain personal
data, and a bug report is not a lawful place to store it.

Expect an acknowledgement within a few days. This is a small project, so please be patient
with timelines, and say up front if you have a disclosure deadline.

## What counts as a vulnerability here

This is an offline analysis tool, not a service, so the interesting classes are not the
usual web ones.

- **Path traversal in the bundle writer or the ingest adapters.** A crafted original path
  inside an evidence bundle that makes the analyzer read or write outside the intended
  directory. The bundle comes from a potentially compromised endpoint, so its content is
  untrusted input.
- **Anything executed from evidence.** Deserialization, template evaluation, a subprocess
  built from a field in a log. Evidence is data and must never become code.
- **Regular expression denial of service in the rule engine.** Rules are data from a public
  repository, and they run over attacker-influenced text such as fetched web pages inside
  tool results. A rule that backtracks catastrophically can stall an investigation.
- **Cross-site scripting in the viewer.** Agent transcripts contain text an attacker
  controls: fetched pages, tool output, injected instructions. The viewer renders that,
  so an escaping mistake is a real finding, not a theoretical one.
- **Anything that makes the tool write to evidence.** The read-only guarantee is the
  foundation everything else rests on. A bug that modifies, moves or deletes a source
  artifact, or that updates an access time we promised not to touch without recording it,
  is a serious defect.
- **Anything that makes the tool reach the network.** No part of the pipeline may make a
  network call. An accidental DNS lookup, an update check or a font fetched from a CDN all
  break the offline guarantee and can tip off a subject.
- **A silent loss of evidence.** A record dropped, truncated or hidden without a trace.
  It is not a memory-safety issue, but in this tool it causes a wrong conclusion, so it is
  treated with the same seriousness.
- **Leakage through output.** A finding, an export or a log line that reproduces a secret
  or an internal identifier where it was not supposed to.

Out of scope: the web UI being reachable from another machine if you deliberately bind it
somewhere other than loopback, and heuristic rules producing false positives or missing
things. Heuristics are documented as heuristics.

## Dual use

This tool locates credential files and reconstructs everything a developer typed. The same
capability that lets an investigator answer a question lets someone else mine a colleague's
machine, or lets an attacker who already has a foothold find the fastest path to secrets
and to the developer's own knowledge.

That is not a reason to keep the knowledge private. Where agent data lives is discoverable
by anyone who looks, several vendors document it themselves, and defenders are the ones
currently at a disadvantage: security teams cannot answer basic questions about tools their
developers already use every day. What is worth doing is making the defaults protective.

- Artifacts marked `sensitivity: secret`, credential files above all, are recorded as
  metadata plus a hash by default. Their content is not copied unless the operator
  explicitly asks with `--include-secrets`, and that choice is recorded in the manifest.
- The collector writes only into its output directory, never anywhere else, and never
  executes an agent binary on the target.
- Nothing is sent anywhere. There is no telemetry and no network access, so the tool cannot
  become an exfiltration channel of its own.
- The data model is built so that pseudonymizing users and hosts is a later feature rather
  than a rewrite, because plenty of legitimate uses do not need to know who.
- The documentation states plainly that use requires authorization. See the README.

## Publishing detection rules that name anti-forensic techniques

The `anti_forensics` rule pack describes, in public, how someone would suppress an agent's
history: which setting shortens retention, which environment variable disables
persistence, which command purges a project. Publishing that teaches the countermeasure
along with the detection.

We publish it anyway, and the reasoning is worth stating rather than leaving implicit.
Every one of those mechanisms is a documented product feature, described in the vendors'
own manuals for legitimate reasons. Someone motivated to cover their tracks finds them in
a search, not here. The people who genuinely do not know they exist are the defenders, and
leaving them uninformed buys nothing. What we do not publish is anything that only helps an
attacker and no defender, and rules stay honest about their limits: each one documents its
known false positives, and a finding is a lead that needs analyst review, never a verdict.
