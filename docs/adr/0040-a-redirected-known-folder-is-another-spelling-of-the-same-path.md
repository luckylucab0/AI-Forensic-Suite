# ADR 0040: A redirected known folder is another spelling of the same path

- **Status:** accepted
- **Date:** 2026-09-21

## Context

Seven catalogue paths sit under the profile's Documents folder: one product's user-visible
output folder and six directories another product discovers its global rules, workflows,
hooks, agent definitions and plugins in. They are catalogued as `~/Documents/...`, which is
what the vendors' own code joins.

On Windows that path is frequently not where the folder is. OneDrive's Known Folder Move
redirects Documents into the OneDrive tree, and in a managed fleet it is commonly on by
default. The literal profile path then holds nothing, a collection of it comes back empty,
and the absence reads as a profile that never had a global rule. One of the two vendors
documents the problem in its own source and works around it by reading three environment
variables, `OneDrive`, `OneDriveConsumer` and `OneDriveCommercial`, and joining `Documents`
to each; the other does not, which means its own client would also look in the wrong place
while the folder written by its extension sits under OneDrive.

The collector already searches both locations for a redirected `%APPDATA%` or `%TEMP%`,
from the environment, on a live host and for the process's own profile only. That mechanism
cannot answer for Documents: there is no `%DOCUMENTS%` placeholder, and a mounted image has
no environment to ask, which is the case where a redirected folder is hardest to notice.

## Decision

The redirected location is a second spelling of the same artifact and lives in the same
catalogue entry, next to the literal one, as `~/OneDrive*/Documents/...`.

A glob rather than an environment variable, for three reasons. It works on a mounted image,
where the variable does not exist and where this evidence is most often read. It matches
the commercial folder, which is named `OneDrive - <tenant>` after the organization, without
that name having to be written down anywhere: a catalogue that spelled it out would violate
the first non-negotiable of this repository. And every consumer of the catalogue already
handles a wildcard in a segment, so no collector, exporter or matcher needs a new
placeholder.

Each such path is listed in `unsourced_paths` unless the entry's own cited source states
it, which is true for exactly one of them.

## Consequences

A Windows collection now takes the global instruction surface on a redirected machine,
which is most managed machines, and an empty result from it means the folder was empty.

The cost is a glob that can match a directory somebody named `OneDriveBackup`, which
collects a few files nobody asked for. That is the cheap direction of this trade: a false
match costs a manifest entry, a missed match costs the evidence.

Two gaps stay, and they are honest ones. A OneDrive root moved outside the profile is not
matched by a profile-anchored glob, and nothing in a bundle would say so; an examiner
working on a live host can read the variable, one working from an image has to look for the
junction. And a folder redirected by Group Policy to a network share is in neither place.
Both are the reason the entries say what they say rather than claiming completeness.

What would make us revisit it: a `%DOCUMENTS%` placeholder resolved from the shell folders
registry key would answer all three cases on Windows, at the price of teaching seven
consumers a new placeholder and of reading a registry hive out of an image. Worth doing if
a real collection turns up the network-share case.

## Alternatives considered

- **An environment variable placeholder `%ONEDRIVE%`.** Works only where the environment is
  the endpoint's, which excludes every image, and needs a new placeholder in both collectors
  and five exporters.
- **A separate catalogue entry for the redirected tree.** Two entries for one logical thing
  breaks the rule that an entry lists every spelling of the same artifact, and the formats
  under Documents differ per entry, so it would have had to be several.
- **Nothing, with a note in the entry.** The note is what an analyst reads after the
  collection came back empty, which is too late.
