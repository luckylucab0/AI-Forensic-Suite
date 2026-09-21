# Evidence bundle format, version 1

English | [Deutsch](BUNDLE_FORMAT.de.md)

This is the contract between collection and analysis. Everything to the left of it happens
on a machine under investigation, possibly compromised, under time pressure, with no
dependencies available. Everything to the right happens offline and can afford to be
thorough. Two independent collectors implement this specification, one in Python 3.8 and
one in PowerShell 5.1, so it is written to be implementable twice rather than to describe
what one program happens to do.

## Layout

```
<bundle>/
  manifest.json            what was collected, from where, with what hashes
  chain_of_custody.jsonl    append-only, hash-chained record of who did what
  files/                   collected content, mirroring original paths
    C/Users/alice/.claude/settings.json
    Users/alice/.claude/settings.json
    registry/HKLM/SOFTWARE/Policies/ClaudeCode.json
```

Optionally the whole directory is zipped to `<bundle>.zip`, with `<bundle>.zip.sha256`
beside it holding the hash and the file name in the format `sha256sum` reads.

Mirroring original paths is the reason ingest is uniform. A native bundle, a KAPE output
tree and a Velociraptor offline collection are all a root plus original paths, so one
adapter shape reads all three, plus a mounted image and an exported profile.

## A registry key, as a document

Only the PowerShell collector writes these and only when it is running on the host itself,
because a key cannot be read from a mounted image without a hive parser and this suite has
none. Four catalogue entries are carried this way, and which four is not a property of the
format: it is in `scripts/build_collectors.py` with the reason, and a test binds it to the
catalogue. The two registry entries left out are the platform's own execution evidence and
an installer's persistence keys, which every general purpose registry tool reads better
than this one would and which are not about an agent's behaviour.

A key becomes one JSON document:

```json
{
  "format_version": 1,
  "key": "HKLM\\SOFTWARE\\Policies\\ClaudeCode",
  "last_write_utc": "2026-09-14T09:02:11.000000Z",
  "values": [
    { "name": "Settings", "type": "REG_SZ", "data": "{\"permissions\": {\"allow\": []}}" },
    { "name": "Enabled", "type": "REG_DWORD", "data": 1 },
    { "name": "Paths", "type": "REG_MULTI_SZ", "data": ["C:\\one", "C:\\two"] },
    { "name": "Blob", "type": "REG_BINARY", "data_base64": "AAEC" }
  ],
  "subkeys": ["Managed"]
}
```

Field notes:

- `name` is the value's name exactly as the registry holds it, so the unnamed default value
  is the empty string. The analyzer shows it as `(default)`; the document does not rename
  it, because a document that renamed it could not be compared against the registry.
- `type` is the registry type name. A string, a number and a list of strings are carried as
  themselves; anything else is carried as `data_base64` instead of `data`, because bytes
  put through a text encoding stop being the bytes that were there.
- `last_write_utc` belongs to the key. The registry keeps no time per value, so every value
  of one key shares it and every event the analyzer makes out of them says so.
- `subkeys` is the names only. A subkey that is itself catalogued is collected as its own
  entry; one that is not is recorded here so a case says it existed.
- A key that does not exist is a manifest entry with `collected: false` and no document,
  the same as a file that was not there. That distinction is the point: for a policy key,
  an empty document means the policy was not set and a missing one means the key was never
  created, and both are different from nobody having looked.

## manifest.json

```json
{
  "format_version": 1,
  "tool": {
    "name": "collect.py",
    "version": "0.1.0",
    "sha256": "<hash of the collector file that ran>",
    "catalogue_version": "<hash of the embedded catalogue>"
  },
  "collection": {
    "uuid": "<random v4, identifies this collection everywhere downstream>",
    "started_utc": "2026-09-14T10:11:12.131415Z",
    "finished_utc": "2026-09-14T10:11:48.900000Z",
    "local_timezone": "+02:00",
    "local_timezone_name": "CEST",
    "hostname": "<as the endpoint reports it>",
    "os": "windows",
    "os_version": "10.0.22631",
    "architecture": "AMD64",
    "collector_user": "alice",
    "elevated": true,
    "argv": ["collect.py", "--all-users", "--zip"],
    "include_secrets": false,
    "max_file_size": 268435456,
    "root": null,
    "agents_filter": null
  },
  "users": [
    { "name": "alice", "home": "C:\\Users\\alice", "collected": true },
    { "name": "bob", "home": "C:\\Users\\bob", "collected": false, "reason": "permission_denied" }
  ],
  "project_roots": [
    { "path": "C:\\src\\app", "source": "claude_code.global_config" }
  ],
  "files": [
    {
      "artifact_id": "claude_code.transcripts",
      "agent": "claude_code",
      "category": "transcript",
      "user": "alice",
      "original_path": "C:\\Users\\alice\\.claude\\projects\\C--src-app\\1f2e.jsonl",
      "bundle_path": "files/C/Users/alice/.claude/projects/C--src-app/1f2e.jsonl",
      "size": 918273,
      "sha256": "<hash of the bytes as collected>",
      "mtime_utc": "2026-09-13T21:04:55.120000Z",
      "ctime_utc": "2026-09-13T21:04:55.120000Z",
      "atime_utc": "2026-09-14T06:30:01.000000Z",
      "birthtime_utc": "2026-09-01T08:15:00.000000Z",
      "collected": true,
      "reason": null,
      "status": "verified",
      "symlink": null,
      "reparse_point": false,
      "changed_while_reading": false
    }
  ],
  "counts": { "hit": 412, "collected": 402, "skipped": 10, "errors": 2 },
  "errors": [
    { "path": "C:\\Users\\bob\\.claude", "error": "permission_denied", "detail": "..." }
  ],
  "refused_patterns": [
    { "pattern": "$CLAUDE_CONFIG_DIR/projects/*/*.jsonl",
      "expanded": "$CLAUDE_CONFIG_DIR/projects/*/*.jsonl",
      "reason": "environment_unreadable_offline" }
  ]
}
```

Field notes that are not obvious:

- `tool.sha256` is the hash of the collector file as it ran. An analyst can then prove
  which build produced the bundle, including whether it was modified before use.
- `catalogue_version` is the hash of the embedded catalogue, so a collection can be tied
  to the exact artifact definitions that produced it.
- `local_timezone` is recorded once rather than per timestamp. Every timestamp in the
  bundle is UTC; the offset is what lets an analyst reconcile a log line against a
  witness statement.
- `status` on a file entry is copied from the catalogue. It is here so the analyzer can
  report that an empty result came from an unverified path, which is inconclusive, rather
  than from a verified one, which is evidence.
- `reason` is null when `collected` is true, otherwise one of `too_large`,
  `secret_policy`, `permission_denied`, `unreadable`, `not_a_file`, `skipped_symlink`.
  `secret_policy` means the path was claimed by at least one artifact with
  `sensitivity: secret` and `--include-secrets` was not given: the entry still carries its
  size, hash and timestamps, so its presence and its identity are recorded without copying
  credential material. Any claim is enough, so a credential file that a broad directory
  glob also matched is still withheld.
- `artifact_ids` is present only when more than one artifact claimed the same path, and
  then lists all of them, sorted. `artifact_id` stays single-valued and names the most
  specific claim, so a file is attributed to the entry that names it rather than to a
  directory glob that happened to include it, while `artifact_ids` preserves the fact that
  the others matched too.
- `changed_while_reading` is set when the file's size or mtime differs between the hash
  and a re-stat afterwards. The bytes in the bundle are still exactly what was hashed;
  the flag says the source was live.
- `symlink` holds the link target when the entry was a symlink inside the profile, and the
  entry is skipped with `skipped_symlink` when the target lies outside it.
- `source_kind` is present only on an entry that is not a file, and its only value is
  `registry`. Such an entry's `original_path` is the key as the catalogue spells it, its
  `bundle_path` names a JSON document written by the collector rather than bytes copied off
  the disk, and its `mtime_utc` is the key's last-write time, which is the only timestamp
  the registry keeps. There is no `ctime_utc`, `atime_utc` or `birthtime_utc`: a key has
  none. The `sha256` is of the document as written, so it verifies like every other entry.
- `refused_patterns` lists the catalogue patterns the collector declined to search, with
  the pattern as written, how far it got expanding it, and one of `not_absolute`,
  `wildcard_too_broad`, `wildcard_only`, `malformed_variable`,
  `environment_unreadable_offline`, `environment_unreadable_other_user`,
  `profile_is_a_symlink`, `no_project_root` or `registry_key`. The last one is a whole class rather than a
  defect in one pattern: the file pass reads the filesystem and a key is not a path in it,
  so a catalogued key it cannot search is declined by name. It appears only for the
  registry entries this collector does not read at all, since the four it does read are
  collected by the registry pass above and would otherwise be reported twice, once as a
  refusal and once as the entry holding their contents. The two declined are the platform's
  own execution evidence and an installer's persistence keys, and they stay evidence
  somebody goes and gets with the registry facility of whichever tool they are running. It exists because a pattern nobody searched is a hole in the
  coverage, and a bundle that is silent about it looks exactly like a bundle from a host
  where the artifact was absent.

  `environment_unreadable_offline` is the one an analyst will normally see, and it is not
  a defect. Several agents relocate their whole data tree with an environment variable of
  their own, `CLAUDE_CONFIG_DIR` and `CODEX_HOME` among them. On a live host the collector
  reads the variable and follows it. Collecting a mounted image with `--root` there is no
  such environment to read, and the analyst's own is not the endpoint's, so the pattern is
  reported instead of guessed at: look for the variable in the image's shell profiles and
  collect again with `--project-root` or a second pass if it was set.

  `environment_unreadable_other_user` is the same answer for the same reason, on a live
  host. A collection that walks every profile has one environment, the collector's own, and
  applying this user's `CLAUDE_CONFIG_DIR` to somebody else's profile would search this
  user's directory and file what it found under that user's name. Their variable is theirs
  to read: look in their shell profile or their registry, and collect that profile again
  from their session.

  `no_project_root` records a pattern anchored at a working copy on a run where none was
  discovered. Only the agents' own state files say which directories a user had open, and
  when they name none, or when there are none to read, the project tier of the catalogue
  cannot be searched at all. One line per pattern, so the count is the size of the hole,
  and the answer is to collect again with `--project-root` once somebody knows where the
  repositories are. It is reported per pattern rather than once per entry because an entry
  commonly holds both scopes: the profile and system wide paths of the same entry were
  searched, and this is about the other half (ADR 0041).

  `profile_is_a_symlink` records a profile directory the collector did not descend into.
  Where such a link points is not known to be inside the tree being collected: on a live
  host it can leave the profile directory, and in a mounted image it can carry the original
  machine's absolute path and land on the analyst's own disk. The entry names the profile,
  so a relocated home is a lead rather than an absence.

  A pattern that simply does not apply is not listed here. A Windows path on a Linux host,
  a freedesktop variable on Windows, or a relocation variable that is genuinely unset are
  all ordinary, and every one of them has a sibling pattern in the same artifact that is
  being searched.

## Path mapping

Original absolute path to a path under `files/`, applied segment by segment.

1. **Root.** A POSIX path loses its leading `/`. A Windows drive path turns `C:\` into the
   single segment `C`, upper case, colon dropped. A Windows UNC path `\\server\share\...`
   becomes `UNC/server/share/...`.
2. **Percent-encoding.** In each segment, `%` becomes `%25` first, so the mapping stays
   reversible. Then every byte in `< > : " | ? * \` and `/`, every control byte below
   0x20, and every byte that is not valid UTF-8, becomes `%XX` with upper-case hex.
3. **Trailing dot or space.** Windows silently strips these from a file name, so a
   trailing `.` or ` ` is percent-encoded.
4. **Reserved device names.** If a segment's stem, upper-cased, is `CON`, `PRN`, `AUX`,
   `NUL`, `COM0` to `COM9` or `LPT0` to `LPT9`, its first character is percent-encoded.
   `CON.txt` becomes `%43ON.txt`, which no longer names a device.
5. **Over-long segments.** A segment longer than 200 bytes after encoding is cut to 190
   bytes, at a UTF-8 character boundary, and gets `~` plus the first 10 hex characters of
   the SHA-256 of the original segment.
6. **Case collisions.** If the result collides, case-insensitively, with a bundle path
   already used, `~` plus the first 10 hex characters of the SHA-256 of the full original
   path is appended to the last segment. This is what stops `Settings.json` and
   `settings.json` from overwriting each other when a case-sensitive source is written to
   a case-insensitive destination.

Steps 1 to 4 reverse exactly. Steps 5 and 6 do not, which is why **`original_path` is
mandatory on every file entry**: the encoding is never the only record of where something
came from. An analyzer that needs the original path reads it from the manifest, never by
decoding a bundle path.

## chain_of_custody.jsonl

One JSON object per line, appended, never rewritten.

```json
{"seq": 0, "event": "collected", "time_utc": "...", "actor": "alice", "host": "...",
 "tool": "collect.py 0.1.0", "manifest_sha256": "...", "prev_sha256": null, "sha256": "..."}
{"seq": 1, "event": "verified", "time_utc": "...", "actor": "analyst", "host": "...",
 "tool": "agentforensics 0.1.0", "manifest_sha256": "...", "result": "ok",
 "prev_sha256": "<sha256 of record 0>", "sha256": "..."}
```

Each record carries the hash of the previous record and its own hash, computed over the
record with `sha256` removed and keys sorted. Removing or altering a record therefore
breaks the chain at a detectable point.

The honest claim is **tamper-evident, not tamper-proof**. The file sits in a writable
directory and anyone who can write it can rewrite the whole chain. What the chain buys is
that they cannot do it to one record quietly. Stronger guarantees need a signature or an
external timestamp, which is a later decision and not a change to this format.

## Read-only guarantees

- The collector writes nothing outside `--out`. No temporary files elsewhere, no logs, no
  configuration.
- Nothing on the target is modified, moved, renamed or deleted, and no agent binary is
  executed. Version information is read from files.
- Access times: the collector opens with `O_NOATIME` where the platform and the file's
  ownership permit it. Where it cannot, it records the original `atime` before reading, so
  the value in the manifest is the one from before the collection touched it, and the fact
  that reading updated it is knowable rather than hidden.
- Symlinks are not followed outside the profile being collected. A link that points
  outside is recorded with its target and skipped.
- On Windows, reparse points and junctions are detected and recorded rather than
  traversed, so a junction loop cannot make a collection run forever or duplicate content.
- A file that changes while being read is hashed once; the hash matches the bytes stored,
  and `changed_while_reading` records the discrepancy.
- Files locked by a running agent are reported as `unreadable` with the platform error.
  Volume shadow copies are out of scope for version 1 and are noted as such.

## Determinism

Two collections of the same unchanged tree must produce byte-identical manifests apart
from the fields that genuinely differ (times, uuid, argv).

- `files` is sorted by `artifact_id`, then `original_path`, using byte order.
- JSON is written with sorted keys, two-space indent, `\n` line endings, no trailing
  whitespace, and a final newline. Non-ASCII is written as UTF-8 rather than escaped.
- Timestamps are `YYYY-MM-DDTHH:MM:SS.ffffffZ`, microseconds always present, UTC always.
  A timestamp the platform cannot supply is `null`, never zero and never the epoch.
- The zip stores entries in the same order as `files`, with deflate and no extra
  attributes. Entry timestamps are the original file's mtime, not the collection time,
  because a zip whose contents change between two runs of an unchanged tree cannot be
  compared by hash.

## Fields allowed to differ between the two collectors

This list is part of the specification, not an implementation detail. It is where the
operating systems genuinely disagree, and the differential test in CI normalizes exactly
these and nothing else.

| Field | Why it differs |
| --- | --- |
| `collection.os`, `os_version`, `architecture`, `hostname`, `collector_user` | Platform facts |
| `collection.argv`, `uuid`, `started_utc`, `finished_utc` | Per-run |
| `tool.name`, `tool.sha256` | Two different files implement this |
| `birthtime_utc` | Not available on Linux. `null` there, present on macOS and Windows |
| `ctime_utc` | Inode change time on Unix, creation time on Windows. Same field name, different meaning, documented rather than reconciled |
| `atime_utc` | Meaningless on a volume mounted `noatime`, and coarse under `relatime` |
| `bundle_path` separators | Always `/` in the manifest, including on Windows |
| `original_path` separators | As the platform reports them, so `\` on Windows |
| Path case | A case-insensitive source reports the case the filesystem stores, which need not match the case a glob used |
| `users[].home` | Different layouts per platform |
| `collection.elevated` | Administrator on Windows, uid 0 on Unix, and `null` where the platform would not say. Null is a third answer on purpose: "not elevated" and "could not find out" lead an analyst to different conclusions about why a collection is thin, and the field must not state the first when it means the second |
| `collection.local_timezone_name` | The operating system's own name for the zone. `UTC` on Unix and `Coordinated Universal Time` on Windows for the same zone; `collection.local_timezone`, the offset, is the field to reconcile timestamps with |

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Collected at least one artifact |
| 1 | Ran, but at least one error was recorded in the manifest |
| 2 | Could not run: bad arguments, output directory unusable |
| 3 | Ran successfully and found nothing |

Code 3 exists because "this host has no agent artifacts" is a valid and useful result. A
caller must be able to tell it apart from a crash, and a fleet sweep that treats the two
the same produces a wrong picture of where agents are in use.
