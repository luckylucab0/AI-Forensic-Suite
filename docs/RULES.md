<!-- Generated file. Do not edit. -->

# Detection rules

*Generated from rules/ by scripts/gen_rule_docs.py. Do not edit by hand.*

One file per rule under rules/, grouped into packs. A rule is data rather than code: a tree of conditions over named event fields, with no expression to evaluate and nothing callable in a rule file. See docs/adr/0019-rules-are-data-with-their-own-tests.md.

> Every rule is a heuristic. A finding is a lead that needs analyst review, never a verdict.

Every rule carries its own positive and negative samples, and pytest runs each one as its own case. A rule with only positive samples is refused by the loader, because the failure that matters is not a rule that misses: it is a rule that fires on everything, and such a rule passes every positive sample it has.

Findings are written into the case database next to the events they rest on, and every scan is recorded whether or not anything fired. A case with no findings and a case nobody scanned would otherwise look identical, and those are opposite conclusions.

## Packs

| Pack | Id | Severity |
| --- | --- | --- |
| [`anti_forensics`](#anti-forensics) | [AFX-ANTIFORENSICS-001](#afx-antiforensics-001) | high |
|  | [AFX-ANTIFORENSICS-002](#afx-antiforensics-002) | high |
|  | [AFX-ANTIFORENSICS-003](#afx-antiforensics-003) | critical |
|  | [AFX-ANTIFORENSICS-004](#afx-antiforensics-004) | high |
| [`dangerous_commands`](#dangerous-commands) | [AFX-DANGEROUSCOMMANDS-001](#afx-dangerouscommands-001) | high |
|  | [AFX-DANGEROUSCOMMANDS-002](#afx-dangerouscommands-002) | high |
|  | [AFX-DANGEROUSCOMMANDS-003](#afx-dangerouscommands-003) | medium |
| [`data_volume`](#data-volume) | [AFX-DATAVOLUME-001](#afx-datavolume-001) | medium |
|  | [AFX-DATAVOLUME-002](#afx-datavolume-002) | low |
| [`exfil_indicators`](#exfil-indicators) | [AFX-EXFILINDICATORS-001](#afx-exfilindicators-001) | high |
|  | [AFX-EXFILINDICATORS-002](#afx-exfilindicators-002) | medium |
|  | [AFX-EXFILINDICATORS-003](#afx-exfilindicators-003) | medium |
| [`permission_bypass`](#permission-bypass) | [AFX-PERMISSIONBYPASS-001](#afx-permissionbypass-001) | high |
|  | [AFX-PERMISSIONBYPASS-002](#afx-permissionbypass-002) | high |
|  | [AFX-PERMISSIONBYPASS-003](#afx-permissionbypass-003) | medium |
| [`prompt_injection`](#prompt-injection) | [AFX-PROMPTINJECTION-001](#afx-promptinjection-001) | high |
|  | [AFX-PROMPTINJECTION-002](#afx-promptinjection-002) | high |
|  | [AFX-PROMPTINJECTION-003](#afx-promptinjection-003) | medium |
| [`secrets`](#secrets) | [AFX-SECRETS-001](#afx-secrets-001) | high |
|  | [AFX-SECRETS-002](#afx-secrets-002) | critical |
|  | [AFX-SECRETS-003](#afx-secrets-003) | high |
|  | [AFX-SECRETS-004](#afx-secrets-004) | high |
|  | [AFX-SECRETS-005](#afx-secrets-005) | medium |
| [`sensitive_paths`](#sensitive-paths) | [AFX-SENSITIVEPATHS-001](#afx-sensitivepaths-001) | high |
|  | [AFX-SENSITIVEPATHS-002](#afx-sensitivepaths-002) | high |
|  | [AFX-SENSITIVEPATHS-003](#afx-sensitivepaths-003) | critical |
| [`supply_chain`](#supply-chain) | [AFX-SUPPLYCHAIN-001](#afx-supplychain-001) | medium |
|  | [AFX-SUPPLYCHAIN-002](#afx-supplychain-002) | high |
| [`third_party_endpoints`](#third-party-endpoints) | [AFX-THIRDPARTYENDPOINTS-001](#afx-thirdpartyendpoints-001) | high |

Rules are listed by pack, and within a pack by id.

## anti forensics

Steps that shorten or remove the record. The most productive finding in this pack is the one that is documented as incomplete, because it establishes intent and names the directories still worth reading.

#### AFX-ANTIFORENSICS-001

**Transcript retention was lowered below the vendor default**

| | |
| --- | --- |
| Severity | high |
| Pack | `anti_forensics` |
| Agents | `any` |
| Event kinds | `config.snapshot` |
| Fields read | `payload.cleanupPeriodDays`, `payload.desktopSessionCleanupPeriodDays`, `raw.cleanupPeriodDays`, `raw.desktopSessionCleanupPeriodDays` |
| Tags | `T1070`, `retention-reduced` |

A configuration snapshot sets the retention period for transcripts to fewer days than the vendor's default of 30. Claude Code spells this cleanupPeriodDays, and desktopSessionCleanupPeriodDays for desktop and Cowork transcripts.

*What it matches:* `(payload.cleanupPeriodDays < 30 or payload.desktopSessionCleanupPeriodDays < 30 or raw.cleanupPeriodDays < 30 or raw.desktopSessionCleanupPeriodDays < 30)`

*Why an analyst cares:* Retention is the setting that decides how much of an agent's history still exists when somebody comes to look. Lowering it does not delete anything visibly and leaves no command in a shell history, but it shortens the window in which any of this is recoverable, and a value of 0 or 1 means the evidence for all but the current work is already gone. The setting is also the explanation for an absence, which is the other reason to find it: a transcript store that looks swept is a different finding depending on whether the sweep was configured or somebody ran something.

*Known false positives:*

- A deliberate privacy choice. An individual or an organization can decide to keep less, and that is a legitimate configuration rather than an attempt to destroy evidence. The finding says the window is short, not why.
- A machine that was configured once and has kept the setting since, where the low value long predates whatever is being investigated.

*References:*

- <https://code.claude.com/docs/en/settings-reference>
- <https://code.claude.com/docs/en/data-usage>

*Samples in the rule file:* 2 / 2 (+/-)

#### AFX-ANTIFORENSICS-002

**Prompt history recording was suppressed by an environment variable**

| | |
| --- | --- |
| Severity | high |
| Pack | `anti_forensics` |
| Agents | `any` |
| Event kinds | `any` |
| Fields read | `event_text` |
| Tags | `T1070.003`, `history-suppressed` |

An environment variable that stops the agent writing its prompt history appears in a record. For Claude Code the variable is CLAUDE_CODE_SKIP_PROMPT_HISTORY.

*What it matches:* `event_text matches /CLAUDE_CODE_SKIP_PROMPT_HISTORY/ or /(?i)\bSKIP_PROMPT_HISTORY[^\S\n]*=[^\S\n]*(?:1\|true\|yes)/`

*Why an analyst cares:* Prompt history normally outlives the transcripts, because it is a small append-only file that no retention sweep of the same aggressiveness touches. It is therefore often the only surviving record of what a user asked, and suppressing it removes the one artifact that answers that question after the transcripts are gone. A variable set in a shell profile also applies to every future session, which makes it a durable decision rather than a one-off.

*Known false positives:*

- A mention in documentation or in a discussion about privacy settings, which matches because the text on disk is what is searched.
- A variable set to 0 or to an empty value, which the second pattern excludes but the first does not, because the name appearing at all in a shell profile is worth reading.

*References:*

- <https://code.claude.com/docs/en/settings>

*Samples in the rule file:* 2 / 2 (+/-)

#### AFX-ANTIFORENSICS-003

**An agent's own state was purged with its purge command**

| | |
| --- | --- |
| Severity | critical |
| Pack | `anti_forensics` |
| Agents | `any` |
| Event kinds | `command.exec`, `prompt.history` |
| Fields read | `event_text` |
| Tags | `T1070`, `T1485`, `deliberate-destruction` |

A command line runs an agent's own command for removing its stored state for a project. Claude Code spells this claude project purge, which the vendor documents as removing that project's state.

*What it matches:* `event_text matches /\bclaude\s+project\s+purge\b/ or /\bcodex\s+(?:session\|history)\s+(?:purge\|clear\|delete)\b/`

*Why an analyst cares:* This is the one action in this pack that destroys evidence on purpose and says so in its own name. The reason it is worth a critical rather than a high is that the purge is incomplete in a way the vendor documents: the agent's configuration backups, its startup shell snapshots and its session markers are explicitly left alone because they are not project-scoped. So a purge both establishes intent and tells an analyst exactly which directories are still worth reading, which is the most productive kind of finding this tool can produce.

*Known false positives:*

- A purge run for a legitimate reason, such as removing a customer's data from a developer machine at the end of an engagement. Intent is not what this rule reads.
- The command quoted in a runbook or a cleanup script rather than run, which matches because the text on disk is what is searched.

*References:*

- <https://code.claude.com/docs/en/claude-directory>

*Samples in the rule file:* 2 / 2 (+/-)

#### AFX-ANTIFORENSICS-004

**A command removed an agent store, a transcript or a shell history**

| | |
| --- | --- |
| Severity | high |
| Pack | `anti_forensics` |
| Agents | `any` |
| Event kinds | `command.exec`, `prompt.history` |
| Fields read | `event_text` |
| Tags | `T1070.003`, `T1485`, `deliberate-destruction` |

A shell command deletes or truncates a path that holds agent history or shell history: an agent's configuration directory, a transcript store, or one of the shell history files a command invocation would be recorded in.

*What it matches:* `event_text matches /(?:\brm\b(?:\s+-[a-zA-Z]+)*\s\|\bshred\b\|\bunlink\b\|\btruncate\b\|>\s*)/ and event_text matches /\.claude(?:\.json)?\b/ or /\.codex\b/ or /\.copilot\b/ or /\.gemini\b/ or /\.cursor\b/ or /(?:bash\|zsh)_history\b/ or /fish_history\b/ or /ConsoleHost_history\.txt/`

*Why an analyst cares:* Unlike a purge command this leaves nothing behind that names itself, so the deletion has to be read out of the command that did it. It is also the version that reaches the artifacts an agent's own purge does not touch. A shell history removed in the same session as agent work is the specific pattern worth escalating: it removes the record of how the agent was invoked, which is where the flags that answer the bypass question live.

*Known false positives:*

- Ordinary housekeeping. Clearing a cache under an agent directory, or removing a stale lock file, matches and is not destruction of evidence.
- An installer or an uninstaller doing what it is for.
- A redirection into an unrelated file whose path merely mentions one of these directories, since the two halves of this rule are matched over the whole record rather than against each other.

*Samples in the rule file:* 3 / 2 (+/-)

## dangerous commands

Commands whose effect is hard to undo or hard to establish afterwards. Two of these are about destruction and one is about a timeline that can no longer be trusted, which is a different kind of loss and just as relevant.

#### AFX-DANGEROUSCOMMANDS-001

**A recursive delete was run against a broad path**

| | |
| --- | --- |
| Severity | high |
| Pack | `dangerous_commands` |
| Agents | `any` |
| Event kinds | `command.exec` |
| Fields read | `payload.commands[].command` |
| Tags | `T1485`, `destructive-command` |

The agent ran a recursive, forced delete whose target is a root, a home directory, a wildcard at the top of a tree, or a variable that was empty when the command was built. The last case is the one worth reading twice: rm -rf "$DIR"/ with DIR unset deletes from the filesystem root.

*What it matches:* `payload.commands[].command matches /\brm\b[^\|;&]*\s-[a-zA-Z]*[rR][a-zA-Z]*f\|\brm\b[^\|;&]*\s-[a-zA-Z]*f[a-zA-Z]*[rR]/ and payload.commands[].command matches /\brm\b[^\|;&]*\s+/\s*$/ or /\brm\b[^\|;&]*\s+/[a-z]*\s+/ or /\brm\b[^\|;&]*\s+["']?(?:~\|\$HOME\|%USERPROFILE%)["']?/?\s*$/ or /\brm\b[^\|;&]*\s+["']?\$\{?[A-Za-z_][A-Za-z0-9_]*\}?["']?// or /\brm\b[^\|;&]*\s+/\*/`

*Why an analyst cares:* This is the destructive action an agent is most likely to take by accident, and the one whose damage is hardest to establish afterwards, because what was deleted leaves nothing behind that says what it was. Finding the command is often the only way to bound the loss, and the timestamp on it is what tells a restore which backup to go back to.

*Known false positives:*

- A delete inside a container or a build directory that happens to be spelled with an absolute path, which is common in a Dockerfile or a CI script the agent was editing.
- A variable that was in fact set, which the transcript usually cannot confirm. The pattern flags the shape, and the shape is worth reading whether or not it fired.

*Samples in the rule file:* 3 / 2 (+/-)

#### AFX-DANGEROUSCOMMANDS-002

**A command piped a download straight into a shell**

| | |
| --- | --- |
| Severity | high |
| Pack | `dangerous_commands` |
| Agents | `any` |
| Event kinds | `command.exec` |
| Fields read | `payload.commands[].command` |
| Tags | `T1059`, `T1105`, `remote-code-execution` |

The agent fetched something from the network and piped it into a shell or an interpreter in one command, the curl or wget into sh pattern and its PowerShell equivalent.

*What it matches:* `(payload.commands[].command matches /(?:curl\|wget\|Invoke-WebRequest\|iwr\|Invoke-RestMethod)\b[^\|]*\\|\s*(?:sudo\s+)?(?:ba\|z\|d\|k)?sh\b/ or payload.commands[].command matches /(?:curl\|wget)\b[^\|]*\\|\s*(?:sudo\s+)?(?:python[23]?\|perl\|ruby\|node)\b/ or payload.commands[].command matches /(?i)(?:iwr\|Invoke-WebRequest\|Invoke-RestMethod)\b[^\|]*\\|\s*(?:iex\|Invoke-Expression)\b/)`

*Why an analyst cares:* This is remote code execution the agent chose to perform, and the code it ran is not in the transcript: only the address it came from is. So the finding is both the action and the limit of what can be known about it, which is why the address matters more here than in most findings. It is also the shape a prompt injection most often asks an agent to produce, which makes the surrounding conversation worth reading.

*Known false positives:*

- A documented installer. Several widely used tools publish exactly this command as their installation instruction, so the pattern is common in legitimate setup work.
- A line in a Dockerfile or a CI script the agent was reading or writing rather than running, which reaches the command facet only if the agent also executed it.

*Samples in the rule file:* 2 / 2 (+/-)

#### AFX-DANGEROUSCOMMANDS-003

**A command rewrote or force-pushed git history**

| | |
| --- | --- |
| Severity | medium |
| Pack | `dangerous_commands` |
| Agents | `any` |
| Event kinds | `command.exec` |
| Fields read | `payload.commands[].command` |
| Tags | `T1070`, `history-rewritten` |

The agent force-pushed, reset hard, rewrote history with filter-branch or filter-repo, or amended and pushed.

*What it matches:* `(payload.commands[].command matches /\bgit\b[^\|;&]*\bpush\b[^\|;&]*(?:--force\b(?!-with-lease)\|(?<![\w-])-f(?![\w-]))/ or payload.commands[].command matches /\bgit\b[^\|;&]*\breset\b[^\|;&]*--hard\b/ or payload.commands[].command matches /\bgit\b[^\|;&]*\b(?:filter-branch\|filter-repo)\b/)`

*Why an analyst cares:* History rewriting is ordinary developer work and is in this pack for a different reason than the other two: it destroys the timeline an investigation would otherwise use. Commit dates, authorship and the order in which changes appeared are all evidence, and a force push replaces them with something that looks equally authentic. If an agent's work is being reconstructed from a repository, this is the finding that says the repository can no longer be trusted to say when things happened.

*Known false positives:*

- Force-pushing a branch the agent itself created is routine and is what a rebase workflow requires, so on its own this says nothing about intent.
- A reset hard to discard local changes, which is the ordinary way to start over and destroys nothing that was shared.

*Samples in the rule file:* 2 / 2 (+/-)

## data volume

Shape rather than content. These rules say where in a timeline to look deliberately, and nothing about what will be found there.

#### AFX-DATAVOLUME-001

**A session read many files in a short time**

| | |
| --- | --- |
| Severity | medium |
| Pack | `data_volume` |
| Agents | `any` |
| Event kinds | `file.read` |
| Fields read | `payload.files[].path` |
| Tags | `T1005`, `T1083`, `collection` |

Twenty or more file reads from one session inside ten minutes. The count is over reads the agent performed, not over files that exist, so a repository the agent walked once counts once per read.

*What it matches:* `payload.files[].path is present`

*Fires on a count rather than on one event, grouped by* `session_id`, n >= 20, 10 min.

*Why an analyst cares:* A burst of reads is what collection looks like from the inside. An agent working on a change reads the files around it; an agent enumerating a tree reads everything, and the difference between the two is the rate rather than any single read. This is a shape rule rather than a content rule, so it says where in the timeline to look and nothing about what was found there.

*Known false positives:*

- Ordinary work in an unfamiliar repository, where reading twenty files in ten minutes is what understanding the code requires and is the most common cause of this finding.
- A refactor or a dependency upgrade touching many files, which reads all of them.
- A search tool that reports each hit as its own read, which inflates the count without the agent having read twenty distinct things.

*Samples in the rule file:* 1 / 1 (+/-)

#### AFX-DATAVOLUME-002

**A single prompt or tool result carried a very large body of text**

| | |
| --- | --- |
| Severity | low |
| Pack | `data_volume` |
| Agents | `any` |
| Event kinds | `user.prompt`, `tool.result`, `file.read` |
| Fields read | `payload.text`, `payload.output` |
| Tags | `T1005`, `large-transfer` |

One record holds more than sixty thousand characters of text: a paste into a prompt, or a tool result the agent read in one piece.

*What it matches:* `(payload.text is > 60000 long or payload.output is > 60000 long)`

*Why an analyst cares:* Volume is where a leak hides. A credential in a one-line prompt is findable by every rule in the secrets pack; the same credential inside a sixty-thousand-character paste is findable by those rules too, but a human reviewing the transcript will not read that far, and the question of what else was in it stays open. This rule exists to put such a record on the list of things to look at deliberately rather than to accuse it of anything, which is why it is low.

*Known false positives:*

- A log file or a test output the agent was asked to analyse, which is a normal request and produces exactly this.
- A generated file, a lockfile or a minified bundle read in one piece, none of which a person pasted.

*Samples in the rule file:* 1 / 1 (+/-)

## exfil indicators

Data leaving the device. These rules report the shape of a transfer, not its contents, so each one is a question about what was sent rather than an answer.

#### AFX-EXFILINDICATORS-001

**A command posted local data to a paste or file sharing site**

| | |
| --- | --- |
| Severity | high |
| Pack | `exfil_indicators` |
| Agents | `any` |
| Event kinds | `command.exec`, `network.request`, `tool.call` |
| Fields read | `event_text` |
| Tags | `T1567.002`, `T1041`, `exfiltration` |

A command sends data to a paste service, a transfer service or a webhook collector, or pipes a local file into such a request.

*What it matches:* `event_text matches /(?i)\bhttps?://(?:[a-z0-9-]+\.)*(?:pastebin\.com\|paste\.ee\|dpaste\.[a-z]+\|ghostbin\.[a-z]+\|termbin\.com\|0x0\.st\|transfer\.sh\|file\.io\|anonfiles\.[a-z]+\|gofile\.io\|catbox\.moe\|bashupload\.com)\b/ or /(?i)\bhttps?://(?:[a-z0-9-]+\.)*(?:webhook\.site\|requestbin\.[a-z]+\|pipedream\.net\|beeceptor\.com\|interact\.sh\|oast\.[a-z]+)\b/ or /\bnc\s+termbin\.com\s+9999\b/`

*Why an analyst cares:* These destinations exist to make data reachable by URL to anyone who has it, which is what separates them from an ordinary outbound request. An agent asked to share a log or a diff will reach for one, and so will an injected instruction, so the finding is a question about what was sent rather than an answer. The command line usually names the file, which is what makes the question answerable.

*Known false positives:*

- A deliberate share. Putting a build log on a paste site to send to a colleague is ordinary, and the finding cannot tell that from the alternative.
- A collector URL used on purpose while debugging a webhook integration, which is what those services are for.

*Samples in the rule file:* 2 / 2 (+/-)

#### AFX-EXFILINDICATORS-002

**A command encoded local data before sending it**

| | |
| --- | --- |
| Severity | medium |
| Pack | `exfil_indicators` |
| Agents | `any` |
| Event kinds | `command.exec` |
| Fields read | `payload.commands[].command` |
| Tags | `T1132`, `T1041`, `exfiltration` |

A single command reads or encodes local data and sends it in the same pipeline: a base64 or gzip stage feeding a network client, or a request whose body is built from a file.

*What it matches:* `payload.commands[].command matches /\b(?:base64\|openssl\s+enc\|gzip\|tar\s+[a-z]*c\|zip\|xxd)\b/ and payload.commands[].command matches /\b(?:curl\|wget\|nc\|ncat\|socat\|Invoke-WebRequest\|Invoke-RestMethod\|scp\|rsync)\b/`

*Why an analyst cares:* Encoding before sending is not itself suspicious, and that is why this rule is medium. What makes it worth reading is that encoding removes the one thing an outbound request would otherwise reveal, which is what was in it. A finding here says that whatever left cannot be reconstructed from a network record, so the transcript is the only place the answer could still be.

*Known false positives:*

- A legitimate upload of an archive, which is how most artifacts are published and which matches because tar and curl are in the same command.
- A download that is decoded rather than an upload that is encoded, since the pattern reads the command's parts and not their direction.

*Samples in the rule file:* 2 / 2 (+/-)

#### AFX-EXFILINDICATORS-003

**A command pushed to a git remote the agent had just added**

| | |
| --- | --- |
| Severity | medium |
| Pack | `exfil_indicators` |
| Agents | `any` |
| Event kinds | `command.exec` |
| Fields read | `payload.commands[].command` |
| Tags | `T1567`, `exfiltration` |

Within one event the agent both added or set a git remote and pushed to it, or pushed to a remote whose URL carries an embedded credential.

*What it matches:* `(payload.commands[].command matches /\bgit\b[^;&\|]*\bremote\b[^;&\|]*\b(?:add\|set-url)\b[\s\S]{0,400}?\bgit\b[^;&\|]*\bpush\b/ or payload.commands[].command matches /\bgit\b[^;&\|]*\bpush\b[^;&\|]*https?://[^\s/@]+:[^\s/@]+@/)`

*Why an analyst cares:* Pushing code is what a coding agent does, so a push on its own says nothing. A push to a remote that did not exist a moment earlier is different: it means the destination came from the conversation rather than from the repository's own configuration, and a destination that came from the conversation could have come from anywhere in it, including from content the agent read rather than from the user.

*Known false positives:*

- A fork workflow, where adding a second remote and pushing to it in one go is the normal way to do the work.
- A setup script that configures a remote and pushes an initial commit, which is exactly this shape and entirely routine.

*Samples in the rule file:* 2 / 2 (+/-)

## permission bypass

Safety controls that were turned off rather than controls that failed. Both halves of the question are here: what was set at startup, and what was changed afterwards.

#### AFX-PERMISSIONBYPASS-001

**The agent was started with permission prompts skipped**

| | |
| --- | --- |
| Severity | high |
| Pack | `permission_bypass` |
| Agents | `any` |
| Event kinds | `command.exec`, `config.snapshot`, `prompt.history` |
| Fields read | `event_text` |
| Tags | `T1562.001`, `permission-bypass` |

A command line starts an agent with the flag that skips permission prompts, or with the permission mode that does the same. For Claude Code these are --dangerously-skip-permissions and --permission-mode bypassPermissions, which the vendor documents as equivalent.

*What it matches:* `(event_text matches /--dangerously-skip-permissions/ or event_text matches /--permission-mode[= ]+bypassPermissions/)`

*Why an analyst cares:* This is the single clearest answer to the question whether safety controls were bypassed, because it is not a control that failed, it is a control somebody turned off and had to type a word like dangerously to turn off. In this mode the agent writes without asking, including to the paths the vendor protects by default such as the repository's own git directory and the agent's own configuration, so anything found afterwards has to be read knowing that nobody was asked.

*Known false positives:*

- A deliberate use inside a container or a virtual machine, which is what the vendor documentation recommends the mode for. The finding is still correct; whether it was appropriate depends on where the agent was running.
- Documentation, a README or a script that mentions the flag without running it, which matches because the text is what is on disk.

*References:*

- <https://code.claude.com/docs/en/cli-reference>
- <https://code.claude.com/docs/en/permissions>

*Samples in the rule file:* 2 / 2 (+/-)

#### AFX-PERMISSIONBYPASS-002

**The approval mode was changed mid-session to one that stops asking**

| | |
| --- | --- |
| Severity | high |
| Pack | `permission_bypass` |
| Agents | `any` |
| Event kinds | `permission.change` |
| Fields read | `payload.permissions[].mode` |
| Tags | `T1562.001`, `permission-bypass` |

A permission.change event records the agent's approval mode moving to one that auto-approves tool calls. For Claude Code the vendor documents acceptEdits, auto and bypassPermissions as modes that do not prompt for the calls they cover.

*What it matches:* `payload.permissions[].mode is 'bypassPermissions' or 'acceptEdits' or 'auto' or 'dontAsk'`

*Why an analyst cares:* A mode set at startup is a decision about the whole session. A mode changed part way through is a decision about what comes next, which makes the moment it changed the thing to read the transcript around: what was the agent about to do, and who decided it should not be asked about. This is the half of the bypass question a flag on a command line cannot answer.

*Known false positives:*

- acceptEdits is a routine choice for a developer working in a scratch repository, and on its own says little. Read it together with what the agent did next.
- dontAsk auto-denies rather than auto-approves, so it appears here because it stops the prompting rather than because it widens what is allowed. It is in the list because a session that stopped asking is a session whose transcript reads differently, in either direction.

*References:*

- <https://code.claude.com/docs/en/permissions>

*Samples in the rule file:* 2 / 2 (+/-)

#### AFX-PERMISSIONBYPASS-003

**A permission rule allows every call of a whole tool**

| | |
| --- | --- |
| Severity | medium |
| Pack | `permission_bypass` |
| Agents | `any` |
| Event kinds | `config.snapshot` |
| Fields read | `payload.permissions[].subject` |
| Tags | `T1562.001`, `permission-bypass` |

A configuration snapshot holds an allow entry that is a bare tool name. The vendor documents a bare name as matching every call of that tool, so an entry of Bash allows every shell command, Read every file read and WebFetch every outbound request.

*What it matches:* `payload.permissions[].subject is 'Bash' or 'Read' or 'Write' or 'Edit' or 'MultiEdit' or 'WebFetch' or 'WebSearch' or 'NotebookEdit'`

*Why an analyst cares:* This is the quiet version of a bypass. Nobody typed a dangerous-looking flag and no mode changed; a line in a settings file means the prompt for a whole class of action never appears again, in every session, for as long as the file says so. An analyst reading a transcript with no permission prompts in it needs to know whether that is because nothing needed approving or because a rule had already approved it.

*Known false positives:*

- A bare Read entry is close to harmless on its own, because reads inside the working directory need no approval anyway.
- A project that has deliberately allowed a tool and constrained it another way, for example with a deny rule or a pre-tool hook, which the vendor documents as taking precedence over an allow rule.

*References:*

- <https://code.claude.com/docs/en/permissions>

*Samples in the rule file:* 2 / 2 (+/-)

## prompt injection

Whether the agent was manipulated by instructions it read rather than instructions it was given. The scope of these rules is the point: the first one looks only at what came back from a tool, never at a user prompt, because a user is entitled to instruct the agent and a web page is not.

#### AFX-PROMPTINJECTION-001

**Instruction-like text arrived in content the agent read rather than from the user**

| | |
| --- | --- |
| Severity | high |
| Pack | `prompt_injection` |
| Agents | `any` |
| Event kinds | `tool.result`, `mcp.call`, `network.request` |
| Fields read | `event_text` |
| Tags | `prompt-injection`, `T1204` |

A tool result, a fetched page or an MCP response carries text addressed to the agent: telling it to ignore previous instructions, claiming to be a system message, or instructing it to perform an action. The scope is the point. This rule looks only at what came back from a tool, never at a user prompt, because the user is allowed to instruct the agent and a web page is not.

*What it matches:* `(event_text matches /(?i)ignore\s+(?:all\s+)?(?:the\s+)?(?:previous\|prior\|above\|earlier)\s+(?:instructions?\|prompts?\|rules?\|context)/ or event_text matches /(?i)disregard\s+(?:all\s+)?(?:previous\|prior\|the\s+above\|your)\s+(?:instructions?\|rules?\|system\s+prompt)/ or event_text matches /(?i)</?(?:system\|system-reminder\|important_instructions\|IMPORTANT)>/ or event_text matches /(?i)\b(?:you\s+are\s+now\|from\s+now\s+on\s+you\|new\s+instructions?\s*:\|system\s+override)\b/ or event_text matches /(?i)\bdo\s+not\s+(?:tell\|mention\|inform)\s+the\s+user\b/)`

*Why an analyst cares:* This is the answer to whether the agent was manipulated by injected instructions, which is one of the questions this suite exists for. An agent cannot distinguish instructions from data in the text it reads, so content that speaks to the agent in the imperative is the mechanism, and finding it in a tool result is finding the delivery. What the agent did in the turns after the match is where the consequence would be.

*Known false positives:*

- Documentation about prompt injection, which necessarily quotes these phrases and is exactly what a developer asks an agent to read when working on the problem.
- A test fixture or a security test suite in the repository the agent was working in.
- A conversation in an issue tracker or a pull request the agent fetched, where somebody was discussing an agent's behaviour.

*References:*

- <https://owasp.org/www-project-top-10-for-large-language-model-applications/>

*Samples in the rule file:* 2 / 2 (+/-)

#### AFX-PROMPTINJECTION-002

**Text the agent read contained invisible or direction-changing characters**

| | |
| --- | --- |
| Severity | high |
| Pack | `prompt_injection` |
| Agents | `any` |
| Event kinds | `tool.result`, `mcp.call`, `network.request`, `file.read`, `user.prompt`, `config.snapshot` |
| Fields read | `event_text` |
| Tags | `prompt-injection`, `T1027`, `obfuscation` |

A record carries zero-width characters, bidirectional overrides, or Unicode tag characters. Zero-width joiners and spaces are invisible; bidi overrides make text render in an order different from the order it is stored in; tag characters are a block that renders as nothing at all and is sometimes used to smuggle a whole instruction.

*What it matches:* `event_text matches /[​‌‍⁠﻿]/ or /[‪-‮⁦-⁩]/ or /[󠀀-󠁿]/`

*Why an analyst cares:* A human reviewing a page, a pull request or a configuration file sees one thing and the agent reads another. That gap is the entire technique, and unlike a phrase-based injection there is no benign version of it in ordinary prose. It is also invisible to the reviewer by construction, which is why a tool has to be the thing that finds it.

*Known false positives:*

- A legitimate use of a zero-width joiner, which is how several writing systems and most emoji sequences are composed. A record in a language that uses them will match.
- A byte order mark at the start of a file, which is ordinary on Windows and matches the first pattern.

*References:*

- <https://www.unicode.org/reports/tr9/>

*Samples in the rule file:* 3 / 2 (+/-)

#### AFX-PROMPTINJECTION-003

**A project instruction file arrived with the work rather than with the project**

| | |
| --- | --- |
| Severity | medium |
| Pack | `prompt_injection` |
| Agents | `any` |
| Event kinds | `file.write`, `file.read`, `config.snapshot`, `memory.write` |
| Fields read | `kind`, `payload.files[].path`, `payload.instructions[].scope` |
| Tags | `prompt-injection`, `T1547`, `persistence` |

An instruction file was written or changed during the session, or one was read from a path outside the working directory the agent reported. Instruction files are the ones an agent loads and obeys: CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules, .windsurfrules, the files under .cursor/rules and .github/instructions, and an MCP configuration.

*What it matches:* `(kind is 'file.write' or 'memory.write' and payload.files[].path matches path **/CLAUDE.md or **/CLAUDE.local.md or **/AGENTS.md or **/GEMINI.md or **/.cursorrules or **/.windsurfrules or **/.cursor/rules/** or **/.github/copilot-instructions.md or **/.github/instructions/** or **/.kiro/steering/** or **/.mcp.json or **/mcp.json or **/claude_desktop_config.json or payload.instructions[].scope is 'project' or 'local')`

*Why an analyst cares:* These files are instructions to the agent that no user has to type and that persist into every later session. A repository that was cloned with one already in it has effectively shipped instructions to whoever opens it next, and one written mid-session has changed the rules the rest of the session ran under. Either way the question an analyst needs settled is whether the agent's instructions came from the person operating it.

*Known false positives:*

- A developer asking the agent to write or update the project's own instruction file, which is a normal and recommended thing to do and produces exactly this event.
- A project whose instruction file has been in version control for months, where the finding says only that it was in effect.

*Samples in the rule file:* 3 / 2 (+/-)

## secrets

Credentials that reached a transcript. These rules search the whole record rather than the mapped fields, because a credential can sit anywhere in one, including in a field no parser understood. None of them quotes what it matched.

#### AFX-SECRETS-001

**A cloud provider access key reached an agent transcript**

| | |
| --- | --- |
| Severity | high |
| Pack | `secrets` |
| Agents | `any` |
| Event kinds | `any` |
| Fields read | `event_text` |
| Tags | `T1552.001`, `credential-in-transcript` |

An access key identifier in the shape a major cloud provider issues appears somewhere in this record: a prompt, a tool argument, a tool result or a field no parser mapped. The whole record is searched rather than the fields somebody thought to map, because a credential can sit anywhere in one.

*What it matches:* `event_text matches /\bAKIA[0-9A-Z]{16}\b/`

This rule does not quote what it matched. The matched value is a credential, and a finding is exported and pasted into reports, so the value stays in the event it came from.

*Why an analyst cares:* A key that reached a transcript has left the developer's control twice over. It was sent to a model provider as part of the conversation, and it is now on disk in a file that is not a secret store, that is not encrypted, and that synchronisation and backup tools treat as ordinary text. Whether the key was used is a separate question; that it has to be rotated is not.

*Known false positives:*

- A key of this shape quoted in documentation, a test fixture or an example, which is common in a repository that teaches cloud usage.
- A key that was already revoked before the conversation, which the transcript cannot say.

*References:*

- <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html>

*Samples in the rule file:* 2 / 2 (+/-)

#### AFX-SECRETS-002

**A private key block reached an agent transcript**

| | |
| --- | --- |
| Severity | critical |
| Pack | `secrets` |
| Agents | `any` |
| Event kinds | `any` |
| Fields read | `event_text` |
| Tags | `T1552.004`, `credential-in-transcript` |

The opening line of a PEM private key block appears in this record. Matched on the header rather than on the key material, because the header is the part that is the same across every key type and cannot occur by accident.

*What it matches:* `event_text matches /-----BEGIN (?:RSA \|EC \|DSA \|OPENSSH \|PGP \|ENCRYPTED )?PRIVATE KEY-----/`

This rule does not quote what it matched. The matched value is a credential, and a finding is exported and pasted into reports, so the value stays in the event it came from.

*Why an analyst cares:* A private key in a transcript is the strongest form of this finding. Unlike an API token it usually cannot be rotated without touching every system that trusts it, the header is unambiguous so there is little room for a false positive, and the reason a key ends up in a conversation is almost always that somebody pasted a file they should not have.

*Known false positives:*

- A test key committed to a repository on purpose, which many projects carry for their own test suites.
- Documentation that shows the shape of a key file without a real key in it.

*References:*

- <https://www.rfc-editor.org/rfc/rfc7468>

*Samples in the rule file:* 2 / 2 (+/-)

#### AFX-SECRETS-003

**A model provider API token reached an agent transcript**

| | |
| --- | --- |
| Severity | high |
| Pack | `secrets` |
| Agents | `any` |
| Event kinds | `any` |
| Fields read | `event_text` |
| Tags | `T1552.001`, `credential-in-transcript` |

A token in the shape several model providers issue, an sk- prefix followed by a long opaque string, appears in this record.

*What it matches:* `event_text matches /\bsk-[A-Za-z0-9_-]{20,}\b/`

This rule does not quote what it matched. The matched value is a credential, and a finding is exported and pasted into reports, so the value stays in the event it came from.

*Why an analyst cares:* This is the credential that pays for inference, and one of the few in a developer's possession that bills by use. A token in a transcript is both an unrotated secret and a spending risk, and a transcript is a file that gets copied into bug reports and support tickets more readily than a credential store ever would be.

*Known false positives:*

- A revoked or example token quoted in documentation or in a test.
- Another vendor's identifier that happens to use the same prefix, which is not rare. The prefix is a convention rather than a registered scheme.

*Samples in the rule file:* 2 / 2 (+/-)

#### AFX-SECRETS-004

**A source forge personal access token reached an agent transcript**

| | |
| --- | --- |
| Severity | high |
| Pack | `secrets` |
| Agents | `any` |
| Event kinds | `any` |
| Fields read | `event_text` |
| Tags | `T1552.001`, `credential-in-transcript` |

A token in the documented prefixed shape a major source forge issues appears in this record. The prefixes cover personal access tokens, OAuth tokens, user-to-server and server-to-server tokens and refresh tokens.

*What it matches:* `event_text matches /\bgh[pousr]_[A-Za-z0-9]{20,}\b/`

This rule does not quote what it matched. The matched value is a credential, and a finding is exported and pasted into reports, so the value stays in the event it came from.

*Why an analyst cares:* This token is usually the one with the most reach in a developer's possession: it can read private repositories, push code, and in many configurations act on the organization's behalf. It is also the credential a coding agent has the most reason to be handed, which is what makes a transcript a likely place to find one.

*Known false positives:*

- A token already revoked, which the forge does on publication but which the transcript cannot say.
- A token of this shape used in a test fixture.

*References:*

- <https://github.blog/security/application-security/behind-githubs-new-authentication-token-formats/>

*Samples in the rule file:* 2 / 2 (+/-)

#### AFX-SECRETS-005

**A secret was assigned to a named variable in view of the agent**

| | |
| --- | --- |
| Severity | medium |
| Pack | `secrets` |
| Agents | `any` |
| Event kinds | `any` |
| Fields read | `event_text` |
| Tags | `T1552.001`, `credential-in-transcript` |

A variable or key whose name says it holds a credential, assigned a value of plausible length, appears in this record. This is the shape that catches the credentials no vendor prefix identifies: a database password, an internal service token, a signing key.

*What it matches:* `event_text matches /(?i)\b(?:api[_-]?key\|secret\|passwd\|password\|client[_-]?secret\|access[_-]?token\|auth[_-]?token\|private[_-]?key)\b[^\S\n]*[:=][^\S\n]*["']?[A-Za-z0-9_\-/+.]{8,}/`

This rule does not quote what it matched. The matched value is a credential, and a finding is exported and pasted into reports, so the value stays in the event it came from.

*Why an analyst cares:* Most credentials have no recognisable prefix, so a pack that only matched known shapes would report the ones that are easy to find and miss the ones that are specific to the organization. Matching the assignment rather than the value is deliberately broad, which is why this rule is medium: it is a lead to read rather than a conclusion.

*Known false positives:*

- A placeholder, which this rule cannot tell from a value. Both password=changeme and password=REDACTED match, and both are common in documentation and in templates.
- A configuration file the agent read that holds an environment variable name rather than a value, such as password=$DB_PASSWORD.
- A key name in a schema or a type definition, where the value is a type rather than a secret.

*Samples in the rule file:* 2 / 2 (+/-)

## sensitive paths

Paths an agent read that hold credentials or the map to them. What makes a read a finding is the destination: the contents went into a conversation with a model provider and onto disk in a transcript.

#### AFX-SENSITIVEPATHS-001

**The agent read a private key or an SSH configuration**

| | |
| --- | --- |
| Severity | high |
| Pack | `sensitive_paths` |
| Agents | `any` |
| Event kinds | `file.read`, `command.exec`, `tool.call` |
| Fields read | `payload.files[].path`, `payload.commands[].command` |
| Tags | `T1552.004`, `sensitive-path-read` |

A file read, a shell command or a tool argument names a path under an SSH directory, a key file by its conventional name, or a certificate or keystore extension.

*What it matches:* `(payload.files[].path matches path **/.ssh/** or **/id_rsa or **/id_ed25519 or **/id_ecdsa or **/id_dsa or **/*.pem or **/*.p12 or **/*.pfx or **/*.jks or **/*.keystore or payload.commands[].command matches /(?:^\|[\s"'=])(?:~\|/[A-Za-z0-9_./-]*)?/\.ssh/\|\bid_(?:rsa\|ed25519\|ecdsa\|dsa)\b/)`

*Why an analyst cares:* A private key the agent read has been sent to a model provider as part of the conversation and written into a transcript on disk, so the read is the moment the key left the developer's control regardless of what the agent did next. An SSH configuration is worth almost as much: it names the hosts and the identities available from this machine, which is the map somebody moving laterally would want.

*Known false positives:*

- Reading a public key, which shares the directory and often most of the name. The finding names the path, so the distinction is one glance away.
- Legitimate work on SSH configuration, which is a normal thing to ask an agent for and requires reading exactly these files.
- A test key inside a project, which many projects carry for their own test suites.

*Samples in the rule file:* 3 / 2 (+/-)

#### AFX-SENSITIVEPATHS-002

**The agent read a cloud or package registry credential file**

| | |
| --- | --- |
| Severity | high |
| Pack | `sensitive_paths` |
| Agents | `any` |
| Event kinds | `file.read`, `command.exec`, `tool.call` |
| Fields read | `payload.files[].path`, `payload.commands[].command` |
| Tags | `T1552.001`, `sensitive-path-read` |

A file read or a command names a credential file belonging to a cloud provider command line tool, a container registry, a package registry or a Kubernetes configuration.

*What it matches:* `(payload.files[].path matches path **/.aws/credentials or **/.aws/config or **/.azure/** or **/.config/gcloud/** or **/.kube/config or **/.docker/config.json or **/.npmrc or **/.pypirc or **/.netrc or **/.git-credentials or **/gcloud/application_default_credentials.json or payload.commands[].command matches /\.aws/credentials\b/ or /\.kube/config\b/ or /\.docker/config\.json\b/ or /\.(?:npmrc\|pypirc\|netrc\|git-credentials)\b/ or /application_default_credentials\.json\b/)`

*Why an analyst cares:* These files are the ones that turn a developer machine into access to production. Unlike a password they are usually long-lived, and unlike an SSH key they are frequently read by legitimate tooling, so their appearance in an agent transcript is easy to overlook. What makes it a finding is the destination: the contents went into a conversation with a model provider and onto disk in a transcript.

*Known false positives:*

- Legitimate configuration work. Asking an agent to fix a broken cloud profile or a registry authentication problem requires reading exactly these files.
- A tool the agent ran that reads the file itself, where the path appears in the command line without the agent having read the contents into the conversation.

*Samples in the rule file:* 3 / 2 (+/-)

#### AFX-SENSITIVEPATHS-003

**The agent read a browser profile, a keychain or a password store**

| | |
| --- | --- |
| Severity | critical |
| Pack | `sensitive_paths` |
| Agents | `any` |
| Event kinds | `file.read`, `command.exec`, `tool.call` |
| Fields read | `payload.files[].path`, `payload.commands[].command` |
| Tags | `T1555`, `T1539`, `credential-store-access` |

A file read or a command names a browser profile database, an operating system keychain or credential store, or the data directory of a password manager.

*What it matches:* `(payload.files[].path matches path **/Login Data or **/Cookies or **/logins.json or **/key4.db or **/cert9.db or **/Library/Keychains/** or **/.local/share/keyrings/** or **/.password-store/** or **/*.kdbx or **/1Password/** or **/Bitwarden*/** or payload.commands[].command matches /\bsecurity\s+(?:find-generic-password\|find-internet-password\|dump-keychain)\b/ or /\bsecret-tool\s+(?:lookup\|search)\b/ or /(?i)\bGet-Credential\b\|\bcmdkey\s+/list\b/ or /\.kdbx\b\|\.password-store\b\|logins\.json\b\|key4\.db\b/)`

*Why an analyst cares:* There is no ordinary software engineering reason to read any of these. A browser profile holds saved passwords, cookies and session tokens for everything the user is signed in to; a keychain holds the credentials the operating system keeps on the user's behalf; a password manager's store is the whole of it. This is the one rule in the pack where a match is closer to a conclusion than to a lead, which is why it is critical and why its false positive list is short.

*Known false positives:*

- Work on a tool that legitimately integrates with one of these stores, such as a credential helper the agent was asked to write or debug.
- A path named Cookies or Login Data belonging to something other than a browser profile, which the finding's full path settles in one glance.

*Samples in the rule file:* 3 / 2 (+/-)

## supply chain

Code the agent loaded, and code configured to run without anyone asking. An MCP server is both a dependency and a tool surface, which is why what it is matters as much as what it did.

#### AFX-SUPPLYCHAIN-001

**An MCP server was launched from a package fetched at start time**

| | |
| --- | --- |
| Severity | medium |
| Pack | `supply_chain` |
| Agents | `any` |
| Event kinds | `config.snapshot`, `command.exec`, `mcp.call` |
| Fields read | `event_text` |
| Tags | `T1195`, `T1072`, `supply-chain` |

A configuration snapshot or a command starts an MCP server through a runner that downloads the package as it launches it: npx -y, uvx, pipx run, bunx or the equivalent.

*What it matches:* `(event_text matches /\buvx\b/ or /\bpipx\s+run\b/ or /\bbunx\b/ or event_text matches /\bnpx\b/ and event_text matches /(?:^\|[\s,=])(?:-y\|--yes)(?:$\|[\s,])/ or event_text matches /\bdeno\s+run\b[^\n]*\b--allow-(?:all\|run\|net)\b/)`

*Why an analyst cares:* An MCP server is code the agent loads and a tool surface the agent will call, so what it is matters as much as what it does. A runner that fetches at start time means the code is whatever the registry served that day, there is no lockfile, and -y suppresses the prompt that would otherwise name the package. Finding the configuration is how an analyst establishes which server versions could have been in play, since the machine may no longer have the answer.

*Known false positives:*

- The vendor's own documented way to run most MCP servers, which is exactly this. The finding is about what can be established later, not about a mistake.
- An ordinary developer command that has nothing to do with MCP, since npx and uvx are general-purpose runners.

*Samples in the rule file:* 2 / 2 (+/-)

#### AFX-SUPPLYCHAIN-002

**A hook or a lifecycle script was configured to run a command**

| | |
| --- | --- |
| Severity | high |
| Pack | `supply_chain` |
| Agents | `any` |
| Event kinds | `config.snapshot`, `file.write` |
| Fields read | `payload.hooks`, `payload.files[].path`, `event_text` |
| Tags | `T1546`, `T1195.002`, `persistence` |

A configuration snapshot holds a hook that runs a shell command, or a file write adds a git hook or a package lifecycle script.

*What it matches:* `(payload.hooks is present or payload.files[].path matches path **/.git/hooks/* or **/.husky/** or **/.claude/hooks/** or **/.claude/settings.json or **/.claude/settings.local.json or event_text matches /(?i)"(?:PreToolUse\|PostToolUse\|SessionStart\|UserPromptSubmit\|Stop\|PreCompact)"\s*:/ or event_text matches /"scripts"\s*:[\s\S]{0,200}"(?:preinstall\|postinstall\|prepare)"\s*:/)`

*Why an analyst cares:* A hook is code that runs without anyone asking, at a moment the agent chose, and the vendor documents that a pre-tool hook can let a call proceed without the prompt that would otherwise appear. That makes a hook both a persistence mechanism and a permission bypass wearing different clothes. It also survives the session, so a hook found on a machine is a question about every session since it was written, not just this one.

*Known false positives:*

- A project that uses hooks for what they are for, formatting on commit being the obvious case, which is good practice and matches.
- A settings file written because the developer granted a permission through the agent's own interface, which is the documented way to do it.

*References:*

- <https://code.claude.com/docs/en/permissions>

*Samples in the rule file:* 3 / 2 (+/-)

## third party endpoints

Where the conversation actually went. An endpoint override changes the answer to which data left the device for a whole session, and nothing in a transcript says which endpoint served it.

#### AFX-THIRDPARTYENDPOINTS-001

**The agent's model endpoint was pointed somewhere other than its vendor**

| | |
| --- | --- |
| Severity | high |
| Pack | `third_party_endpoints` |
| Agents | `any` |
| Event kinds | `config.snapshot`, `command.exec`, `prompt.history`, `session.start` |
| Fields read | `event_text` |
| Tags | `T1090`, `T1071`, `third-party-endpoint` |

A base URL override, a proxy variable or a custom provider setting appears in a record: ANTHROPIC_BASE_URL, OPENAI_BASE_URL, an equivalent for another provider, or an HTTPS proxy set for the agent's process.

*What it matches:* `event_text matches /(?i)\b(?:ANTHROPIC\|OPENAI\|AZURE_OPENAI\|GOOGLE\|GEMINI\|MISTRAL\|GROQ\|DEEPSEEK\|OPENROUTER)_(?:BASE_URL\|API_BASE\|ENDPOINT)[^\S\n]*[:=][^\S\n]*\S/ or /(?i)\bANTHROPIC_AUTH_TOKEN[^\S\n]*[:=][^\S\n]*\S/ or /(?i)\b(?:HTTPS?_PROXY\|ALL_PROXY)[^\S\n]*[:=][^\S\n]*\S/ or /(?i)"(?:baseURL\|base_url\|apiBase\|api_base\|endpoint)"[^\S\n]*:[^\S\n]*"https?:///`

*Why an analyst cares:* This decides where the conversation went. Every prompt, every file the agent read into context and every credential that reached a transcript was sent to whatever this points at, so an override changes the answer to "which data left the device" for the whole session. It is also a quiet setting: nothing in a transcript says which endpoint served it, so the configuration is the only place the answer exists.

*Known false positives:*

- A corporate proxy or an approved inference gateway, which is a legitimate and common configuration. The finding says where the traffic went, not whether that was allowed.
- A base URL for something other than the model endpoint, such as an application's own API, which matches the last pattern because the key name is generic.

*References:*

- <https://code.claude.com/docs/en/llm-gateway>

*Samples in the rule file:* 3 / 2 (+/-)
