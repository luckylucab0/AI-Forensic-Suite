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
|  | [AFX-ANTIFORENSICS-005](#afx-antiforensics-005) | low |
|  | [AFX-ANTIFORENSICS-006](#afx-antiforensics-006) | medium |
| [`collection_integrity`](#collection-integrity) | [AFX-COLLECTIONINTEGRITY-001](#afx-collectionintegrity-001) | medium |
|  | [AFX-COLLECTIONINTEGRITY-002](#afx-collectionintegrity-002) | info |
|  | [AFX-COLLECTIONINTEGRITY-003](#afx-collectionintegrity-003) | low |
|  | [AFX-COLLECTIONINTEGRITY-004](#afx-collectionintegrity-004) | low |
|  | [AFX-COLLECTIONINTEGRITY-005](#afx-collectionintegrity-005) | low |
|  | [AFX-COLLECTIONINTEGRITY-006](#afx-collectionintegrity-006) | medium |
| [`dangerous_commands`](#dangerous-commands) | [AFX-DANGEROUSCOMMANDS-001](#afx-dangerouscommands-001) | high |
|  | [AFX-DANGEROUSCOMMANDS-002](#afx-dangerouscommands-002) | high |
|  | [AFX-DANGEROUSCOMMANDS-003](#afx-dangerouscommands-003) | medium |
| [`data_volume`](#data-volume) | [AFX-DATAVOLUME-001](#afx-datavolume-001) | medium |
|  | [AFX-DATAVOLUME-002](#afx-datavolume-002) | low |
| [`exfil_indicators`](#exfil-indicators) | [AFX-EXFILINDICATORS-001](#afx-exfilindicators-001) | high |
|  | [AFX-EXFILINDICATORS-002](#afx-exfilindicators-002) | medium |
|  | [AFX-EXFILINDICATORS-003](#afx-exfilindicators-003) | medium |
|  | [AFX-EXFILINDICATORS-004](#afx-exfilindicators-004) | high |
| [`permission_bypass`](#permission-bypass) | [AFX-PERMISSIONBYPASS-001](#afx-permissionbypass-001) | high |
|  | [AFX-PERMISSIONBYPASS-002](#afx-permissionbypass-002) | high |
|  | [AFX-PERMISSIONBYPASS-003](#afx-permissionbypass-003) | medium |
|  | [AFX-PERMISSIONBYPASS-004](#afx-permissionbypass-004) | medium |
|  | [AFX-PERMISSIONBYPASS-005](#afx-permissionbypass-005) | high |
|  | [AFX-PERMISSIONBYPASS-006](#afx-permissionbypass-006) | medium |
|  | [AFX-PERMISSIONBYPASS-007](#afx-permissionbypass-007) | high |
|  | [AFX-PERMISSIONBYPASS-008](#afx-permissionbypass-008) | medium |
|  | [AFX-PERMISSIONBYPASS-009](#afx-permissionbypass-009) | high |
| [`prompt_injection`](#prompt-injection) | [AFX-PROMPTINJECTION-001](#afx-promptinjection-001) | high |
|  | [AFX-PROMPTINJECTION-002](#afx-promptinjection-002) | high |
|  | [AFX-PROMPTINJECTION-003](#afx-promptinjection-003) | medium |
|  | [AFX-PROMPTINJECTION-004](#afx-promptinjection-004) | high |
| [`secrets`](#secrets) | [AFX-SECRETS-001](#afx-secrets-001) | high |
|  | [AFX-SECRETS-002](#afx-secrets-002) | critical |
|  | [AFX-SECRETS-003](#afx-secrets-003) | high |
|  | [AFX-SECRETS-004](#afx-secrets-004) | high |
|  | [AFX-SECRETS-005](#afx-secrets-005) | medium |
|  | [AFX-SECRETS-006](#afx-secrets-006) | high |
|  | [AFX-SECRETS-007](#afx-secrets-007) | high |
|  | [AFX-SECRETS-008](#afx-secrets-008) | medium |
| [`sensitive_paths`](#sensitive-paths) | [AFX-SENSITIVEPATHS-001](#afx-sensitivepaths-001) | high |
|  | [AFX-SENSITIVEPATHS-002](#afx-sensitivepaths-002) | high |
|  | [AFX-SENSITIVEPATHS-003](#afx-sensitivepaths-003) | critical |
| [`supply_chain`](#supply-chain) | [AFX-SUPPLYCHAIN-001](#afx-supplychain-001) | medium |
|  | [AFX-SUPPLYCHAIN-002](#afx-supplychain-002) | high |
|  | [AFX-SUPPLYCHAIN-003](#afx-supplychain-003) | high |
|  | [AFX-SUPPLYCHAIN-004](#afx-supplychain-004) | high |
| [`third_party_endpoints`](#third-party-endpoints) | [AFX-THIRDPARTYENDPOINTS-001](#afx-thirdpartyendpoints-001) | high |
|  | [AFX-THIRDPARTYENDPOINTS-002](#afx-thirdpartyendpoints-002) | medium |
|  | [AFX-THIRDPARTYENDPOINTS-003](#afx-thirdpartyendpoints-003) | medium |

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

*What it matches:* `event_text matches /(?:\brm\b(?:\s+-[a-zA-Z]+)*\s\|\bshred\b\|\bunlink\b\|\btruncate\b\|>\s*)/ and event_text matches /\.claude(?:\.json)?\b/ or /\.agents\b/ or /\.aider[a-z.]*\b/ or /\.amp\b/ or /\.cline(?:rules)?\b/ or /\.codeium\b/ or /\.codex\b/ or /\.continue\b/ or /\.copilot\b/ or /\.cursor(?:-server)?\b/ or /\.devin\b/ or /\.factory\b/ or /\.gemini\b/ or /\.hermes\b/ or /\.junie\b/ or /\.kilocode\b/ or /\.kiro\b/ or /\.lmstudio\b/ or /\.ollama\b/ or /\.pi\b/ or /\.qwen\b/ or /\.roo\b/ or /\.windsurf(?:-next\|-server)?\b/ or /(?:bash\|zsh)_history\b/ or /fish_history\b/ or /ConsoleHost_history\.txt/`

*Why an analyst cares:* Unlike a purge command this leaves nothing behind that names itself, so the deletion has to be read out of the command that did it. It is also the version that reaches the artifacts an agent's own purge does not touch. A shell history removed in the same session as agent work is the specific pattern worth escalating: it removes the record of how the agent was invoked, which is where the flags that answer the bypass question live.

*Known false positives:*

- Ordinary housekeeping. Clearing a cache under an agent directory, or removing a stale lock file, matches and is not destruction of evidence.
- An installer or an uninstaller doing what it is for.
- A redirection into an unrelated file whose path merely mentions one of these directories, since the two halves of this rule are matched over the whole record rather than against each other.

*Samples in the rule file:* 4 / 2 (+/-)

#### AFX-ANTIFORENSICS-005

**An agent's own saved-permission file is named in the global git excludes**

| | |
| --- | --- |
| Severity | low |
| Pack | `anti_forensics` |
| Agents | `any` |
| Event kinds | `config.snapshot` |
| Fields read | `payload.key`, `payload.text` |
| Tags | `T1070`, `proof-of-use` |

The user's global git excludes file names an agent's saved-permission file. One agent appends that pattern by itself, the first time it writes such a file into a repository that does not already ignore it, so the pattern is a record the agent left outside every directory it owns.

*What it matches:* `payload.key matches /^exclude:/ and payload.text matches /(?i)(^\|[/\\*])\.(claude\|cline\|codeium\|continue\|cursor\|aider\|qwen\|gemini)[/\\]/`

*Why an analyst cares:* This is the one finding here that survives a thorough clean-up, which is why it is worth a rule despite being small. Deleting an agent's configuration directory, purging its projects and clearing its transcripts leaves this line untouched: it is in git's file, in the user's own configuration directory, and nothing an agent does removes it. So it says two things after everything else is gone. That the agent ran on this machine at all, and that it wrote at least one saved permission, which means somebody was asked to approve something and the answer was kept for next time. It says nothing about what was approved or when. It is low severity because on a machine where the agent was used openly it is entirely expected, and it becomes interesting only next to an absence: an endpoint whose agent directories are gone and whose git excludes still carry this line.

*Known false positives:*

- A pattern the user wrote themselves, which is common and indistinguishable from one an agent appended. The finding is that the line is there, not who put it there.
- A machine where the agent is still installed and in daily use, where this is the expected state and says nothing beyond that.
- A pattern naming one of these directories for an unrelated reason, since the directory names are short and several are ordinary words.

*References:*

- <https://code.claude.com/docs/en/settings>

*Samples in the rule file:* 2 / 2 (+/-)

#### AFX-ANTIFORENSICS-006

**The agent was configured to leave no trace of itself in git history**

| | |
| --- | --- |
| Severity | medium |
| Pack | `anti_forensics` |
| Agents | `any` |
| Event kinds | `config.snapshot`, `prompt.history`, `command.exec`, `unparsed.record` |
| Fields read | `event_text` |
| Tags | `T1070`, `T1562.001`, `attribution-defeated` |

A setting or an environment variable turns off the trailers one agent writes into every commit it makes: the thread identifier that links a commit to the conversation behind it, and the co-author line that says an agent wrote the code. Amp spells the settings amp.git.commit.ampThread.enabled and amp.git.commit.coauthor.enabled, and the variables AMP_DISABLE_AMP_THREAD_TRAILER and AMP_DISABLE_AMP_COAUTHOR_TRAILER.

*What it matches:* `event_text matches /AMP_DISABLE_AMP_(?:THREAD\|COAUTHOR)_TRAILER[^\S\n]*[=:][^\S\n]*\S/ or /amp\.git\.commit\.(?:ampThread\|coauthor)\.enabled[^\S\n]*[=:][^\S\n]*false/`

*Why an analyst cares:* Both trailers are on by default, and the thread identifier is frequently the only link between a commit in a repository and the conversation that produced it, because the conversation itself is not necessarily on the endpoint at all. With them off, the agent's commits are indistinguishable from anybody else's work in the one place an organisation is most likely to look. That makes this the inverse of most findings here: it does not destroy a record, it stops one being written, so there is nothing later to recover and the only evidence that it happened is this configuration. It is also the answer to a question an investigation will otherwise get wrong. A repository whose history carries no agent trailers reads as a repository no agent touched, and that conclusion is only safe once this rule has come back empty.

*Known false positives:*

- A commit-message policy. A repository can reject trailers, a team can strip them for tidiness, and a squash or rebase workflow can drop them anyway, so a project that turns them off has an ordinary reason available.
- A mention rather than a setting. The rule searches the text a record holds, so documentation of the variable that happens to show an assignment matches. A question about it in a conversation is out of scope by kind and cannot reach this rule.
- A value set after the period under investigation, since a settings file says what is in force and not when the line was written. Compare its mtime against the session times before reading it as intent.

*References:*

- <https://ampcode.com/manual/configuration.md>

*Samples in the rule file:* 4 / 3 (+/-)

## collection integrity

Whether what was collected can answer the question it is being asked. Every other pack says something happened on the endpoint; this one says a part of the collection may be looking in the wrong place, which is the one failure that reads exactly like a clean result. Its rule is generated from the catalogue, because a list of catalogue facts copied into a rule file is a list that stops being true without anybody noticing.

#### AFX-COLLECTIONINTEGRITY-001

**An agent was configured to write somewhere else, or not at all**

| | |
| --- | --- |
| Severity | medium |
| Pack | `collection_integrity` |
| Agents | `any` |
| Event kinds | `config.snapshot`, `prompt.history`, `command.exec`, `unparsed.record` |
| Fields read | `event_text` |
| Tags | `collection-integrity`, `relocated-tree` |

A shell profile, or the environment an agent ran in, exports a variable the catalogue records as changing where that agent keeps its data, whether it keeps it, or what it obeys. What was collected from the default paths is therefore not necessarily what that agent wrote, and not necessarily all of what it was told.

*What it matches:* `event_text matches /\b(AMP_DISABLE_AMP_COAUTHOR_TRAILER\|AMP_DISABLE_AMP_THREAD_TRAILER\|AMP_SKIP_UPDATE_CHECK\|ANTHROPIC_CONFIG_DIR\|CLAUDE_CODE_DEBUG_LOGS_DIR\|CLAUDE_CODE_PLUGIN_CACHE_DIR\|CLAUDE_CODE_PROJECT_DIR_NAME\|CLAUDE_CODE_SKIP_PROMPT_HISTORY\|CLAUDE_CONFIG_DIR\|CLAUDE_DESKTOP_ADD_REPO\|CLAUDE_PLUGIN_ROOT\|CLINE_CONNECTORS_DB_PATH\|CLINE_CONNECTOR_DATA_DIR\|CLINE_CONNECTOR_SETTINGS_PATH\|CLINE_CRON_DB_PATH\|CLINE_DATA_DIR\|CLINE_DB_DATA_DIR\|CLINE_DIR\|CLINE_GLOBAL_SETTINGS_PATH\|CLINE_HOOKS_LOG_PATH\|CLINE_MCP_SETTINGS_PATH\|CLINE_PROVIDER_SETTINGS_PATH\|CLINE_SESSION_DATA_DIR\|CLINE_TASKS_DB_PATH\|CLINE_TEAM_DATA_DIR\|CODEX_HOME\|CODEX_SQLITE_HOME\|CONTEXT_FILE_NAMES\|CONTINUE_GLOBAL_DIR\|COPILOT_CACHE_HOME\|COPILOT_HOME\|COPILOT_PROVIDERS_CONFIG\|CURSOR_CONFIG_DIR\|CURSOR_DATA_DIR\|CURSOR_SANDBOX_POLICY_DIR\|CURSOR_TRANSCRIPT_PATH\|FLATPAK_XDG_CONFIG_HOME\|FLATPAK_XDG_DATA_HOME\|FLATPAK_XDG_STATE_HOME\|GEMINI_CLI_HOME\|GEMINI_CLI_SYSTEM_DEFAULTS_PATH\|GEMINI_CLI_SYSTEM_SETTINGS_PATH\|GEMINI_CLI_TRUSTED_FOLDERS_PATH\|GEMINI_SYSTEM_MD\|GOOSE_DISABLE_KEYRING\|GOOSE_MOIM_MESSAGE_FILE\|GOOSE_MOIM_MESSAGE_TEXT\|GOOSE_PATH_ROOT\|GOOSE_RECIPE_GITHUB_REPO\|GOOSE_RECIPE_PATH\|HERMES_HOME\|KILO_CONFIG_CONTENT\|KILO_DB\|KIRO_ACP_RECORD_PATH\|KIRO_API_KEY\|KIRO_CHAT_LOG_FILE\|KIRO_HOME\|KIRO_LOG_LEVEL\|KIRO_LOG_NO_COLOR\|OLLAMA_MODELS\|OPENCODE_CONFIG\|OPENCODE_CONFIG_CONTENT\|OPENCODE_CONFIG_DIR\|OPENCODE_DB\|OPENCODE_DISABLE_CHANNEL_DB\|OPENCODE_MODELS_PATH\|OPENCODE_PLUGIN_META_FILE\|OPENCODE_TEST_HOME\|OPENCODE_TUI_CONFIG\|PI_CODING_AGENT_DIR\|PI_CODING_AGENT_SESSION_DIR\|QWEN_CODE_FORCE_ENCRYPTED_FILE_STORAGE\|QWEN_CODE_MCP_APPROVALS_PATH\|QWEN_CODE_MEMORY_BASE_DIR\|QWEN_CODE_MEMORY_LOCAL\|QWEN_CODE_MEMORY_PROJECT_SCOPE\|QWEN_CODE_PROFILE_STARTUP\|QWEN_CODE_SYSTEM_DEFAULTS_PATH\|QWEN_CODE_SYSTEM_SETTINGS_PATH\|QWEN_DEBUG_LOG_FILE\|QWEN_HOME\|QWEN_RUNTIME_DIR\|QWEN_SANDBOX\|QWEN_SANDBOX_IMAGE\|QWEN_SANDBOX_NET\|QWEN_TELEMETRY_OUTFILE\|Q_CLI_DATA_DIR\|Q_DISABLE_TELEMETRY\|Q_LOG_LEVEL\|Q_LOG_STDOUT\|Q_ZDOTDIR\|SANDBOX\|SEATBELT_PROFILE\|VSCODE_EXTENSIONS\|VSCODE_PORTABLE\|WINDSURF_CONFIG_DIR)[^\S\n]*[=:][^\S\n]*\S/`

*Why an analyst cares:* This rule is about the case rather than about the endpoint, which is why it exists at all. Every other finding says something happened; this one says a part of the collection may be answering the wrong question. An agent whose home was moved leaves nothing at the path a collection searched, and nothing found there reads exactly like an agent that was never used. A few of these variables carry the instructions themselves rather than a path, in which case there is nothing further to collect and what the agent was told every turn exists only in the environment of the run. The variable is usually set for an ordinary reason, so this is not a suspicion about anybody: it is an instruction to go back for what the variable names before concluding anything from an empty result.

*Known false positives:*

- A variable set to the location the agent uses anyway, which changes nothing and is common in a profile that spells out a default.
- A mention in a configuration file or a script that explains the variable rather than setting it, since the rule searches the text a record holds. A question about the variable in a conversation is out of scope by kind and cannot reach this rule.
- A variable that was exported after the period under investigation, since a profile says what is in force and not when a line was added to it.

*References:*

- <https://code.claude.com/docs/en/troubleshoot-install.md>

*Samples in the rule file:* 2 / 2 (+/-)

#### AFX-COLLECTIONINTEGRITY-002

**An agent tidied its own data, and left the date it did it**

| | |
| --- | --- |
| Severity | info |
| Pack | `collection_integrity` |
| Agents | `any` |
| Event kinds | `artifact.fs` |
| Fields read | `payload.path` |
| Tags | `collection-integrity`, `retention`, `vendor-cleanup` |

A file whose own name carries a date, written by an agent's cleanup rather than by a user. Material older than that date may be gone because the product removed it.

*What it matches:* `payload.path matches /[\\/]\.agent-data-cleanup-\d{4}-\d{2}-\d{2}$/`

*Why an analyst cares:* This rule is about the case rather than about the endpoint. An analyst who finds a transcript directory thinner than the conversation it describes has two readings in front of them, and they lead to opposite conclusions: somebody removed material, or the product removed it by itself on a schedule nobody chose. This marker settles that question for one date, so it fires at the lowest severity there is and its whole job is to be in the timeline before an absence is reported as a deletion. . Read it as a bound and not as an inventory. It says a cleanup ran on that date. It does not say what was removed, because nobody has read the rules the cleanup follows, and an empty marker file cannot say. More than one of these means more than one cleanup, and the set of dates is the schedule. . First hand: measured on a clean Windows 11 26200 host and a clean macOS 26.5 host, on a fresh installation with one trivial conversation each. Both wrote the marker.

*Known false positives:*

- A file somebody created by hand with that name, which would be an odd thing to do but is not prevented by anything.
- A marker restored from a backup onto a host that never ran the cleanup, which would date an event that happened elsewhere.

*Samples in the rule file:* 2 / 2 (+/-)

#### AFX-COLLECTIONINTEGRITY-003

**A URL handler says an agent product was installed on this account**

| | |
| --- | --- |
| Severity | low |
| Pack | `collection_integrity` |
| Agents | `any` |
| Event kinds | `config.snapshot` |
| Fields read | `payload.key`, `payload.text` |
| Tags | `collection-integrity`, `install-evidence`, `survives-uninstall` |

A URL protocol handler registered under the user's own class keys names an agent product's executable. The key is written by the installer and removed by no uninstaller, so it outlives the product it belongs to.

*What it matches:* `payload.key matches /(?i)\\Software\\Classes\\(cursor\|devin\|windsurf)(\\\|$)/ and payload.text matches /(?i)\.exe/`

*Why an analyst cares:* This rule is about the case rather than about the endpoint, and it exists because of what is on the other side of it. Measured on a clean Windows 11 26200 host: two agent products were installed, used once, and uninstalled through their own uninstallers. The uninstall keys were gone afterwards and these handlers were not, with their command values still naming executables that had been deleted. . So the finding is an instruction rather than an accusation. Compare the path in the command value against the filesystem. If the executable is there, the product is installed and its data should be in this collection; if it is not, the product was installed on this account and later removed, and this key is telling you where it was and that its data may still be on the disk, because an uninstall of these products removes the program and none of the content. . Read the scheme name rather than the product name. One of the two products registers three schemes, one of them under the name it had before it was renamed, and all of them point at the current executable. A key under the old name is therefore not evidence that the old product was ever installed, and a search for the current name finds a third of what that product registered.

*Known false positives:*

- An ordinary installed product. This rule fires on every host where one of these editors is installed, which is why it is low rather than higher: the finding is worth a look at the path, not an escalation.
- A handler registered by something else that happens to use one of these scheme names, which nothing on Windows prevents.
- A scheme key restored from a backup or roamed from another machine with the profile.

*Samples in the rule file:* 2 / 3 (+/-)

#### AFX-COLLECTIONINTEGRITY-004

**One folder was open in more than one agent product**

| | |
| --- | --- |
| Severity | low |
| Pack | `collection_integrity` |
| Agents | `any` |
| Event kinds | `config.snapshot` |
| Fields read | `project_path` |
| Tags | `collection-integrity`, `cross-product`, `scoping` |

The same project folder appears in the per-workspace state of two or more different agent products. Whatever one product's transcripts say about that folder is not the whole of what was done in it.

*What it matches:* `project_path is present`

*Fires on a count rather than on one event, grouped by* `project_path`, n >= 2.

*Why an analyst cares:* This rule is about the case rather than about the endpoint, and what it corrects is a scoping mistake rather than a technical one. An examination that found one agent's conversations about a repository and answered from them has answered about one of the products that worked on it. The other one's transcripts live in a different tree, under a different product name, and on the measured hosts in a different store format, so nothing in the first product's data points at them. . It is worth a rule rather than a note because the endpoint makes the connection hard to see. Measured on a clean Windows 11 26200 host and a clean macOS 26.5 host: two editors derived from the same one keep their per-workspace state in a directory whose name is not a digest of the folder path, so nobody can compute it, and the same folder produces the same opaque name in both products. The only thing that undoes the name is a small file beside each store, and it is that file this rule's field comes from. . Read it as an instruction to widen the collection, not as suspicion. Two agent products on one machine is ordinary. What is not ordinary is reporting on one of them as though it were all of them.

*Known false positives:*

- A developer who simply uses two editors. That is the common case and the reason this is low rather than higher: the finding is a reason to collect the second product's data, not a reason to suspect anybody.
- One product migrated from another and carried the workspace state over. The renamed product in this catalogue does exactly that, so a folder can appear under both its names without anybody having used the older one.
- A folder path that two products resolved differently, for example one through a symbolic link and one not. Those group as different folders and this rule will miss the pair rather than invent one, which is the right way round.

*Samples in the rule file:* 2 / 1 (+/-)

#### AFX-COLLECTIONINTEGRITY-005

**A hook that looks like it applied to every tool call applied to none**

| | |
| --- | --- |
| Severity | low |
| Pack | `collection_integrity` |
| Agents | `any` |
| Event kinds | `config.snapshot`, `unparsed.record` |
| Fields read | `event_text`, `provenance.artifact_id`, `agent` |
| Tags | `collection-integrity`, `hooks`, `silently-skipped` |

A hook rule in one product's plugin tree carries a matcher of a bare asterisk. In this product the matcher is a regular expression and not a glob, and the vendor states that a bare "*" is an invalid expression, so the whole rule is skipped: the product logs a warning and moves on. The expression that does match everything there is ".*". The rule reads only that one spelling, because a rule file is data and cannot evaluate an expression to decide whether it compiles.

*What it matches:* `event_text matches /"?\bmatcher\b"?[^\S\n]*[:=][^\S\n]*"?\*"?,?[^\S\n]*(?=\n\|\Z)/ and (provenance.artifact_id is 'goose.hooks' or agent is 'goose')`

*Why an analyst cares:* The pack is the argument here, so it is worth making. This finding is not about conduct on the endpoint: nothing ran, nothing was blocked, nobody turned a control off. It is about the reading of a file the case already holds, and it corrects that reading in both directions at once. A hooks file is otherwise read twice over. The supply chain pack reports the command a hook runs, which for this rule never ran. And a PreToolUse rule that denies is the explanation an analyst reaches for when a transcript shows a tool call that did not happen, which for this rule cannot be the explanation. So a hook written this way turns into a control that was in force and a reason a call was refused, and it was neither. That is a part of the collection answering a different question than the one it looks like it answered, which is what this pack is for. . It is also a pointer at the one artifact that dates the mistake. The vendor documents the skip as a warning in the product's log, and this catalogue collects those logs, so how often the rule was skipped and when is there rather than in the hooks file, which says only what was configured. . Low, because on its own it says that nothing happened. What makes it worth reporting at all is that the absence it explains is one somebody would otherwise explain wrongly.

*Known false positives:*

- A hook that was meant to be narrow and got its expression wrong, which is the same file on disk and is a mistake rather than a misleading record. The finding is the same either way: this rule did not run.
- A newer version of the product that accepts the expression. The rule reports what the vendor documents today, and a file says what was configured rather than which build read it.
- The value quoted in a plugin's own documentation or in an example that happens to be filed as configuration, since the text a record holds is what is searched.
- The mirror image, which is a miss rather than a false positive and belongs here so it is not discovered by surprise: an invalid expression spelled any other way, and a hooks file the case could not attribute to this product, are both outside what this rule claims.

*References:*

- <https://raw.githubusercontent.com/block/goose/main/documentation/docs/guides/context-engineering/hooks.md>

*Samples in the rule file:* 2 / 3 (+/-)

#### AFX-COLLECTIONINTEGRITY-006

**A head-to-head run left a copy of uncommitted work outside the repository**

| | |
| --- | --- |
| Severity | medium |
| Pack | `collection_integrity` |
| Agents | `any` |
| Event kinds | `artifact.fs` |
| Fields read | `payload.path` |
| Tags | `collection-integrity`, `uncommitted-work`, `multi-provider` |

A collected file sits inside one product's head-to-head worktree tree, under ~/.qwen/arena/<session-id>/worktrees/<model-name>/. The vendor states that each competing agent gets its own git worktree mirroring the working directory exactly, including staged changes, unstaged changes and untracked files, and that selecting a winner applies that agent's diff and then cleans up every worktree automatically.

*What it matches:* `payload.path matches path **/.qwen/arena/*/worktrees/*/**`

*Why an analyst cares:* Three things follow from a tree that is still there, and each of them changes where an examination looks rather than saying somebody did something wrong. . It is a copy of somebody's working directory outside the repository. Untracked files are in it by the vendor's own description, so a file that was never committed and later deleted, or a change that was never staged, can survive here and nowhere else. A tree that is present is also a run that was abandoned, crashed or is still going, because a finished run deletes its worktrees: this is material the product intended to remove. . One task went to several providers at once. Each directory under worktrees is a different model, and all of them were given the same task and the same repository content, so the answer to which providers received this work is the list of those directory names rather than the one model a settings file names. . And the sessions are filed somewhere an analyst will not look. This is an inference rather than a vendor statement, and the catalogue entry says so: each competing agent is a full session whose working directory is its worktree, and this product keys its transcript tree by working directory, so those conversations are expected under a project directory carrying the worktree path rather than the repository. Check that before reporting a session as missing. . Two limits worth stating. The absence of any such tree says nothing at all, because the product deletes them on a win. And the base directory moves: the agents.arena worktreeBaseDir setting replaces it with any absolute path, the vendor states a leading tilde is not expanded there, and a relocated tree is outside what this rule can see, so the settings file is what has to be read before an empty result is believed. . It reports once per collected file rather than once per tree. That is deliberate: the only thing a worktree is guaranteed to hold is its files, and a pattern narrowed to the top of the tree would go blind on the first layout that nests. The count is the size of the copy and the model directories in the findings are the providers.

*Known false positives:*

- A run that is still going, which is the feature working as documented. The tree is a copy of uncommitted work either way, so the finding is true and the reading is different: check the timestamps against the session times before calling it abandoned.
- A tree left by a crash rather than by anybody's choice, which is the most likely cause and is not misconduct. What the finding asserts is that the copy exists, not how it came to.
- A directory somebody created by hand at that path, or a copy of one restored from a backup onto a machine where the feature was never used, which would put a run on the timeline of the wrong host.
- A worktree of a repository that holds nothing sensitive and nothing uncommitted, where the copy is a duplicate of what the repository already has. The finding is the same shape and the analyst's next step is what differs.

*References:*

- <https://github.com/QwenLM/qwen-code/blob/main/docs/users/features/arena.md>

*Samples in the rule file:* 2 / 3 (+/-)

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
| Fields read | `payload.commands[].command`, `parse_problem`, `event_text` |
| Tags | `T1059`, `T1105`, `remote-code-execution` |

The agent fetched something from the network and piped it into a shell or an interpreter in one command, the curl or wget into sh pattern and its PowerShell equivalent.

*What it matches:* `(payload.commands[].command matches /(?:curl\|wget\|Invoke-WebRequest\|iwr\|Invoke-RestMethod)\b[^\|]*\\|\s*(?:sudo\s+)?(?:ba\|z\|d\|k)?sh\b/ or payload.commands[].command matches /(?:curl\|wget)\b[^\|]*\\|\s*(?:sudo\s+)?(?:python[23]?\|perl\|ruby\|node)\b/ or payload.commands[].command matches /(?i)(?:iwr\|Invoke-WebRequest\|Invoke-RestMethod)\b[^\|]*\\|\s*(?:iex\|Invoke-Expression)\b/ or parse_problem contains 'is returned uninterpreted' and event_text matches /(?:curl\|wget\|Invoke-WebRequest\|iwr\|Invoke-RestMethod)\b[^\|\n]*\\|[^\S\n]*(?:sudo[^\S\n]+)?(?:ba\|z\|d\|k)?sh\b/)`

*Why an analyst cares:* This is remote code execution the agent chose to perform, and the code it ran is not in the transcript: only the address it came from is. So the finding is both the action and the limit of what can be known about it, which is why the address matters more here than in most findings. It is also the shape a prompt injection most often asks an agent to produce, which makes the surrounding conversation worth reading.

*Known false positives:*

- A documented installer. Several widely used tools publish exactly this command as their installation instruction, so the pattern is common in legitimate setup work.
- A line in a Dockerfile or a CI script the agent was reading or writing rather than running, which reaches the command facet only if the agent also executed it.
- In a record nobody has mapped, a command the conversation only talked about. Nothing in such a record says whether the text is a command that ran, a command that was proposed or a command somebody quoted, which is why the finding says the kind of the record has not been established.

*Samples in the rule file:* 3 / 3 (+/-)

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

#### AFX-EXFILINDICATORS-004

**A command uploaded a local file to a remote destination**

| | |
| --- | --- |
| Severity | high |
| Pack | `exfil_indicators` |
| Agents | `any` |
| Event kinds | `command.exec`, `tool.call` |
| Fields read | `event_text` |
| Tags | `T1567`, `T1048`, `exfiltration` |

A command line sends a file off the machine by name: curl with an upload flag or a file form field, scp or rsync to a host, a cloud storage copy to a bucket, or a sync tool copying to a configured remote.

*What it matches:* `(event_text matches /(?i)\bcurl\b[^\n]*(?:\s-T\s\|\s--upload-file\s\|\s-F\s+[^\n]*@)/ or event_text matches /(?i)\bwget\b[^\n]*\s--post-file[=\s]/ or event_text matches /(?i)\bscp\b[^\n]*\s[A-Za-z0-9._-]+@[A-Za-z0-9._-]+:/ or event_text matches /(?i)\brsync\b[^\n]*\s[A-Za-z0-9._-]+@[A-Za-z0-9._-]+:/ or event_text matches /(?i)\baws\s+s3\s+(?:cp\|sync\|mv)\b[^\n]*\ss3:/// or event_text matches /(?i)\bgsutil\s+(?:cp\|rsync)\b[^\n]*\sgs:/// or event_text matches /(?i)\baz\s+storage\s+blob\s+upload\b/ or event_text matches /(?i)\brclone\s+(?:copy\|sync\|move\|copyto)\b/)`

*Why an analyst cares:* The other rules in this pack are about the shapes that hide an upload: a paste site, an encoding step, a git remote added moments earlier. This one is the plain case, and it was missing. It is also the one an agent produces most readily, because uploading a file is a reasonable thing to ask for and the command for it is one line. What makes it a finding rather than a note is that the file is named on the line. An analyst reading it knows which data left, which is the question this whole pack exists for, and can say so without reconstructing anything.

*Known false positives:*

- A deployment, a backup or a release step, which is what most of these commands are for. The finding says a file left the device, not that it should not have.
- A command the agent wrote into a script rather than ran. A line in a file the agent was editing reaches this rule through the record that quotes it, and the kind of that record is what tells the two apart.
- A sync tool's remote that is another directory on the same machine, which is a configured destination this rule cannot resolve from the command line alone.

*Samples in the rule file:* 3 / 2 (+/-)

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

A command line starts an agent with the flag that skips permission prompts, or with the permission mode that does the same. For Claude Code these are --dangerously-skip-permissions and --permission-mode bypassPermissions, which the vendor documents as equivalent. Cursor's command line product spells it --force, documented as allowing direct file changes without confirmation, with --yolo as its documented alternative spelling.

*What it matches:* `(event_text matches /--dangerously-skip-permissions/ or event_text matches /--permission-mode[= ]+bypassPermissions/ or event_text matches /(?m)\bcursor-agent\b[^\n]*[^\S\n]--force\b/ or event_text matches /(?m)(?:^\|[^\S\n])--yolo\b/)`

*Why an analyst cares:* This is the single clearest answer to the question whether safety controls were bypassed, because it is not a control that failed, it is a control somebody turned off and had to type a word like dangerously to turn off. In this mode the agent writes without asking, including to the paths the vendor protects by default such as the repository's own git directory and the agent's own configuration, so anything found afterwards has to be read knowing that nobody was asked.

*Known false positives:*

- A deliberate use inside a container or a virtual machine, which is what the vendor documentation recommends the mode for. The finding is still correct; whether it was appropriate depends on where the agent was running.
- Documentation, a README or a script that mentions the flag without running it, which matches because the text is what is on disk.

*References:*

- <https://code.claude.com/docs/en/cli-reference>
- <https://code.claude.com/docs/en/permissions>
- <https://cursor.com/docs/cli/headless>

*Samples in the rule file:* 4 / 3 (+/-)

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
| Fields read | `payload.permissions[].subject`, `event_text` |
| Tags | `T1562.001`, `permission-bypass` |

A configuration snapshot holds an allow entry that is a bare tool name. The vendor documents a bare name as matching every call of that tool, so an entry of Bash allows every shell command, Read every file read and WebFetch every outbound request.

*What it matches:* `(payload.permissions[].subject is 'Bash' or 'Read' or 'Write' or 'Edit' or 'MultiEdit' or 'WebFetch' or 'WebSearch' or 'NotebookEdit' or event_text matches /(?m)^[^\S\n]*(?:Bash\|Read\|Write\|Edit\|MultiEdit\|WebFetch\|WebSearch\|NotebookEdit)\(\*\)[^\S\n]*$/)`

*Why an analyst cares:* This is the quiet version of a bypass. Nobody typed a dangerous-looking flag and no mode changed; a line in a settings file means the prompt for a whole class of action never appears again, in every session, for as long as the file says so. An analyst reading a transcript with no permission prompts in it needs to know whether that is because nothing needed approving or because a rule had already approved it.

*Known false positives:*

- A bare Read entry is close to harmless on its own, because reads inside the working directory need no approval anyway.
- A project that has deliberately allowed a tool and constrained it another way, for example with a deny rule or a pre-tool hook, which the vendor documents as taking precedence over an allow rule.

*References:*

- <https://code.claude.com/docs/en/permissions>

*Samples in the rule file:* 3 / 3 (+/-)

#### AFX-PERMISSIONBYPASS-004

**An instruction document granted itself the right to run commands**

| | |
| --- | --- |
| Severity | medium |
| Pack | `permission_bypass` |
| Agents | `any` |
| Event kinds | `instruction.source` |
| Fields read | `payload.declared_tools[]` |
| Tags | `permission-bypass`, `T1059`, `supply-chain` |

A skill, command, workflow or agent definition on the endpoint declares the tools it may use in its own front matter, and the declared set includes command execution or a wildcard. The vendors spell this key allowed-tools, allowedTools, tools or permissions depending on the product; the parser lifts whichever is present onto the event.

*What it matches:* `(payload.declared_tools[] matches /(?i)^(bash\|shell\|sh\|zsh\|powershell\|cmd\|terminal)\b/ or /(?i)^(execute\|exec\|run)(_\|-)?(command\|shell\|bash\|script)?$/ or /(?i)^(kill)(_\|-)?(bash\|shell)$/ or payload.declared_tools[] is '*' or 'all' or 'any' or 'Bash(*)' or '*:*')`

*Why an analyst cares:* This is a permission change written as a document rather than as a setting, which is why it is easy to miss: an analyst checking what the agent was allowed to do reads the settings files, and a skill that grants itself a shell is not in them. It also travels. A skill file arrives with a checkout or with an installed plugin, so whoever could write to that repository or publish that plugin decided what the agent may run, and the person operating the agent was never asked.

*Known false positives:*

- A deploy or build skill the team wrote on purpose, which needs a shell to do its job and declares it honestly. This is the common case, which is why the rule is medium: the finding says a document holds the grant, not that the grant is wrong.
- A skill shipped by the vendor's own marketplace, where the grant was reviewed by whoever published it rather than by the user.

*Samples in the rule file:* 3 / 3 (+/-)

#### AFX-PERMISSIONBYPASS-005

**A configuration starts every session in a mode that approves its own tool calls**

| | |
| --- | --- |
| Severity | high |
| Pack | `permission_bypass` |
| Agents | `any` |
| Event kinds | `config.snapshot` |
| Fields read | `raw.permissions.defaultMode`, `raw.defaultMode`, `payload.defaultMode`, `event_text`, `raw.approvalMode`, `payload.approvalMode`, `raw.approval_policy` |
| Tags | `T1562.001`, `permission-bypass` |

A configuration sets the mode a session starts in to one that approves tool calls without asking. Claude Code spells this defaultMode bypassPermissions in its settings files, Cline calls the equivalent mode yolo, which its own preset code describes as guaranteeing that tool policies are enabled and auto-approved, Codex spells it approval_policy = never, which its vendor names as one of the two settings an organization forbids through its managed requirements file, and Warp's command line agent sets a per-action value to always_allow in the execution profile in its settings file.

*What it matches:* `(raw.permissions.defaultMode is 'bypassPermissions' or raw.defaultMode is 'bypassPermissions' or payload.defaultMode is 'bypassPermissions' or event_text matches /(?m)^[^\S\n]*defaultMode[^\S\n]*=[^\S\n]*bypassPermissions[^\S\n]*$/ or event_text matches /(?m)^[^\S\n]*mode[^\S\n]*=[^\S\n]*yolo[^\S\n]*$/ or raw.approvalMode is 'unrestricted' or payload.approvalMode is 'unrestricted' or event_text matches /(?m)^[^\S\n]*approvalMode[^\S\n]*=[^\S\n]*unrestricted[^\S\n]*$/ or raw.approval_policy is 'never' or event_text matches /(?m)^[^\S\n]*approval_policy[^\S\n]*=[^\S\n]*never[^\S\n]*$/ or event_text matches /(?m)^[^\S\n]*(?:execute_commands\|apply_code_diffs)[^\S\n]*=[^\S\n]*always_allow[^\S\n]*$/)`

*Why an analyst cares:* The two rules beside this one find a bypass somebody typed: a flag on a command line, or a mode changed part way through a session. This one is the version that needs typing once. A line in a settings file or in a schedule the agent wrote for itself means every session from then on starts with the prompt already answered, including the sessions nobody is present for. It also explains an absence twice over. A transcript with no approvals in it reads differently once this is known, and for Cline it removes evidence rather than only approvals: the vendor's own hook documentation states that hooks are disabled in yolo mode, and the hook log is the artifact that dates this agent's prompts. So a scheduled run in yolo mode approves everything and writes no audit line about any of it, and the vendor's cron documentation lists yolo as the default mode for a scheduled run.

*Known false positives:*

- A machine that exists to run an agent unattended, in a container or a disposable virtual machine, which is what the vendors recommend these modes for. The finding is still correct: it says approvals were not asked for, not that asking was required.
- A document that records the mode of a past run rather than setting it for future ones. Both are the same line in the same shape, and which one it is depends on the file, which is why the finding names the file it came from.

*References:*

- <https://code.claude.com/docs/en/permissions>
- <https://docs.warp.dev/agents/cli/permissions-and-profiles/>
- <https://cursor.com/docs/cli/reference/configuration>
- <https://raw.githubusercontent.com/cline/cline/main/sdk/packages/core/src/extensions/tools/presets.ts>
- <https://raw.githubusercontent.com/cline/cline/main/sdk/examples/hooks/README.md>
- <https://raw.githubusercontent.com/cline/cline/main/sdk/examples/cron/README.md>
- <https://developers.openai.com/codex/config-basic>

*Samples in the rule file:* 6 / 7 (+/-)

#### AFX-PERMISSIONBYPASS-006

**A configuration starts every session in a mode that edits files without asking**

| | |
| --- | --- |
| Severity | medium |
| Pack | `permission_bypass` |
| Agents | `any` |
| Event kinds | `config.snapshot` |
| Fields read | `raw.permissions.defaultMode`, `raw.defaultMode`, `payload.defaultMode`, `event_text` |
| Tags | `T1562.001`, `permission-bypass` |

A configuration sets the mode a session starts in to acceptEdits, which the vendor documents as automatically accepting file edits and common filesystem commands such as mkdir, touch, mv and cp inside the working directory, or to auto, which auto-approves tool calls subject to a background classifier.

*What it matches:* `(raw.permissions.defaultMode is 'acceptEdits' or 'auto' or raw.defaultMode is 'acceptEdits' or 'auto' or payload.defaultMode is 'acceptEdits' or 'auto' or event_text matches /(?m)^[^\S\n]*defaultMode[^\S\n]*=[^\S\n]*(?:acceptEdits\|auto)[^\S\n]*$/)`

*Why an analyst cares:* This is the weaker half of the setting the rule before it covers, and it is worth its own finding for one reason: it is the ordinary answer to "why are there no approvals in this transcript". An analyst who does not know the mode reads a session full of file writes with nothing asking about them and has to decide whether the prompts were answered, never shown, or removed. The mode says which, and it says it for every session on the endpoint rather than for the one being read. It stays at medium because it is a setting people turn on to get work done and because what it approves is bounded: the vendor documents it as edits and common filesystem commands inside the working directory, not as every tool call. A high severity here would teach an analyst to skip the pack.

*Known false positives:*

- A developer who turned it on deliberately for their own repository, which is most uses of it. The finding is context for reading the transcripts rather than a mistake on its own.
- A document that records the mode a past session ran in rather than setting the mode for future ones. The finding names the file, which is what tells the two apart.

*References:*

- <https://code.claude.com/docs/en/permissions>

*Samples in the rule file:* 2 / 2 (+/-)

#### AFX-PERMISSIONBYPASS-007

**A configuration turned the sandbox off for every session**

| | |
| --- | --- |
| Severity | high |
| Pack | `permission_bypass` |
| Agents | `any` |
| Event kinds | `config.snapshot` |
| Fields read | `raw.sandbox_mode`, `payload.sandbox_mode`, `event_text` |
| Tags | `T1562.001`, `permission-bypass` |

A configuration disables the sandbox the agent otherwise runs its commands in. Codex spells this sandbox_mode = danger-full-access, with a built-in permission profile of the same name, and its own documentation introduces it as disabling sandboxing entirely and names it as one of the two settings an organization forbids through its managed requirements file.

*What it matches:* `(raw.sandbox_mode is 'danger-full-access' or payload.sandbox_mode is 'danger-full-access' or event_text matches /(?m)^[^\S\n]*sandbox_mode[^\S\n]*=[^\S\n]*danger-full-access[^\S\n]*$/ or event_text matches /(?m)^[^\S\n]*default_permissions[^\S\n]*=[^\S\n]*:?danger-full-access[^\S\n]*$/)`

*Why an analyst cares:* This is the other half of the question the rest of this pack answers. The approval settings decide whether anybody was asked; this one decides what the agent could reach once it went ahead. With the sandbox on, the vendor keeps a workspace writable and the repository's own git directory and the agent's configuration directory read-only, and outbound network access is off unless it is switched on. With it off, none of that holds, so a command in a transcript could have written anywhere on the disk and could have reached the network whatever the transcript shows. It matters most where an analyst would otherwise reason from the defaults. A report that says the agent could not have touched a path because the vendor protects it is wrong on this endpoint, and nothing in the transcript says so.

*Known false positives:*

- A container or a disposable virtual machine, which is what the vendor documents the setting for: it says to use it only where the environment already isolates processes. The finding is still correct, and whether it was appropriate depends on where the agent was running.
- A document that records the setting of a past run rather than setting it for future ones. The finding names the file it came from, which is what tells the two apart.

*References:*

- <https://developers.openai.com/codex/config-basic>
- <https://developers.openai.com/codex/config-advanced>

*Samples in the rule file:* 2 / 2 (+/-)

#### AFX-PERMISSIONBYPASS-008

**The sandbox the agent runs commands in was allowed to reach the network**

| | |
| --- | --- |
| Severity | medium |
| Pack | `permission_bypass` |
| Agents | `any` |
| Event kinds | `config.snapshot` |
| Fields read | `raw.sandbox_workspace_write.network_access`, `payload.sandbox_workspace_write.network_access`, `event_text` |
| Tags | `T1562.001`, `permission-bypass`, `egress` |

A configuration turns on outbound network access for the sandbox the agent's commands run in. Codex spells this network_access under its workspace-write sandbox table, and its own documentation carries the setting with the comment that it is an opt in.

*What it matches:* `(raw.sandbox_workspace_write.network_access is 'true' or payload.sandbox_workspace_write.network_access is 'true' or event_text matches /(?mi)^[^\S\n]*network_access[^\S\n]*=[^\S\n]*true[^\S\n]*$/)`

*Why an analyst cares:* The rule before this one finds the sandbox switched off entirely. This is the narrower change that is far more common and much easier to miss: the sandbox stays on, the filesystem limits still apply, and the one thing that was off by default is now on. It matters for the question this suite exists to answer about data leaving a device. With the sandbox's network off, a command the agent ran could not reach anything, whatever the command says, so a curl in a transcript is an attempt rather than a transfer. With it on, the same line has to be read as a transfer. Nothing in the transcript distinguishes the two cases, and no other artifact records it.

*Known false positives:*

- Ordinary development, where an agent has to install dependencies or call an API to do what it was asked. This is a documented setting people turn on for good reasons, and the finding is context for reading the commands rather than a mistake on its own.
- A configuration recording a past run rather than setting a future one. The finding names the file, which is what tells the two apart.

*References:*

- <https://developers.openai.com/codex/config-advanced>

*Samples in the rule file:* 1 / 2 (+/-)

#### AFX-PERMISSIONBYPASS-009

**A managed policy sits in a hive a non-administrator can write**

| | |
| --- | --- |
| Severity | high |
| Pack | `permission_bypass` |
| Agents | `any` |
| Event kinds | `config.snapshot` |
| Fields read | `raw.hive`, `raw.key` |
| Tags | `T1112`, `policy-in-user-hive` |

A managed policy for an agent was found under the current user's registry hive rather than under the machine's. The user hive needs no administrative rights, so a policy there was not necessarily set by whoever administers this machine.

*What it matches:* `raw.hive is 'user' and raw.key matches /(?i)\\Policies\\/`

*Why an analyst cares:* The managed settings of one of these products are documented as being read from both hives, and the vendor's own guidance is to check both and compare. That is the whole finding. An organisation that deploys a policy deploys it to the machine hive, which needs rights an ordinary account does not have. A policy in the user hive is one the account under investigation could have written, and if the machine hive holds no policy at all then what looks like a corporate control is a setting the user chose for themselves. It is the registry's version of a project-level settings file overriding what an administrator meant to enforce, and unlike a file it leaves nothing in a working copy for anybody to notice.

*Known false positives:*

- A machine administered per user, or a test deployment, where a policy in the user hive is deliberate. The finding says who could have written it, not who did.
- An account that is itself an administrator, where the distinction between the two hives says nothing about rights. Whether the account was elevated is in the manifest of the collection rather than in this event.
- A policy present in both hives with the same content, which is what a deployment that writes both looks like.

*References:*

- <https://code.claude.com/docs/en/settings>

*Samples in the rule file:* 1 / 3 (+/-)

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
| Event kinds | `tool.result`, `mcp.call`, `network.request`, `file.read`, `user.prompt`, `config.snapshot`, `instruction.source`, `memory.write` |
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

*Samples in the rule file:* 4 / 2 (+/-)

#### AFX-PROMPTINJECTION-003

**A project instruction file arrived with the work rather than with the project**

| | |
| --- | --- |
| Severity | medium |
| Pack | `prompt_injection` |
| Agents | `any` |
| Event kinds | `file.write`, `file.read`, `config.snapshot`, `memory.write`, `instruction.source` |
| Fields read | `kind`, `payload.files[].path`, `payload.instructions[].scope` |
| Tags | `prompt-injection`, `T1547`, `persistence` |

An instruction file was written or changed during the session, or one was read from a path outside the working directory the agent reported. Instruction files are the ones an agent loads and obeys: CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules, .windsurfrules, the files under .cursor/rules and .github/instructions, and an MCP configuration.

*What it matches:* `(kind is 'file.write' or 'memory.write' and payload.files[].path matches path **/CLAUDE.md or **/CLAUDE.local.md or **/AGENTS.md or **/GEMINI.md or **/.cursorrules or **/.windsurfrules or **/.cursor/rules/** or **/.github/copilot-instructions.md or **/.github/instructions/** or **/.kiro/steering/** or **/.mcp.json or **/mcp.json or **/claude_desktop_config.json or payload.instructions[].scope is 'project' or 'local')`

*Why an analyst cares:* These files are instructions to the agent that no user has to type and that persist into every later session. A repository that was cloned with one already in it has effectively shipped instructions to whoever opens it next, and one written mid-session has changed the rules the rest of the session ran under. Either way the question an analyst needs settled is whether the agent's instructions came from the person operating it.

*Known false positives:*

- A developer asking the agent to write or update the project's own instruction file, which is a normal and recommended thing to do and produces exactly this event.
- A project whose instruction file has been in version control for months, where the finding says only that it was in effect.

*Samples in the rule file:* 4 / 3 (+/-)

#### AFX-PROMPTINJECTION-004

**An instruction that overrides the agent's behaviour is stored in its memory**

| | |
| --- | --- |
| Severity | high |
| Pack | `prompt_injection` |
| Agents | `any` |
| Event kinds | `memory.write` |
| Fields read | `event_text` |
| Tags | `prompt-injection`, `T1204`, `persistence` |

A memory the agent wrote for itself carries the language of an instruction rather than of a note: ignore the previous instructions, from now on you, do not tell the user, act without asking.

*What it matches:* `(event_text matches /(?i)ignore\s+(?:all\s+)?(?:the\s+)?(?:previous\|prior\|above\|earlier)\s+(?:instructions?\|prompts?\|rules?\|context)/ or event_text matches /(?i)disregard\s+(?:all\s+)?(?:previous\|prior\|the\s+above\|your)\s+(?:instructions?\|rules?\|system\s+prompt)/ or event_text matches /(?i)\b(?:you\s+are\s+now\|from\s+now\s+on\s+you\|new\s+instructions?\s*:\|system\s+override)\b/ or event_text matches /(?i)\bdo\s+not\s+(?:tell\|mention\|inform\|ask)\s+the\s+user\b/ or event_text matches /(?i)\b(?:always\|never)\b[^\n]{0,60}\bwithout\s+(?:asking\|confirmation\|approval\|permission)\b/ or event_text matches /(?i)\b(?:skip\|bypass\|suppress)\b[^\n]{0,40}\b(?:confirmation\|approval\|permission\|prompt)s?\b/)`

*Why an analyst cares:* A memory is the one piece of agent-written text with no retention policy against it. Every transcript store in this catalogue is swept, rotated or deleted by something and none of the memory directories is, and the content is written back into the context of later sessions. So an instruction that reaches the agent once and is remembered reaches it again in every session afterwards, with no file in the repository and no line in a settings file to show for it, and the conversation that planted it may be long gone. That is what makes this worth its own rule rather than a note on the injection rule beside it. That one catches the instruction arriving, in a tool result or a fetched page, and it can only catch it while the transcript that carried it still exists. This one catches what the instruction became.

*Known false positives:*

- A memory the user asked for in as many words. "Always run the tests without asking" is a preference somebody may well have stated, and the finding is the place to check whether they did: the conversation that wrote the memory is the evidence, where it still exists.
- A note about prompt injection written while working on the problem, which quotes this language for the same reason the rule matches it.

*References:*

- <https://owasp.org/www-project-top-10-for-large-language-model-applications/>

*Samples in the rule file:* 2 / 2 (+/-)

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

*What it matches:* `event_text matches /(?i)(?<![A-Za-z0-9])(?:api[_-]?key\|secret\|passwd\|password\|client[_-]?secret\|access[_-]?token\|auth[_-]?token\|private[_-]?key)(?:_[A-Za-z0-9]+)*[^\S\n]*[:=][^\S\n]*["']?[A-Za-z0-9_\-/+.]{8,}/`

This rule does not quote what it matched. The matched value is a credential, and a finding is exported and pasted into reports, so the value stays in the event it came from.

*Why an analyst cares:* Most credentials have no recognisable prefix, so a pack that only matched known shapes would report the ones that are easy to find and miss the ones that are specific to the organization. Matching the assignment rather than the value is deliberately broad, which is why this rule is medium: it is a lead to read rather than a conclusion.

*Known false positives:*

- A placeholder, which this rule cannot tell from a value. Both password=changeme and password=REDACTED match, and both are common in documentation and in templates.
- A configuration file the agent read that holds an environment variable name rather than a value, such as password=$DB_PASSWORD.
- A key name in a schema or a type definition, where the value is a type rather than a secret.
- A setting whose name merely contains one of these words, such as SECRET_MANAGER_ENDPOINT or PASSWORD_MIN_LENGTH, since the name is matched with its surrounding words rather than on its own. The length floor keeps the numeric ones out and not the rest, which is part of why this rule is medium.

*Samples in the rule file:* 4 / 2 (+/-)

#### AFX-SECRETS-006

**A credential was passed to a command as a flag**

| | |
| --- | --- |
| Severity | high |
| Pack | `secrets` |
| Agents | `any` |
| Event kinds | `any` |
| Fields read | `event_text` |
| Tags | `T1552.003`, `credential-in-transcript` |

A command line carries a credential as the value of an option such as --api-key, --token or --password. Cursor's command line agent documents --api-key as one of its two ways of authenticating, and the same shape appears in every tool that offers one.

*What it matches:* `event_text matches /(?i)--(?:api[_-]?key\|access[_-]?token\|auth[_-]?token\|token\|password\|secret)(?:=\|[^\S\n]+)["']?[A-Za-z0-9_/+.][A-Za-z0-9_\-/+.]{11,}/`

This rule does not quote what it matched. The matched value is a credential, and a finding is exported and pasted into reports, so the value stays in the event it came from.

*Why an analyst cares:* A credential given as a flag is written down twice by the operating system before anything the agent does: into the shell history file, which this suite collects, and into the process table, where anything running as any user on the machine could read it while the command ran. Neither copy is deleted when the credential is rotated, so a shell history is a credential store that nobody thinks of as one, and the rule that matches an assignment does not see this shape because a flag and its value are separated by a space rather than by an equals sign. It is high rather than critical because the value may be a placeholder from a document somebody pasted, and because the finding names an exposure rather than a use.

*Known false positives:*

- A placeholder in a README, a runbook or a help text, which this rule cannot tell from a value. It matches because the text is what is on disk.
- A value that is long enough to look like a credential and is not one, such as a job name or a file name given to an option whose name mentions a token.

*References:*

- <https://cursor.com/docs/cli/reference/authentication>

*Samples in the rule file:* 3 / 3 (+/-)

#### AFX-SECRETS-007

**A credential was carried in an authorization header**

| | |
| --- | --- |
| Severity | high |
| Pack | `secrets` |
| Agents | `any` |
| Event kinds | `any` |
| Fields read | `event_text` |
| Tags | `T1552.001`, `credential-in-transcript` |

An HTTP authorization header with a value appears in this record: a bearer token, a basic-auth blob, or an API key header. The header names itself, so unlike a bare string this is a credential in a request rather than a string that looks like one.

*What it matches:* `event_text matches /(?i)\bauthorization["']?[^\S\n]*[:=][^\S\n]*["']?(?:bearer\|token\|basic\|apikey)[^\S\n]+[A-Za-z0-9_\-./+=]{12,}/ or /(?i)\b(?:x-api-key\|x-auth-token\|api-key\|proxy-authorization)["']?[^\S\n]*[:=][^\S\n]*["']?[A-Za-z0-9_\-./+=]{12,}/`

This rule does not quote what it matched. The matched value is a credential, and a finding is exported and pasted into reports, so the value stays in the event it came from.

*Why an analyst cares:* This is the shape a credential takes at the moment it is used, and it is the one shape the other rules in this pack miss. They match a token by its vendor prefix or by the name of the variable it was assigned to, and a header has neither: the token is whatever the service issued, and the name in front of it is Authorization, which no rule about a variable called api_key will ever see. It matters most where the request is not in the transcript at all. A wrapper function in a shell environment adds the header to every call it makes, and the transcript records the wrapper's name, so the credential is only ever visible in the environment the agent ran in.

*Known false positives:*

- A documentation example or a template, where the value is a placeholder of plausible length such as YOUR_API_KEY_HERE or a row of x characters. This rule cannot tell a placeholder from a credential, and neither can the file it is reading.
- A header in a recorded response or in a log the agent read rather than one it sent, which is still a credential on the endpoint but says nothing about the agent using it.
- A test fixture in the working copy, which is where deliberately invalid tokens of the right shape live.

*References:*

- <https://datatracker.ietf.org/doc/html/rfc9110#name-authorization>

*Samples in the rule file:* 4 / 2 (+/-)

#### AFX-SECRETS-008

**A credential file was copied into every worktree the agent creates**

| | |
| --- | --- |
| Severity | medium |
| Pack | `secrets` |
| Agents | `any` |
| Event kinds | `config.snapshot` |
| Fields read | `payload.key`, `payload.text` |
| Tags | `T1552.001`, `credential-at-rest` |

A worktree include list names a file whose name says it holds credentials. The vendor documents this list as the gitignored files to copy into every worktree the agent creates, so a name here means copies of that file exist beside every checkout on the machine rather than only in the main one.

*What it matches:* `payload.key matches /^include:/ and payload.text matches /(?i)(^\|[/\\])\.env(\.\|$)/ or /(?i)\b(secrets?\|credentials?\|\.netrc\|id_rsa\|id_ed25519\|\.pem\|\.p12\|keystore\|serviceaccount)\b/ or /(?i)\.(pem\|key\|p12\|pfx\|jks)$/`

*Why an analyst cares:* This is a finding about where to look rather than about a value. The list is written by the author of the repository and it is an explicit inventory: it says, in the author's own words, which files git was deliberately keeping out of the repository and which of those the agent is to duplicate anyway. Every worktree is then a second copy of the credential, in a directory the developer may not think of as holding one, outside whatever protects the original. The vendor's own documentation names .env and secrets configuration as the examples, so this is the documented use of the feature and not an abuse of it, which is exactly why it is easy to leave in place and forget.

*Known false positives:*

- A file named for secrets that holds only names, such as a template or an example environment file checked in for documentation. The list says what is copied and not what is in it.
- An entry that no longer exists on disk. The list is the author's intent at the time it was written, and the worktrees it applied to may have been removed since.
- A repository where the feature was never used, since the file is read whether or not the agent ever created a worktree. The vendor also documents that the list is not processed when a hook replaces the default worktree behaviour.

*References:*

- <https://code.claude.com/docs/en/worktrees.md>

*Samples in the rule file:* 3 / 2 (+/-)

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

*What it matches:* `(payload.hooks is present or payload.files[].path matches path **/.git/hooks/* or **/.husky/** or **/.claude/hooks/** or **/.claude/settings.json or **/.claude/settings.local.json or event_text matches /(?i)"(?:PreToolUse\|PostToolUse\|SessionStart\|UserPromptSubmit\|Stop\|PreCompact)"\s*:/ or event_text matches /(?m)^[^\S\n]*(?:PreToolUse\|PostToolUse\|SessionStart\|UserPromptSubmit\|PreCompact)[^\S\n]*$/ or event_text matches /"scripts"\s*:[\s\S]{0,200}"(?:preinstall\|postinstall\|prepare)"\s*:/ or event_text matches /(?m)^[^\S\n]*(?:preinstall\|postinstall\|prepare)[^\S\n]*=/)`

*Why an analyst cares:* A hook is code that runs without anyone asking, at a moment the agent chose, and the vendor documents that a pre-tool hook can let a call proceed without the prompt that would otherwise appear. That makes a hook both a persistence mechanism and a permission bypass wearing different clothes. It also survives the session, so a hook found on a machine is a question about every session since it was written, not just this one.

*Known false positives:*

- A key on a line of its own in some other document that happens to be named like a hook event. The text views render a mapping one leaf per line, so the second pattern here matches a line rather than a JSON key, which is what makes it work on a document nobody has mapped and what makes this possible.
- A project that uses hooks for what they are for, formatting on commit being the obvious case, which is good practice and matches.
- A settings file written because the developer granted a permission through the agent's own interface, which is the documented way to do it.

*References:*

- <https://code.claude.com/docs/en/permissions>

*Samples in the rule file:* 5 / 2 (+/-)

#### AFX-SUPPLYCHAIN-003

**A hook script on the endpoint fetches code and runs it**

| | |
| --- | --- |
| Severity | high |
| Pack | `supply_chain` |
| Agents | `any` |
| Event kinds | `instruction.source` |
| Fields read | `payload.executable`, `payload.text` |
| Tags | `supply-chain`, `T1059`, `T1105`, `prompt-injection` |

A file the catalogue files under instructions is a script rather than prose, and its text downloads something and pipes or evaluates it into an interpreter. The shapes covered are a curl or wget piped into a shell or an interpreter, a shell substitution around a download, and the PowerShell equivalents built on Invoke-Expression, Invoke-WebRequest or DownloadString.

*What it matches:* `payload.executable is 'true' and payload.text matches /(?i)\b(curl\|wget)\b[^\n\|]*\\|[^\n]*\b(sh\|bash\|zsh\|dash\|python[0-9.]*\|perl\|ruby\|node)\b/ or /(?i)(eval\|source\|\.)[^\n]*\$\([^\n]*\b(curl\|wget)\b/ or /(?i)\b(iex\|invoke-expression)\b[^\n]*\b(invoke-webrequest\|iwr\|invoke-restmethod\|irm\|downloadstring\|downloadfile)\b/ or /(?i)\b(downloadstring\|downloadfile)\b[^\n]*\\|[^\n]*\b(iex\|invoke-expression)\b/`

*Why an analyst cares:* A hook is the one instruction an agent executes rather than reads, and it runs when the agent decides to run it rather than when a person asks. A hook that fetches its payload means the code that ran on the endpoint is not the code that was collected from it, so the file in evidence does not answer what happened and the remote does. That is worth interrupting an analyst for, and it is worth checking against the network destinations the same case recorded.

*Known false positives:*

- An installer or bootstrap hook a team wrote deliberately, fetching a pinned release from a host they control. The finding is still worth reading: the code that ran is not in evidence either way.

*Samples in the rule file:* 3 / 3 (+/-)

#### AFX-SUPPLYCHAIN-004

**A settings file names a command the agent runs to fetch its credentials**

| | |
| --- | --- |
| Severity | high |
| Pack | `supply_chain` |
| Agents | `any` |
| Event kinds | `config.snapshot` |
| Fields read | `raw.apiKeyHelper`, `raw.awsAuthRefresh`, `raw.awsCredentialExport`, `raw.gcpAuthRefresh`, `raw.otelHeadersHelper`, `event_text` |
| Tags | `T1078`, `T1552`, `supply-chain` |

A configuration sets one of the credential helper keys: a shell command line the product runs by itself to produce the token it authenticates with, or to refresh a cloud credential. Claude Code documents apiKeyHelper, awsAuthRefresh, awsCredentialExport, gcpAuthRefresh and otelHeadersHelper, each as a command line it executes.

*What it matches:* `(raw.apiKeyHelper is present or raw.awsAuthRefresh is present or raw.awsCredentialExport is present or raw.gcpAuthRefresh is present or raw.otelHeadersHelper is present or event_text matches /(?m)^[^\S\n]*(?:apiKeyHelper\|awsAuthRefresh\|awsCredentialExport\|gcpAuthRefresh\|otelHeadersHelper)[^\S\n]*=[^\S\n]*\S/)`

*Why an analyst cares:* The hook rule beside this one finds a command the agent runs around a tool call. This is a command it runs around authentication, and it differs in three ways that matter to an investigation. It runs outside the conversation. The vendor documents the helper being rerun on a cache timer, on a 401 or a 403, and before a request when the cached token has expired, so it executes on a schedule no transcript records and leaves no turn behind. Its output is a credential. The vendor states that the helper's output is sent as the API key and as the bearer token, so whatever this command prints is what authenticated every model request, and a command that was replaced prints whatever its replacement wants. And it can arrive with a repository. The vendor scopes these keys to any settings file, including a project one, and notes that an interactive session waits for the workspace trust prompt before running one from project or local settings. So the file is evidence of intent even where the prompt was never accepted, and evidence of execution where it was.

*Known false positives:*

- The ordinary use, which is what the setting is for: a vault client or a cloud login command, in an organization that rotates credentials. The finding says the agent runs a command of somebody's choosing to get its token, which is worth reading once whatever the answer turns out to be.
- A settings file that carries the key and was never the effective one, such as a project file in a workspace nobody trusted. The finding names the file, and the vendor documents the trust prompt that decides it.

*References:*

- <https://code.claude.com/docs/en/settings-reference>

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

#### AFX-THIRDPARTYENDPOINTS-002

**A tool server the agent used runs somewhere else**

| | |
| --- | --- |
| Severity | medium |
| Pack | `third_party_endpoints` |
| Agents | `any` |
| Event kinds | `config.snapshot`, `mcp.call` |
| Fields read | `event_text`, `raw.mcpServers[].url` |
| Tags | `T1071`, `third-party-endpoint`, `mcp` |

An MCP server is configured with a remote transport: an entry carrying a url together with a type of http, streamable-http, sse or ws, rather than a command the agent starts on the endpoint.

*What it matches:* `(event_text matches /(?i)"?(?:type\|transport)"?[^\S\n]*[:=][^\S\n]*"?(?:streamable[-_]?http\|http\|sse\|ws)"?/ and event_text matches /(?i)"?(?:url\|serverUrl\|httpUrl\|endpoint)"?[^\S\n]*[:=][^\S\n]*"?(?:https?\|wss?):/// or raw.mcpServers[].url matches /(?i)^(?:https?\|wss?):///)`

*Why an analyst cares:* This is the other half of the question the rule before it answers. That one says where the conversation went; this one says where the agent's tools ran. Every call to a remote server, and every argument of every call, left the device: a file path, a file's contents where the tool takes them, a query, a token. The transcript records that a tool was called and not that the call went off the machine, so the configuration is the only place that fact exists. It stays at medium because a remote server is an ordinary, documented way to use this protocol, and most of them are services somebody chose deliberately. What the finding buys is the list: an analyst answering "which data left the device" needs the servers as much as the model endpoint, and a project-scoped configuration file is checked into a repository, so anyone who can commit to it can add one.

*Known false positives:*

- A service the organization chose and approved. The finding says a tool server was off the device, not that it should not have been.
- A server on the loopback address or on the local network, which matches because the entry is an http transport. The host in the finding is what tells those apart, and a server on localhost is still a second process the transcript does not describe.
- An entry that was configured and never connected. The vendor documents that a project scoped server waits for approval and that an entry with a url but no type is skipped, so a configuration is evidence of intent and the transcript is evidence of use.

*References:*

- <https://code.claude.com/docs/en/mcp>

*Samples in the rule file:* 2 / 2 (+/-)

#### AFX-THIRDPARTYENDPOINTS-003

**A machine-wide policy names the installation the conversations went to**

| | |
| --- | --- |
| Severity | medium |
| Pack | `third_party_endpoints` |
| Agents | `any` |
| Event kinds | `config.snapshot`, `unparsed.record` |
| Fields read | `provenance.artifact_id`, `event_text` |
| Tags | `third-party-endpoint`, `managed-policy`, `egress-route` |

A machine-wide policy file for one agent's command line product is in the case. The vendor documents it as pinning authentication to an enterprise host and an account, with the fields enterprise_host and account_id, and as optionally forcing an outbound proxy for the agent and its updater through a proxy section carrying a mode, a url and a no_proxy list.

*What it matches:* `(provenance.artifact_id is 'devin.cli_system_policy' or event_text matches /(?i)"?\benterprise_host\b"?[^\S\n]*[:=][^\S\n]*"?[A-Za-z0-9]/)`

*Why an analyst cares:* The two rules before this one answer where the conversation went and where the tools ran from what a user could set. This one answers the same question from what the machine was given, and it is the only place that answer exists: nothing in the user's profile names the installation of the vendor's service that served a session, so a case collected from a profile alone cannot say which server held the conversations. The absence of the file is an answer too, and a usable one: with no policy the product talked to the vendor's public service. . The route is the other half. The vendor documents the enterprise proxy as taking precedence over the user's own setting, and documents the product as exiting at startup if the user configured one as well, so on a machine where the agent ran at all, the traffic went out through the proxy named here. An examination answering what left the device and by which path has both ends of it in this one file. . Medium rather than high, and the reason is in the false positives below: this file is a managed deployment doing its job, and most machines that have one are enterprise machines rather than interesting ones. What the finding buys is the destination, in a form a report can name. It is also evidence about itself: the vendor states the file is meant to be deployed root owned and read only to the user because the product reads it wherever it finds it, so a copy that is user writable is a policy anybody on the machine could have written and its ownership and mode belong in the finding beside its contents.

*Known false positives:*

- An ordinary managed deployment, which is what the file is for and the common case by some distance. The finding names the destination and the route; it says nothing about whether either was allowed, and on a corporate machine both usually were.
- A policy deployed by an image onto a machine where the product was never run, in which case the host is where traffic would have gone rather than where anything went. The transcripts, and their absence, are what settle that.
- A stale or superseded policy. The file says what is in force when it is read, and its modification time belongs to the management channel that deployed it rather than to any session, so it cannot date what it applied to.
- A machine where the user's own configuration also set a proxy, which the vendor documents as an error that stops the product starting. Such a pair is a product that refused to run rather than a route anything went through.

*References:*

- <https://cli.devin.ai/docs/enterprise/system-config.md>

*Samples in the rule file:* 2 / 2 (+/-)
