# Supported agents

English | [Deutsch](SUPPORT.de.md)

<!-- Generated file. Do not edit. Run scripts/gen_support_docs.py. -->

What this suite reads, per agent, counted from the catalogue and the reader registry rather than written down. The numbers move when the code does.

31 catalogue files, 30 of them a product and one cross-cutting. 498 of 624 artifacts are read by 37 reader modules, into 23 event kinds. 499 artifacts rest on a fetched vendor source.

**How to read an empty result.** An agent listed here with artifacts read means the paths were searched and the files that were there were parsed, so an empty result is evidence that those paths held nothing. It is never evidence that the agent was not used: the data tree may have been relocated by a variable, the retention period may have swept it, the paths may be the unverified ones, or the user may have worked in a profile nobody collected. Where an entry is unverified, `docs/ARTIFACTS.md` says so per artifact and the analyzer repeats it in its output.

## Per agent

`transcripts` counts the entries filed as a conversation store. `read` counts every entry of the agent a reader claims, whatever its category: instruction files, MCP configuration, permission state, prompt and shell history, memories and logs are in that number and are often what answers the question when the transcripts are gone. `at the floor` counts the entries read by a generic reader, which returns the content and decides nothing about what a record means.

| Agent | OS | Transcripts | Read | At the floor | Not read |
| --- | --- | --- | --- | --- | --- |
| Aider | Linux, macOS, Windows | 2 / 2 | 11 / 13 | 8 | 2 |
| Amazon Q Developer (CLI and IDE extension) | Linux, macOS, Windows | 3 / 3 | 17 / 20 | 9 | 3 |
| Amp | Linux, macOS, Windows | 2 / 2 | 10 / 11 | 6 | 1 |
| ChatGPT Desktop | macOS, Windows | 2 / 5 | 3 / 11 | 3 | 8 |
| Claude Code | Linux, macOS, Windows | 5 / 6 | 68 / 78 | 37 | 10 |
| Claude Desktop | Linux, macOS, Windows | 1 / 2 | 18 / 29 | 11 | 11 |
| Cline | Linux, macOS, Windows | 5 / 5 | 21 / 25 | 8 | 4 |
| Continue | Linux, macOS, Windows | 1 / 1 | 17 / 21 | 11 | 4 |
| Cross-cutting evidence | Linux, macOS, Windows | none | 20 / 27 | 6 | 7 |
| Cursor | Linux, macOS, Windows | 9 / 9 | 43 / 50 | 32 | 7 |
| Devin | Linux, macOS, Windows | 1 / 1 | 2 / 2 | 2 | 0 |
| Factory Droid | Linux, macOS, Windows | 2 / 2 | 9 / 10 | 7 | 1 |
| Gemini CLI | Linux, macOS, Windows | 1 / 1 | 15 / 19 | 8 | 4 |
| GitHub Copilot CLI | Linux, macOS, Windows | 3 / 4 | 16 / 20 | 11 | 4 |
| Goose | Linux, macOS, Windows | 4 / 4 | 18 / 19 | 11 | 1 |
| Hermes | Linux, macOS, Windows | 10 / 11 | 41 / 56 | 31 | 15 |
| JetBrains AI Assistant | Linux, macOS, Windows | 1 / 1 | 5 / 7 | 4 | 2 |
| Junie | Linux, macOS, Windows | 2 / 2 | 7 / 9 | 6 | 2 |
| Kilo Code | Linux, macOS, Windows | 2 / 2 | 7 / 7 | 4 | 0 |
| Kiro | Linux, macOS, Windows | 5 / 5 | 20 / 22 | 14 | 2 |
| LM Studio | Linux, macOS, Windows | 1 / 1 | 5 / 7 | 3 | 2 |
| Ollama | Linux, macOS, Windows | 1 / 1 | 8 / 12 | 5 | 4 |
| OpenAI Codex CLI | Linux, macOS, Windows | 6 / 6 | 11 / 13 | 5 | 2 |
| OpenCode | Linux, macOS, Windows | 2 / 2 | 7 / 12 | 5 | 5 |
| pi | Linux, macOS, Windows | 1 / 1 | 8 / 10 | 3 | 2 |
| Qwen Code | Linux, macOS, Windows | 2 / 2 | 30 / 36 | 17 | 6 |
| Roo Code | Linux, macOS, Windows | 1 / 1 | 6 / 7 | 2 | 1 |
| Visual Studio Code host storage | Linux, macOS, Windows | none | 8 / 10 | 6 | 2 |
| Warp | Linux, macOS, Windows | none | 8 / 9 | 5 | 1 |
| Windsurf | Linux, macOS, Windows | 6 / 6 | 30 / 40 | 16 | 10 |
| Zed | Linux, macOS, Windows | 3 / 3 | 9 / 12 | 4 | 3 |

## What is not read, and why

Every artifact in the catalogue is collected and appears in a case, whether a reader claims it or not: an entry with no reader still produces one filesystem event carrying its path, hash and timestamps. What follows is what is missing beyond that, in five groups, because they are five different answers.

### Credential stores: metadata and a hash, by design

41 entries. The collector records the path, the size, the timestamps and the hash, and copies no content unless it is told to, so there is nothing for a reader to read. That is a decision rather than a gap: the file is evidence that an agent was authenticated and to which provider, and the token in it is not what an investigation needs.

### Collected and handed to the reader that is better at it

5 entries. Each is collected whole and deliberately not parsed here, because a reader for that format already exists and is the one a report will be challenged on.

- `crosscutting.macos_launch_services_registrations`: the registration database that still names an application after everything else has been cleaned. Its own reader is the system's registration tool, which this suite does not run because it runs nothing on the endpoint, so the file is collected and read afterwards
- `crosscutting.windows_execution_evidence_files`: the platform's own record that a binary ran: Amcache, Prefetch, SRUM and the scheduled-task XML. Collected whole and handed to the tools written for those formats, AmcacheParser, PECmd and SrumECmd, which are better than anything this project would write and are what a report will be challenged on
- `crosscutting.windows_execution_evidence_registry`: ShimCache, BAM and UserAssist. Registry keys, so only the PowerShell collector can reach them and only on the host itself, and the parsers for them are the established ones. UserAssist in particular records GUI launches and not command lines, which is how every agent here is started, so an empty result from it says nothing and the entry says so
- `crosscutting.windows_removed_product_registry`: the generic uninstall keys a removed product leaves behind. Declined by name rather than read, because the per-product protocol handlers that also survive an uninstall are separate entries and those are read as documents
- `cursor.install_and_machine_identity`: an uninstall key under a product GUID, which is not globbable and is declined by name. The filesystem half of the same install evidence is read under its own entries

### Containers in a format nobody here has read

74 entries, binary or directory layouts with no documented format. Each one is collected whole and is on the timeline as a filesystem event. Reading one means writing a format implementation, not finishing an unfinished reader.

- `amazonq.cli_subagent_executions` (directory)
- `amazonq.ide_extension_install` (directory)
- `chatgpt_desktop.macos_app_pairing_extensions` (binary)
- `chatgpt_desktop.macos_codex_app_support` (binary)
- `chatgpt_desktop.macos_computer_use_service` (binary)
- `chatgpt_desktop.macos_httpstorages` (binary)
- `chatgpt_desktop.macos_legacy_app_support` (binary)
- `chatgpt_desktop.macos_legacy_conversations_dir` (binary)
- `chatgpt_desktop.macos_saved_state_and_logs` (binary)
- `claude_code.feedback_bundles` (binary)
- `claude_code.image_cache` (binary)
- `claude_code.install_legacy_and_npm` (binary)
- `claude_code.install_native` (binary)
- `claude_code.plugin_data` (binary)
- `claude_code.uploads` (binary)
- `claude_code.worktrees` (binary)
- `claude_desktop.cowork_session_files` (directory)
- `claude_desktop.cowork_session_store` (directory)
- `claude_desktop.cowork_vm_bundle` (binary)
- `claude_desktop.embedded_claude_code` (binary)
- `claude_desktop.install_evidence_macos` (directory)
- `claude_desktop.install_evidence_windows` (directory)
- `claude_desktop.ssh_remote_artifacts` (directory)
- `claude_desktop.user_output_folder` (directory)
- `cline.chat_workspace` (directory)
- `continue.downloaded_binaries` (binary)
- `copilot.cache` (directory)
- `copilot.extensions_and_plugins` (directory)
- `copilot.session_state` (directory)
- `crosscutting.windows_appdata_program_dirs` (binary)
- `cursor.computer_use_sidecar` (directory)
- `cursor.install_dirs` (directory)
- `cursor.macos_update_state` (directory)
- `cursor.worker_data` (directory)
- `cursor.worktrees` (directory)
- `factory_droid.worktrees` (directory)
- `gemini_cli.home_tree` (directory)
- `gemini_cli.project_runtime_trees` (directory)
- `hermes.backups` (binary)
- `hermes.browser_agent_profiles` (directory)
- `hermes.browser_media` (binary)
- `hermes.browser_profile` (directory)
- `hermes.mcp_installs` (directory)
- `hermes.profile_home` (directory)
- `hermes.retired_wal_generations` (directory)
- `hermes.sandboxes` (binary)
- `hermes.state_snapshots` (directory)
- `junie.plugin_install_evidence` (binary)
- `kiro.cli_install` (binary)
- `kiro.legacy_amazonq_config` (directory)
- `lmstudio.cli_and_server` (binary)
- `lmstudio.models` (binary)
- `ollama.backup_dir` (binary)
- `ollama.macos_app_container` (binary)
- `ollama.model_blobs` (binary)
- `opencode.install_and_runtime_trees` (binary)
- `opencode.repos_cache` (binary)
- `opencode.state_and_temp` (directory)
- `pi.bin` (binary)
- `qwen_code.arena_worktrees` (directory)
- `qwen_code.audit_landing` (directory)
- `qwen_code.project_temp_spill` (directory)
- `vscode.local_history` (directory)
- `vscode.user_data_roots` (binary)
- `windsurf.cli_feature_state` (binary)
- `windsurf.code_tracker_and_settings` (binary)
- `windsurf.enterprise_policy_bundled` (directory)
- `windsurf.language_server_binaries_and_logs` (binary)
- `windsurf.macos_update_state` (directory)
- `windsurf.server_data` (directory)
- `windsurf.worktrees` (directory)
- `zed.extensions` (binary)
- `zed.semantic_index` (directory)
- `zed.state_tree` (directory)

### Readable formats with a reason

6 entries are in a format this suite reads and are claimed by no reader, each with the reason recorded in the code beside the decision. A new entry in this state fails a test until somebody either reads it or writes the reason down, which is what keeps this list from becoming the unfinished-work list by accident.

- `cline.extension_id`: the entry is the extension's storage directory, and what is under it is claimed by the entries for the task tree and the checkpoints. The id itself is the evidence and it is in the path, which the artifact event carries
- `crosscutting.homebrew_prefixes`: an installation prefix, so the evidence is which directories exist under it rather than what any one file says
- `crosscutting.uv_tool_dir`: declared and deliberately not read by the reader for this format, which says why in its own module: the manifests here describe the installer's own bookkeeping rather than an agent's activity
- `jetbrains_ai.base_directories`: the entry is the product's directory layout, which is what makes the other entries for this family resolvable. The files under it are claimed by those
- `roo_code.extension_id`: the same shape as the other extension id entry above
- `windsurf.enterprise_policy_templates`: group-policy templates, which are XML and say which settings exist rather than which were set. What was set is in the registry key of the entry beside this one, which a Windows collection carries as a document and this suite reads

### Unfinished work on a format that is already read

None as of this generation. The check behind this section looks for a catalogue entry in a format this suite already reads, with no reader and no reason: that is the shape unfinished work takes here, and there is none.

## Started and not finished

2 entries where somebody wrote down that the reading is incomplete. Everything above is a decision; this is a list of work. An entry here may also appear above, in whichever group its current state puts it, because `read` on this page is a yes or a no and an analyst deciding whether a case can be quoted needs the third answer. The declaration lives in `src/agentforensics/parsers/coverage.py` and a test holds each entry to still existing in the catalogue, so this list cannot outlive what it promises.

- `goose.plugins`: the plugin tree is collected whole and read as text, which is right for the shell scripts in it and wrong for the hooks/hooks.json beside them. That file registers the commands the product runs on tool events, and the matcher that decides which calls they fire on, so until something reads it as the registry it is, a case holds it as prose and no rule can ask what a hook was permitted to do
- `vscode.local_history`: the editor's own copy of a file from before each change, which an agent's edits land in like anybody else's. The index inside is JSON and the versions beside it are the file contents, and reading the pair as a snapshot store is format work nobody here has done. The directory is collected and is on the timeline; the earlier text inside it is not on the timeline as anything

## Where the reading is thin

300 artifacts are read by a generic reader. The file is read completely and every record is in the case with its content; what the record means is not decided, and each one says so on itself. Two kinds of record carry that statement: `unparsed.record` for something nothing could read, and a record marked as returned uninterpreted for something read whose format nobody has mapped. The counts are separate in every summary this suite prints, because a store nobody has a schema for and a half-written file are opposite problems.

## Where to look next

`docs/ARTIFACTS.md` for every path of every artifact with its source and verification state, `docs/UNIFIED_FORMAT.md` for the format the readers produce, `docs/COLLECTION.md` for what a collection takes.
