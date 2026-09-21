# Unterstützte Agenten

[English](SUPPORT.md) | Deutsch

<!-- Generierte Datei. Nicht bearbeiten. scripts/gen_support_docs.py ausführen. -->

Was diese Suite pro Agent liest, gezählt aus dem Katalog und der Leser-Registrierung statt aufgeschrieben. Die Zahlen bewegen sich mit dem Code.

31 Katalogdateien, davon 30 ein Produkt und eine übergreifende. 519 von 656 Artefakten werden von 38 Leser-Modulen gelesen, in 23 Ereignisarten. 518 Artefakte beruhen auf einer abgerufenen Herstellerquelle.

**Wie ein leeres Ergebnis zu lesen ist.** Steht ein Agent hier mit gelesenen Artefakten, dann wurden die Pfade durchsucht und die vorhandenen Dateien ausgewertet, also ist ein leeres Ergebnis ein Befund über diese Pfade. Es ist nie ein Befund darüber, dass der Agent nicht benutzt wurde: der Datenbaum kann über eine Variable verschoben sein, die Aufbewahrungsfrist kann ihn gelöscht haben, die Pfade können die unverifizierten sein, oder die Person hat in einem Profil gearbeitet, das niemand gesammelt hat. Wo ein Eintrag unverifiziert ist, sagt `docs/ARTIFACTS.de.md` es pro Artefakt, und der Analyzer wiederholt es in seiner Ausgabe.

## Pro Agent

`Transkripte` zählt die Einträge, die als Konversationsspeicher geführt sind. `Gelesen` zählt jeden Eintrag des Agenten, den ein Leser beansprucht, egal in welcher Kategorie: Instruktionsdateien, MCP-Konfiguration, Berechtigungszustand, Prompt- und Shell-Historie, Erinnerungen und Logs stecken in dieser Zahl und sind oft das, was die Frage beantwortet, wenn die Transkripte weg sind. `Am Boden` zählt die Einträge, die ein generischer Leser liest, der den Inhalt zurückgibt und nichts darüber entscheidet, was ein Record bedeutet.

| Agent | OS | Transkripte | Gelesen | Am Boden | Nicht gelesen |
| --- | --- | --- | --- | --- | --- |
| Aider | Linux, macOS, Windows | 2 / 2 | 11 / 13 | 8 | 2 |
| Amazon Q Developer (CLI and IDE extension) | Linux, macOS, Windows | 3 / 3 | 17 / 20 | 9 | 3 |
| Amp | Linux, macOS, Windows | 2 / 2 | 10 / 11 | 6 | 1 |
| ChatGPT Desktop | macOS, Windows | 2 / 6 | 5 / 19 | 5 | 14 |
| Claude Code | Linux, macOS, Windows | 5 / 6 | 68 / 78 | 37 | 10 |
| Claude Desktop | Linux, macOS, Windows | 1 / 2 | 18 / 29 | 11 | 11 |
| Cline | Linux, macOS, Windows | 5 / 5 | 21 / 25 | 8 | 4 |
| Continue | Linux, macOS, Windows | 1 / 1 | 17 / 21 | 11 | 4 |
| Cross-cutting evidence | Linux, macOS, Windows | keine | 20 / 27 | 6 | 7 |
| Cursor | Linux, macOS, Windows | 9 / 9 | 43 / 50 | 31 | 7 |
| Devin | Linux, macOS, Windows | 1 / 1 | 6 / 7 | 5 | 1 |
| Factory Droid | Linux, macOS, Windows | 2 / 2 | 9 / 10 | 7 | 1 |
| Gemini CLI | Linux, macOS, Windows | 1 / 1 | 15 / 19 | 8 | 4 |
| GitHub Copilot CLI | Linux, macOS, Windows | 3 / 4 | 16 / 20 | 11 | 4 |
| Goose | Linux, macOS, Windows | 4 / 4 | 19 / 20 | 9 | 1 |
| Hermes | Linux, macOS, Windows | 10 / 11 | 41 / 56 | 31 | 15 |
| JetBrains AI Assistant | Linux, macOS, Windows | 1 / 1 | 6 / 8 | 4 | 2 |
| Junie | Linux, macOS, Windows | 2 / 2 | 7 / 9 | 6 | 2 |
| Kilo Code | Linux, macOS, Windows | 2 / 2 | 7 / 7 | 4 | 0 |
| Kiro | Linux, macOS, Windows | 5 / 5 | 20 / 22 | 14 | 2 |
| LM Studio | Linux, macOS, Windows | 1 / 1 | 5 / 7 | 3 | 2 |
| Ollama | Linux, macOS, Windows | 1 / 1 | 8 / 12 | 5 | 4 |
| OpenAI Codex CLI | Linux, macOS, Windows | 8 / 9 | 22 / 29 | 13 | 7 |
| OpenCode | Linux, macOS, Windows | 2 / 2 | 7 / 12 | 5 | 5 |
| pi | Linux, macOS, Windows | 1 / 1 | 8 / 10 | 3 | 2 |
| Qwen Code | Linux, macOS, Windows | 2 / 2 | 30 / 36 | 17 | 6 |
| Roo Code | Linux, macOS, Windows | 1 / 1 | 6 / 7 | 2 | 1 |
| Visual Studio Code host storage | Linux, macOS, Windows | keine | 9 / 10 | 6 | 1 |
| Warp | Linux, macOS, Windows | keine | 8 / 9 | 5 | 1 |
| Windsurf | Linux, macOS, Windows | 6 / 6 | 31 / 41 | 16 | 10 |
| Zed | Linux, macOS, Windows | 3 / 3 | 9 / 12 | 4 | 3 |

## Was nicht gelesen wird, und warum

Jedes Artefakt im Katalog wird gesammelt und erscheint im Fall, ob ein Leser es beansprucht oder nicht: ein Eintrag ohne Leser erzeugt weiterhin ein Dateisystem-Ereignis mit Pfad, Hash und Zeitstempeln. Was folgt, ist das, was darüber hinaus fehlt, in fünf Gruppen, weil es fünf verschiedene Antworten sind.

### Credential-Speicher: Metadaten und Hash, absichtlich

41 Einträge. Der Collector hält Pfad, Grösse, Zeitstempel und Hash fest und kopiert keinen Inhalt, solange es ihm nicht gesagt wird, also gibt es für einen Leser nichts zu lesen. Das ist eine Entscheidung und keine Lücke: die Datei belegt, dass ein Agent authentisiert war und bei welchem Anbieter, und das Token darin ist nicht, was eine Untersuchung braucht.

### Gesammelt und dem Leser übergeben, der es besser kann

5 Einträge. Jeder wird ganz gesammelt und hier absichtlich nicht ausgewertet, weil für dieses Format schon ein Leser existiert und es der ist, an dem ein Bericht gemessen wird.

- `crosscutting.macos_launch_services_registrations`: the registration database that still names an application after everything else has been cleaned. Its own reader is the system's registration tool, which this suite does not run because it runs nothing on the endpoint, so the file is collected and read afterwards
- `crosscutting.windows_execution_evidence_files`: the platform's own record that a binary ran: Amcache, Prefetch, SRUM and the scheduled-task XML. Collected whole and handed to the tools written for those formats, AmcacheParser, PECmd and SrumECmd, which are better than anything this project would write and are what a report will be challenged on
- `crosscutting.windows_execution_evidence_registry`: ShimCache, BAM and UserAssist. Registry keys, so only the PowerShell collector can reach them and only on the host itself, and the parsers for them are the established ones. UserAssist in particular records GUI launches and not command lines, which is how every agent here is started, so an empty result from it says nothing and the entry says so
- `crosscutting.windows_removed_product_registry`: the generic uninstall keys a removed product leaves behind. Declined by name rather than read, because the per-product protocol handlers that also survive an uninstall are separate entries and those are read as documents
- `cursor.install_and_machine_identity`: an uninstall key under a product GUID, which is not globbable and is declined by name. The filesystem half of the same install evidence is read under its own entries

### Container in einem Format, das hier niemand gelesen hat

85 Einträge, binäre oder Verzeichnis-Layouts ohne dokumentiertes Format. Jeder wird ganz gesammelt und steht als Dateisystem-Ereignis auf der Zeitlinie. Einen davon zu lesen heisst, eine Formatimplementierung zu schreiben, und nicht, einen unfertigen Leser fertigzustellen.

- `amazonq.cli_subagent_executions` (directory)
- `amazonq.ide_extension_install` (directory)
- `chatgpt_desktop.macos_app_pairing_extensions` (binary)
- `chatgpt_desktop.macos_codex_app_support` (binary)
- `chatgpt_desktop.macos_computer_use_service` (binary)
- `chatgpt_desktop.macos_conversations` (binary)
- `chatgpt_desktop.macos_crash_reports` (binary)
- `chatgpt_desktop.macos_drafts` (binary)
- `chatgpt_desktop.macos_httpstorages` (binary)
- `chatgpt_desktop.macos_legacy_app_support` (binary)
- `chatgpt_desktop.macos_legacy_conversations_dir` (binary)
- `chatgpt_desktop.macos_openai_shared_locations` (binary)
- `chatgpt_desktop.macos_saved_state_and_logs` (binary)
- `chatgpt_desktop.macos_web_content_cache` (directory)
- `chatgpt_desktop.macos_workspace_state` (binary)
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
- `codex.app_side_stores` (directory)
- `codex.curated_plugin_clone` (binary)
- `codex.ide_context_socket` (binary)
- `codex.thread_writer_locks` (binary)
- `codex.visualizations` (binary)
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
- `devin.cli_config_dir` (directory)
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

### Lesbare Formate mit einer Begründung

6 Einträge liegen in einem Format, das diese Suite liest, und werden von keinem Leser beansprucht, jeder mit der Begründung im Code neben der Entscheidung. Ein neuer Eintrag in diesem Zustand lässt einen Test scheitern, bis jemand ihn entweder liest oder die Begründung hinschreibt, und genau das verhindert, dass diese Liste versehentlich die Liste der unfertigen Arbeiten wird.

- `cline.extension_id`: the entry is the extension's storage directory, and what is under it is claimed by the entries for the task tree and the checkpoints. The id itself is the evidence and it is in the path, which the artifact event carries
- `crosscutting.homebrew_prefixes`: an installation prefix, so the evidence is which directories exist under it rather than what any one file says
- `crosscutting.uv_tool_dir`: declared and deliberately not read by the reader for this format, which says why in its own module: the manifests here describe the installer's own bookkeeping rather than an agent's activity
- `jetbrains_ai.base_directories`: the entry is the product's directory layout, which is what makes the other entries for this family resolvable. The files under it are claimed by those
- `roo_code.extension_id`: the same shape as the other extension id entry above
- `windsurf.enterprise_policy_templates`: group-policy templates, which are XML and say which settings exist rather than which were set. What was set is in the registry key of the entry beside this one, which a Windows collection carries as a document and this suite reads

### Unfertige Arbeit an einem Format, das schon gelesen wird

Zum Zeitpunkt dieser Generierung keine. Die Prüfung hinter diesem Abschnitt sucht einen Katalogeintrag in einem Format, das diese Suite schon liest, ohne Leser und ohne Begründung: so sieht unfertige Arbeit hier aus, und es gibt keine.

## Angefangen und nicht fertig

Zum Zeitpunkt dieser Generierung keine. Dieser Abschnitt nennt die Lesungen, die jemand angefangen und nicht fertiggestellt hat, deklariert in `src/agentforensics/parsers/coverage.py`, und es gibt keine.

## Wo die Lesung dünn ist

310 Artefakte werden von einem generischen Leser gelesen. Die Datei wird vollständig gelesen und jeder Record steht mit seinem Inhalt im Fall; was der Record bedeutet, ist nicht entschieden, und jeder sagt das an sich selbst. Zwei Arten von Record tragen diese Aussage: `unparsed.record` für etwas, das niemand lesen konnte, und ein als uninterpretiert zurückgegebener Record für etwas Gelesenes, dessen Format niemand abgebildet hat. In jeder Zusammenfassung dieser Suite sind die beiden getrennt gezählt, denn ein Speicher ohne Schema und eine halb geschriebene Datei sind entgegengesetzte Probleme.

## Wo es weitergeht

`docs/ARTIFACTS.de.md` für jeden Pfad jedes Artefakts mit Quelle und Verifikationsstand, `docs/UNIFIED_FORMAT.md` für das Format, das die Leser erzeugen, `docs/COLLECTION.md` für das, was eine Sammlung mitnimmt.
