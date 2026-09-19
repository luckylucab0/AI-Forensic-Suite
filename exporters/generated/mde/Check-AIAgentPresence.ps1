# Generated from the artifact catalogue. Do not edit by hand:
# run `afx export-collection` and commit the result.
# Catalogue digest: 8e99fe9d5a0a
#
# An empty result from this rule means the paths it searched held nothing. It does
# not mean the host is clean. Unverified catalogue entries, relocated data trees and
# the paths listed as not covered below are all reasons a used agent leaves no hit
# here. Where this matters, run the suite's own collector instead: it reads the
# relocation variables and the agents' own state files, which no static rule can.
#
# Presence only. It reads directory existence and file counts and copies
# nothing, so it is safe to run on a host you have not yet decided to
# collect from. For the collection itself, follow the runbook beside this
# file: this script cannot see a relocated tree or a project directory,
# and the collector can.
#
# PowerShell 5.1, no modules, one file, because that is what a live
# response session can run.
#
# Live response is Windows only here, so every catalogue artifact that
# declares no Windows path is outside this check's scope entirely, which
# is a different thing from the per-artifact gaps listed below.
#
# Not covered by this rule:
#   a registry key, which the runbook's collector reads instead
#     claude_code.managed_settings_registry
#     claude_desktop.managed_policy_windows
#     crosscutting.windows_execution_evidence_registry
#     cursor.install_and_machine_identity
#     ollama.env_overrides_registry
#     windsurf.enterprise_policy
#   anchored at a working copy, whose location only the agent's own state file gives: the runbook's collector reads it, this check cannot
#     aider.chat_history
#     aider.config
#     aider.dotenv
#     aider.input_history
#     aider.model_metadata
#     aider.model_settings
#     aider.tags_cache
#     amazonq.cli_agents
#     amazonq.cli_mcp_config
#     amazonq.cli_subagent_executions
#     amazonq.cli_todo_lists
#     amazonq.ide_agent_config
#     amazonq.ide_chat_export
#     amazonq.memory_bank
#     amazonq.project_rules
#     amazonq.prompt_library
#     amp.settings
#     amp.skills
#     claude_code.agent_memory
#     claude_code.agents
#     claude_code.commands
#     claude_code.loop_instructions
#     claude_code.output_styles
#     claude_code.plugin_manifests
#     claude_code.project_claude_local_md
#     claude_code.project_claude_md
#     claude_code.project_mcp_json
#     claude_code.project_rules
#     claude_code.project_settings
#     claude_code.project_settings_local
#     claude_code.settings_referenced_executables
#     claude_code.skills
#     claude_code.workflows
#     claude_code.worktreeinclude
#     claude_code.worktrees
#     claude_desktop.code_launch_config
#     cline.checkpoint_refs_in_workspace
#     cline.rules_project
#     cline.workspace_specs
#     continue.agents
#     continue.config
#     copilot.lsp_config_repo
#     crosscutting.hook_scripts
#     crosscutting.instructions_agents_md
#     crosscutting.instructions_claude_md
#     crosscutting.instructions_clinerules
#     crosscutting.instructions_copilot_instructions
#     crosscutting.instructions_cursor_rules
#     crosscutting.instructions_gemini_md
#     crosscutting.instructions_junie_guidelines
#     crosscutting.instructions_kiro_steering
#     crosscutting.instructions_windsurf_rules
#     crosscutting.mcp_config_files
#     cursor.cli_config
#     cursor.commands_and_plans
#     cursor.hooks
#     cursor.mcp_config
#     cursor.project_instructions
#     cursor.skills
#     cursor.subagents
#     factory_droid.config
#     factory_droid.mcp_and_hooks
#     factory_droid.sessions
#     factory_droid.skills_and_droids
#     gemini_cli.project_config
#     goose.hints
#     goose.memory
#     goose.recipes
#     jetbrains_ai.mcp_config
#     junie.mcp_config
#     junie.project_dir
#     kilo_code.home_dir
#     kiro.agents
#     kiro.hooks
#     kiro.kiroignore
#     kiro.legacy_amazonq_config
#     kiro.mcp_config_project
#     kiro.prompt_library
#     kiro.skills_powers
#     kiro.specs
#     kiro.steering_project
#     opencode.agents_commands
#     opencode.config
#     opencode.tui_config
#     pi.settings
#     qwen_code.auto_memory
#     qwen_code.env_files
#     qwen_code.ignore_files
#     qwen_code.openai_api_logs
#     qwen_code.project_extension_points
#     qwen_code.project_instructions
#     qwen_code.project_mcp_config
#     qwen_code.project_settings
#     roo_code.custom_storage_path
#     roo_code.rules
#     vscode.mcp_config
#     windsurf.hooks
#     windsurf.ignore_files
#     windsurf.mcp_config
#     windsurf.plans
#     windsurf.project_instructions
#     windsurf.workflows_and_skills
#     zed.settings
#   no Windows path with a testable fixed prefix
#     amp.continuations
#     amp.session_pointer
#     cursor.retrieval_index
#     opencode.legacy_json_storage
#   reachable only through a relocation variable: the runbook's collector reads the variable, this check does not
#     claude_code.git_global_excludes
#     kiro.acp_wire_record
#     opencode.mcp_auth
#     opencode.repos_cache

$ErrorActionPreference = 'Stop'
# Every profile on the machine, not just the interactive user's: an agent driven by
# a service account is exactly the case a single-profile check would miss.
$profiles = @()
try {
    $profiles = Get-ChildItem -LiteralPath 'C:\Users' -Directory -ErrorAction Stop |
        Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') } |
        ForEach-Object { $_.FullName }
} catch {
    Write-Output ('cannot enumerate profiles: ' + $_.Exception.Message)
}

$targets = @(
    @{ Agent = 'aider'; Id = 'aider.analytics'; Path = '$profile\.aider\analytics.json' }
    @{ Agent = 'aider'; Id = 'aider.caches'; Path = '$profile\.aider\caches' }
    @{ Agent = 'amazonq'; Id = 'amazonq.cli_checkpoints'; Path = '$profile\.aws\amazonq\cli-checkouts' }
    @{ Agent = 'amazonq'; Id = 'amazonq.cli_logs'; Path = '$profile\AppData\Local\Temp\amazon-q\logs' }
    @{ Agent = 'amazonq'; Id = 'amazonq.cli_logs'; Path = '$profile\AppData\Local\Temp\qlog' }
    @{ Agent = 'amazonq'; Id = 'amazonq.cli_prompt_history'; Path = '$profile\.aws\amazonq\.cli_bash_history' }
    @{ Agent = 'amazonq'; Id = 'amazonq.cli_settings'; Path = '$profile\AppData\Local\amazon-q\settings.json' }
    @{ Agent = 'amazonq'; Id = 'amazonq.cli_state_database'; Path = '$profile\AppData\Local\amazon-q\data.sqlite3' }
    @{ Agent = 'amazonq'; Id = 'amazonq.cli_state_database'; Path = '$profile\AppData\Local\amazon-q\data.sqlite3-shm' }
    @{ Agent = 'amazonq'; Id = 'amazonq.cli_state_database'; Path = '$profile\AppData\Local\amazon-q\data.sqlite3-wal' }
    @{ Agent = 'amazonq'; Id = 'amazonq.cli_user_rules'; Path = '$profile\.aws\amazonq\rules' }
    @{ Agent = 'amazonq'; Id = 'amazonq.ide_chat_history'; Path = '$profile\.aws\amazonq\history' }
    @{ Agent = 'amazonq'; Id = 'amazonq.ide_chat_history'; Path = '$profile\.aws\amazonq\history\chat-history-' }
    @{ Agent = 'amazonq'; Id = 'amazonq.ide_chat_history'; Path = '$profile\.aws\amazonq\history\chat-history-no-workspace.json' }
    @{ Agent = 'amazonq'; Id = 'amazonq.ide_extension_install'; Path = '$profile\.vscode\extensions\amazonwebservices.amazon-q-vscode-' }
    @{ Agent = 'amazonq'; Id = 'amazonq.ide_extension_install'; Path = '$profile\.vscode\extensions\amazonwebservices.aws-toolkit-vscode-' }
    @{ Agent = 'amazonq'; Id = 'amazonq.ide_extension_install'; Path = '$profile\.vscode\extensions\extensions.json' }
    @{ Agent = 'amazonq'; Id = 'amazonq.knowledge_bases'; Path = '$profile\.aws\amazonq\knowledge_bases' }
    @{ Agent = 'amazonq'; Id = 'amazonq.legacy_profiles_and_context'; Path = '$profile\.aws\amazonq\global_context.json' }
    @{ Agent = 'amazonq'; Id = 'amazonq.legacy_profiles_and_context'; Path = '$profile\.aws\amazonq\profiles' }
    @{ Agent = 'amazonq'; Id = 'amazonq.sso_token_cache'; Path = '$profile\.aws\sso\cache' }
    @{ Agent = 'amazonq'; Id = 'amazonq.sso_token_cache'; Path = '$profile\.aws\sso\cache\aws-toolkit-vscode-client-id-' }
    @{ Agent = 'amp'; Id = 'amp.ledger'; Path = '$profile\AppData\Roaming\amp\ledger.jsonl' }
    @{ Agent = 'amp'; Id = 'amp.secrets'; Path = '$profile\.amp\oauth' }
    @{ Agent = 'amp'; Id = 'amp.secrets'; Path = '$profile\AppData\Roaming\amp\secrets.json' }
    @{ Agent = 'amp'; Id = 'amp.threads'; Path = '$profile\AppData\Roaming\amp\threads\T-' }
    @{ Agent = 'chatgpt_desktop'; Id = 'chatgpt_desktop.windows_msix_localcache'; Path = '$profile\AppData\Local\Packages\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0\LocalCache\Roaming\ChatGPT' }
    @{ Agent = 'chatgpt_desktop'; Id = 'chatgpt_desktop.windows_msix_localcache'; Path = '$profile\AppData\Local\Packages\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0\LocalCache\Roaming\ChatGPT\IndexedDB\https_chatgpt.com_0.indexeddb.leveldb' }
    @{ Agent = 'chatgpt_desktop'; Id = 'chatgpt_desktop.windows_msix_localcache'; Path = '$profile\AppData\Local\Packages\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0\LocalCache\Roaming\ChatGPT\Local Storage\leveldb' }
    @{ Agent = 'claude_code'; Id = 'claude_code.anthropic_active_config'; Path = '$profile\AppData\Roaming\Anthropic\active_config' }
    @{ Agent = 'claude_code'; Id = 'claude_code.anthropic_profile_configs'; Path = '$profile\AppData\Roaming\Anthropic\configs' }
    @{ Agent = 'claude_code'; Id = 'claude_code.anthropic_profile_credentials'; Path = '$profile\AppData\Roaming\Anthropic\credentials' }
    @{ Agent = 'claude_code'; Id = 'claude_code.auto_memory'; Path = '$profile\.claude\projects' }
    @{ Agent = 'claude_code'; Id = 'claude_code.changelog_cache'; Path = '$profile\.claude\cache\changelog.md' }
    @{ Agent = 'claude_code'; Id = 'claude_code.config_backups'; Path = '$profile\.claude\backups' }
    @{ Agent = 'claude_code'; Id = 'claude_code.config_backups'; Path = '$profile\.claude\backups\.claude.json.corrupted.' }
    @{ Agent = 'claude_code'; Id = 'claude_code.credentials'; Path = '$profile\.claude\.credentials.json' }
    @{ Agent = 'claude_code'; Id = 'claude_code.daemon_state'; Path = '$profile\.claude\daemon.lock' }
    @{ Agent = 'claude_code'; Id = 'claude_code.daemon_state'; Path = '$profile\.claude\daemon.log' }
    @{ Agent = 'claude_code'; Id = 'claude_code.daemon_state'; Path = '$profile\.claude\daemon\roster.json' }
    @{ Agent = 'claude_code'; Id = 'claude_code.debug_logs'; Path = '$profile\.claude\debug' }
    @{ Agent = 'claude_code'; Id = 'claude_code.feedback_bundles'; Path = '$profile\.claude\feedback-bundles' }
    @{ Agent = 'claude_code'; Id = 'claude_code.feedback_bundles'; Path = '$profile\.claude\feedback\drafts' }
    @{ Agent = 'claude_code'; Id = 'claude_code.feedback_drafts'; Path = '$profile\.claude\feedback\drafts' }
    @{ Agent = 'claude_code'; Id = 'claude_code.file_history_snapshots'; Path = '$profile\.claude\file-history' }
    @{ Agent = 'claude_code'; Id = 'claude_code.global_config'; Path = '$profile\.claude.json' }
    @{ Agent = 'claude_code'; Id = 'claude_code.history_jsonl'; Path = '$profile\.claude\history.jsonl' }
    @{ Agent = 'claude_code'; Id = 'claude_code.image_cache'; Path = '$profile\.claude\image-cache' }
    @{ Agent = 'claude_code'; Id = 'claude_code.install_legacy_and_npm'; Path = '$profile\.claude\local' }
    @{ Agent = 'claude_code'; Id = 'claude_code.install_legacy_and_npm'; Path = '$profile\.npm-global\lib\node_modules\@anthropic-ai\claude-code' }
    @{ Agent = 'claude_code'; Id = 'claude_code.install_legacy_and_npm'; Path = '$profile\.npm-packages\lib\node_modules\@anthropic-ai\claude-code' }
    @{ Agent = 'claude_code'; Id = 'claude_code.install_legacy_and_npm'; Path = '$profile\.nvm\versions\node' }
    @{ Agent = 'claude_code'; Id = 'claude_code.install_legacy_and_npm'; Path = '$profile\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code' }
    @{ Agent = 'claude_code'; Id = 'claude_code.install_native'; Path = '$profile\.local\bin\claude.exe' }
    @{ Agent = 'claude_code'; Id = 'claude_code.jobs'; Path = '$profile\.claude\jobs' }
    @{ Agent = 'claude_code'; Id = 'claude_code.keybindings'; Path = '$profile\.claude\keybindings.json' }
    @{ Agent = 'claude_code'; Id = 'claude_code.known_marketplaces'; Path = '$profile\.claude\plugins\known_marketplaces.json' }
    @{ Agent = 'claude_code'; Id = 'claude_code.legacy_dirs'; Path = '$profile\.claude\logs' }
    @{ Agent = 'claude_code'; Id = 'claude_code.legacy_dirs'; Path = '$profile\.claude\statsig' }
    @{ Agent = 'claude_code'; Id = 'claude_code.legacy_dirs'; Path = '$profile\.claude\todos' }
    @{ Agent = 'claude_code'; Id = 'claude_code.legacy_state_dirs'; Path = '$profile\.claude\logs' }
    @{ Agent = 'claude_code'; Id = 'claude_code.legacy_state_dirs'; Path = '$profile\.claude\statsig' }
    @{ Agent = 'claude_code'; Id = 'claude_code.legacy_state_dirs'; Path = '$profile\.claude\todos' }
    @{ Agent = 'claude_code'; Id = 'claude_code.managed_claude_md'; Path = 'C:\Program Files\ClaudeCode\CLAUDE.md' }
    @{ Agent = 'claude_code'; Id = 'claude_code.managed_mcp_json'; Path = 'C:\Program Files\ClaudeCode\managed-mcp.json' }
    @{ Agent = 'claude_code'; Id = 'claude_code.managed_settings_dropins'; Path = 'C:\Program Files\ClaudeCode\managed-settings.d' }
    @{ Agent = 'claude_code'; Id = 'claude_code.managed_settings_file'; Path = 'C:\Program Files\ClaudeCode\managed-settings.json' }
    @{ Agent = 'claude_code'; Id = 'claude_code.managed_settings_file'; Path = 'C:\ProgramData\ClaudeCode\managed-settings.json' }
    @{ Agent = 'claude_code'; Id = 'claude_code.mcp_logs'; Path = '$profile\AppData\Local\claude-cli-nodejs\Cache' }
    @{ Agent = 'claude_code'; Id = 'claude_code.org_policy_cache'; Path = '$profile\.claude\policy-limits.json' }
    @{ Agent = 'claude_code'; Id = 'claude_code.org_policy_cache'; Path = '$profile\.claude\remote-settings.json' }
    @{ Agent = 'claude_code'; Id = 'claude_code.paste_cache'; Path = '$profile\.claude\paste-cache' }
    @{ Agent = 'claude_code'; Id = 'claude_code.plans'; Path = '$profile\.claude\plans' }
    @{ Agent = 'claude_code'; Id = 'claude_code.plugin_cache'; Path = '$profile\.claude\plugins\cache' }
    @{ Agent = 'claude_code'; Id = 'claude_code.plugin_data'; Path = '$profile\.claude\plugins\data' }
    @{ Agent = 'claude_code'; Id = 'claude_code.plugin_marketplaces_clones'; Path = '$profile\.claude\plugins\marketplaces' }
    @{ Agent = 'claude_code'; Id = 'claude_code.plugins_root'; Path = '$profile\.claude\plugins' }
    @{ Agent = 'claude_code'; Id = 'claude_code.plugins_synced'; Path = '$profile\.claude\plugins\synced' }
    @{ Agent = 'claude_code'; Id = 'claude_code.policy_limits'; Path = '$profile\.claude\policy-limits.json' }
    @{ Agent = 'claude_code'; Id = 'claude_code.session_env'; Path = '$profile\.claude\session-env' }
    @{ Agent = 'claude_code'; Id = 'claude_code.sessions_dir'; Path = '$profile\.claude\sessions' }
    @{ Agent = 'claude_code'; Id = 'claude_code.shell_snapshots'; Path = '$profile\.claude\shell-snapshots' }
    @{ Agent = 'claude_code'; Id = 'claude_code.skills_trash'; Path = '$profile\.claude\skills\.trash' }
    @{ Agent = 'claude_code'; Id = 'claude_code.stats_cache'; Path = '$profile\.claude\stats-cache.json' }
    @{ Agent = 'claude_code'; Id = 'claude_code.subagent_transcripts'; Path = '$profile\.claude\projects' }
    @{ Agent = 'claude_code'; Id = 'claude_code.synced_skills'; Path = '$profile\.claude\skills\synced' }
    @{ Agent = 'claude_code'; Id = 'claude_code.task_lists'; Path = '$profile\.claude\tasks' }
    @{ Agent = 'claude_code'; Id = 'claude_code.themes'; Path = '$profile\.claude\themes' }
    @{ Agent = 'claude_code'; Id = 'claude_code.tool_result_spills'; Path = '$profile\.claude\projects' }
    @{ Agent = 'claude_code'; Id = 'claude_code.transcripts'; Path = '$profile\.claude\projects' }
    @{ Agent = 'claude_code'; Id = 'claude_code.transcripts_set_aside'; Path = '$profile\.claude\projects' }
    @{ Agent = 'claude_code'; Id = 'claude_code.uploads'; Path = '$profile\.claude\uploads' }
    @{ Agent = 'claude_code'; Id = 'claude_code.usage_data'; Path = '$profile\.claude\usage-data' }
    @{ Agent = 'claude_code'; Id = 'claude_code.usage_data'; Path = '$profile\.claude\usage-data\report.html' }
    @{ Agent = 'claude_code'; Id = 'claude_code.usage_reports'; Path = '$profile\.claude\usage-data' }
    @{ Agent = 'claude_code'; Id = 'claude_code.usage_reports'; Path = '$profile\.claude\usage-data\report.html' }
    @{ Agent = 'claude_code'; Id = 'claude_code.user_claude_md'; Path = '$profile\.claude\CLAUDE.md' }
    @{ Agent = 'claude_code'; Id = 'claude_code.user_rules'; Path = '$profile\.claude\rules' }
    @{ Agent = 'claude_code'; Id = 'claude_code.user_settings'; Path = '$profile\.claude\settings.json' }
    @{ Agent = 'claude_code'; Id = 'claude_code.user_settings_local'; Path = '$profile\.claude\settings.local.json' }
    @{ Agent = 'claude_code'; Id = 'claude_code.workflow_runs'; Path = '$profile\.claude\projects' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.app_logs'; Path = '$profile\AppData\Local\Claude-3p\logs\main.log' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.app_logs'; Path = '$profile\AppData\Local\Claude\Logs\main.log' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.app_logs'; Path = '$profile\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\logs' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.app_logs'; Path = '$profile\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\logs\main.log' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.app_logs'; Path = '$profile\AppData\Roaming\Claude\logs\main.log' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.code_session_index'; Path = '$profile\AppData\Local\Claude-3p\claude-code-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.code_session_index'; Path = '$profile\AppData\Local\Claude\claude-code-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.code_session_index'; Path = '$profile\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude-code-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.code_session_index'; Path = '$profile\AppData\Roaming\Claude\claude-code-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_account_settings'; Path = '$profile\AppData\Local\Claude-3p\local-agent-mode-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_account_settings'; Path = '$profile\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\local-agent-mode-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_account_settings'; Path = '$profile\AppData\Roaming\Claude\local-agent-mode-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_audit_key'; Path = '$profile\AppData\Local\Claude-3p\local-agent-mode-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_audit_key'; Path = '$profile\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\local-agent-mode-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_audit_key'; Path = '$profile\AppData\Roaming\Claude\local-agent-mode-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_audit_log'; Path = '$profile\AppData\Local\Claude-3p\local-agent-mode-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_audit_log'; Path = '$profile\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\local-agent-mode-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_audit_log'; Path = '$profile\AppData\Roaming\Claude\local-agent-mode-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_memory'; Path = '$profile\AppData\Local\Claude-3p\local-agent-mode-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_memory'; Path = '$profile\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\local-agent-mode-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_memory'; Path = '$profile\AppData\Roaming\Claude\local-agent-mode-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_session_files'; Path = '$profile\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\local-agent-mode-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_session_files'; Path = '$profile\AppData\Roaming\Claude\local-agent-mode-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_session_store'; Path = '$profile\AppData\Local\Claude-3p\local-agent-mode-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_session_store'; Path = '$profile\AppData\Local\Claude\local-agent-mode-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_session_store'; Path = '$profile\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\local-agent-mode-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_session_store'; Path = '$profile\AppData\Roaming\Claude\local-agent-mode-sessions' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_vm_bundle'; Path = '$profile\AppData\Local\Claude-3p\vm_bundles' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_vm_bundle'; Path = '$profile\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\vm_bundles\claudevm.bundle' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_vm_bundle'; Path = '$profile\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\vm_bundles\claudevm.bundle\sessiondata.vhdx' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.cowork_vm_bundle'; Path = '$profile\AppData\Roaming\Claude\vm_bundles\claudevm.bundle' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.coworkd_service_log'; Path = 'C:\ProgramData\Claude\Logs\coworkd\user-' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.device_identifier'; Path = '$profile\AppData\Local\Claude-3p\ant-did' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.embedded_claude_code'; Path = '$profile\AppData\Local\Claude-3p\claude-code' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.embedded_claude_code'; Path = '$profile\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude-code' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.embedded_claude_code'; Path = '$profile\AppData\Roaming\Claude\claude-code' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.install_evidence_windows'; Path = '$profile\AppData\Local\Packages\Claude_pzs8sxrjxfjjc' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.install_evidence_windows'; Path = 'C:\Program Files\WindowsApps\Claude_' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.local_config_library'; Path = '$profile\AppData\Local\Claude-3p\configLibrary' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.mcp_config'; Path = '$profile\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.mcp_config'; Path = '$profile\AppData\Roaming\Claude\claude_desktop_config.json' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.oauth_and_signin_tokens'; Path = '$profile\AppData\Local\Microsoft\Credentials' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.org_plugins'; Path = 'C:\Program Files\Claude\org-plugins' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.renderer_state'; Path = '$profile\AppData\Local\Claude-3p\IndexedDB' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.renderer_state'; Path = '$profile\AppData\Local\Claude\IndexedDB' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.renderer_state'; Path = '$profile\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\IndexedDB' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.renderer_state'; Path = '$profile\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\Local Storage' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.renderer_state'; Path = '$profile\AppData\Roaming\Claude\IndexedDB' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.renderer_state'; Path = '$profile\AppData\Roaming\Claude\Local Storage' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.scheduled_tasks'; Path = '$profile\.claude\scheduled-tasks' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.ssh_remote_artifacts'; Path = '$profile\.claude\remote\ccd-cli' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.ssh_remote_artifacts'; Path = '$profile\.claude\remote\plugins' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.ssh_remote_artifacts'; Path = '$profile\.claude\remote\run' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.ssh_remote_artifacts'; Path = '$profile\.claude\remote\srv' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.transient_session_credentials'; Path = '$profile\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\ccd-session-secrets' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.transient_session_credentials'; Path = '$profile\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\host-creds-' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.transient_session_credentials'; Path = '$profile\AppData\Roaming\Claude\ccd-session-secrets' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.transient_session_credentials'; Path = '$profile\AppData\Roaming\Claude\host-creds-' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.user_output_folder'; Path = '$profile\Claude' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.user_output_folder'; Path = '$profile\Claude\Projects' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.user_plugins'; Path = '$profile\AppData\Local\Claude-3p\cowork_plugins' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.user_plugins'; Path = '$profile\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\cowork_plugins' }
    @{ Agent = 'claude_desktop'; Id = 'claude_desktop.user_plugins'; Path = '$profile\AppData\Roaming\Claude\cowork_plugins' }
    @{ Agent = 'cline'; Id = 'cline.agent_schedules'; Path = '$profile\.cline\schedules' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\Code - Insiders\User\globalStorage\saoudrizwan.claude-dev\cache' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\Code - Insiders\User\globalStorage\saoudrizwan.claude-dev\cache\remote_config_' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\Code - Insiders\User\globalStorage\saoudrizwan.claude-dev\settings\cline_recommended_models.json' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\Code\User\globalStorage\saoudrizwan.claude-dev\cache' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\Code\User\globalStorage\saoudrizwan.claude-dev\cache\remote_config_' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_recommended_models.json' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\Cursor\User\globalStorage\saoudrizwan.claude-dev\cache' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\Cursor\User\globalStorage\saoudrizwan.claude-dev\cache\remote_config_' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\Cursor\User\globalStorage\saoudrizwan.claude-dev\settings\cline_recommended_models.json' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\Kiro\User\globalStorage\saoudrizwan.claude-dev\cache' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\Kiro\User\globalStorage\saoudrizwan.claude-dev\cache\remote_config_' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\Kiro\User\globalStorage\saoudrizwan.claude-dev\settings\cline_recommended_models.json' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\Positron\User\globalStorage\saoudrizwan.claude-dev\cache' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\Positron\User\globalStorage\saoudrizwan.claude-dev\cache\remote_config_' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\Positron\User\globalStorage\saoudrizwan.claude-dev\settings\cline_recommended_models.json' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\Trae\User\globalStorage\saoudrizwan.claude-dev\cache' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\Trae\User\globalStorage\saoudrizwan.claude-dev\cache\remote_config_' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\Trae\User\globalStorage\saoudrizwan.claude-dev\settings\cline_recommended_models.json' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\VSCodium\User\globalStorage\saoudrizwan.claude-dev\cache' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\VSCodium\User\globalStorage\saoudrizwan.claude-dev\cache\remote_config_' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\VSCodium\User\globalStorage\saoudrizwan.claude-dev\settings\cline_recommended_models.json' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\Windsurf\User\globalStorage\saoudrizwan.claude-dev\cache' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\Windsurf\User\globalStorage\saoudrizwan.claude-dev\cache\remote_config_' }
    @{ Agent = 'cline'; Id = 'cline.cache_and_remote_config'; Path = '$profile\AppData\Roaming\Windsurf\User\globalStorage\saoudrizwan.claude-dev\settings\cline_recommended_models.json' }
    @{ Agent = 'cline'; Id = 'cline.chat_workspace'; Path = '$profile\.cline\data\workspaces\chat' }
    @{ Agent = 'cline'; Id = 'cline.checkpoint_scratch'; Path = '$profile\.cline\data\checkpoint-scratch' }
    @{ Agent = 'cline'; Id = 'cline.checkpoints_shadow_git_legacy'; Path = '$profile\AppData\Roaming\Code - Insiders\User\globalStorage\saoudrizwan.claude-dev\checkpoints' }
    @{ Agent = 'cline'; Id = 'cline.checkpoints_shadow_git_legacy'; Path = '$profile\AppData\Roaming\Code\User\globalStorage\saoudrizwan.claude-dev\checkpoints' }
    @{ Agent = 'cline'; Id = 'cline.checkpoints_shadow_git_legacy'; Path = '$profile\AppData\Roaming\Cursor\User\globalStorage\saoudrizwan.claude-dev\checkpoints' }
    @{ Agent = 'cline'; Id = 'cline.checkpoints_shadow_git_legacy'; Path = '$profile\AppData\Roaming\Kiro\User\globalStorage\saoudrizwan.claude-dev\checkpoints' }
    @{ Agent = 'cline'; Id = 'cline.checkpoints_shadow_git_legacy'; Path = '$profile\AppData\Roaming\Positron\User\globalStorage\saoudrizwan.claude-dev\checkpoints' }
    @{ Agent = 'cline'; Id = 'cline.checkpoints_shadow_git_legacy'; Path = '$profile\AppData\Roaming\Trae\User\globalStorage\saoudrizwan.claude-dev\checkpoints' }
    @{ Agent = 'cline'; Id = 'cline.checkpoints_shadow_git_legacy'; Path = '$profile\AppData\Roaming\VSCodium\User\globalStorage\saoudrizwan.claude-dev\checkpoints' }
    @{ Agent = 'cline'; Id = 'cline.checkpoints_shadow_git_legacy'; Path = '$profile\AppData\Roaming\Windsurf\User\globalStorage\saoudrizwan.claude-dev\checkpoints' }
    @{ Agent = 'cline'; Id = 'cline.cli_sessions'; Path = '$profile\.cline\data\sessions' }
    @{ Agent = 'cline'; Id = 'cline.connector_settings_and_logs'; Path = '$profile\.cline\data\connectors\settings.json' }
    @{ Agent = 'cline'; Id = 'cline.connector_settings_and_logs'; Path = '$profile\.cline\data\logs' }
    @{ Agent = 'cline'; Id = 'cline.connector_settings_and_logs'; Path = '$profile\.cline\data\logs\connectors' }
    @{ Agent = 'cline'; Id = 'cline.data_dir_root'; Path = '$profile\.cline' }
    @{ Agent = 'cline'; Id = 'cline.data_dir_root'; Path = '$profile\.cline\data' }
    @{ Agent = 'cline'; Id = 'cline.data_tasks'; Path = '$profile\.cline\data\tasks' }
    @{ Agent = 'cline'; Id = 'cline.extension_id'; Path = '$profile\AppData\Roaming\Code - Insiders\User\globalStorage\saoudrizwan.claude-dev' }
    @{ Agent = 'cline'; Id = 'cline.extension_id'; Path = '$profile\AppData\Roaming\Code\User\globalStorage\saoudrizwan.claude-dev' }
    @{ Agent = 'cline'; Id = 'cline.extension_id'; Path = '$profile\AppData\Roaming\Cursor\User\globalStorage\saoudrizwan.claude-dev' }
    @{ Agent = 'cline'; Id = 'cline.extension_id'; Path = '$profile\AppData\Roaming\Kiro\User\globalStorage\saoudrizwan.claude-dev' }
    @{ Agent = 'cline'; Id = 'cline.extension_id'; Path = '$profile\AppData\Roaming\Positron\User\globalStorage\saoudrizwan.claude-dev' }
    @{ Agent = 'cline'; Id = 'cline.extension_id'; Path = '$profile\AppData\Roaming\Trae\User\globalStorage\saoudrizwan.claude-dev' }
    @{ Agent = 'cline'; Id = 'cline.extension_id'; Path = '$profile\AppData\Roaming\VSCodium\User\globalStorage\saoudrizwan.claude-dev' }
    @{ Agent = 'cline'; Id = 'cline.extension_id'; Path = '$profile\AppData\Roaming\Windsurf\User\globalStorage\saoudrizwan.claude-dev' }
    @{ Agent = 'cline'; Id = 'cline.global_settings'; Path = '$profile\.cline\data\settings\global-settings.json' }
    @{ Agent = 'cline'; Id = 'cline.global_state_json'; Path = '$profile\.cline\data\globalState.json' }
    @{ Agent = 'cline'; Id = 'cline.global_state_json'; Path = '$profile\.cline\data\workspaces' }
    @{ Agent = 'cline'; Id = 'cline.home_config_tree'; Path = '$profile\.agents\plugins' }
    @{ Agent = 'cline'; Id = 'cline.home_config_tree'; Path = '$profile\.cline\agents' }
    @{ Agent = 'cline'; Id = 'cline.home_config_tree'; Path = '$profile\.cline\cron' }
    @{ Agent = 'cline'; Id = 'cline.home_config_tree'; Path = '$profile\.cline\hooks' }
    @{ Agent = 'cline'; Id = 'cline.home_config_tree'; Path = '$profile\.cline\plugins' }
    @{ Agent = 'cline'; Id = 'cline.home_config_tree'; Path = '$profile\.cline\rules' }
    @{ Agent = 'cline'; Id = 'cline.home_config_tree'; Path = '$profile\.cline\skills' }
    @{ Agent = 'cline'; Id = 'cline.home_config_tree'; Path = '$profile\.cline\tasks' }
    @{ Agent = 'cline'; Id = 'cline.home_config_tree'; Path = '$profile\.cline\workflows' }
    @{ Agent = 'cline'; Id = 'cline.hooks_audit_log'; Path = '$profile\.cline\data\logs\hooks.jsonl' }
    @{ Agent = 'cline'; Id = 'cline.mcp_settings'; Path = '$profile\.cline\data\settings\cline_mcp_settings.json' }
    @{ Agent = 'cline'; Id = 'cline.mcp_settings'; Path = '$profile\AppData\Roaming\Code - Insiders\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json' }
    @{ Agent = 'cline'; Id = 'cline.mcp_settings'; Path = '$profile\AppData\Roaming\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json' }
    @{ Agent = 'cline'; Id = 'cline.mcp_settings'; Path = '$profile\AppData\Roaming\Cursor\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json' }
    @{ Agent = 'cline'; Id = 'cline.mcp_settings'; Path = '$profile\AppData\Roaming\Kiro\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json' }
    @{ Agent = 'cline'; Id = 'cline.mcp_settings'; Path = '$profile\AppData\Roaming\Positron\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json' }
    @{ Agent = 'cline'; Id = 'cline.mcp_settings'; Path = '$profile\AppData\Roaming\Trae\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json' }
    @{ Agent = 'cline'; Id = 'cline.mcp_settings'; Path = '$profile\AppData\Roaming\VSCodium\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json' }
    @{ Agent = 'cline'; Id = 'cline.mcp_settings'; Path = '$profile\AppData\Roaming\Windsurf\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json' }
    @{ Agent = 'cline'; Id = 'cline.provider_settings'; Path = '$profile\.cline\data\settings\providers.json' }
    @{ Agent = 'cline'; Id = 'cline.rules_global'; Path = '$profile\Cline\Rules' }
    @{ Agent = 'cline'; Id = 'cline.secrets_json'; Path = '$profile\.cline\data\secrets.json' }
    @{ Agent = 'cline'; Id = 'cline.sqlite_dbs'; Path = '$profile\.cline\data\db\connectors.db' }
    @{ Agent = 'cline'; Id = 'cline.sqlite_dbs'; Path = '$profile\.cline\data\db\connectors.db-shm' }
    @{ Agent = 'cline'; Id = 'cline.sqlite_dbs'; Path = '$profile\.cline\data\db\connectors.db-wal' }
    @{ Agent = 'cline'; Id = 'cline.sqlite_dbs'; Path = '$profile\.cline\data\db\cron.db' }
    @{ Agent = 'cline'; Id = 'cline.sqlite_dbs'; Path = '$profile\.cline\data\db\cron.db-shm' }
    @{ Agent = 'cline'; Id = 'cline.sqlite_dbs'; Path = '$profile\.cline\data\db\cron.db-wal' }
    @{ Agent = 'cline'; Id = 'cline.sqlite_dbs'; Path = '$profile\.cline\data\db\tasks.db' }
    @{ Agent = 'cline'; Id = 'cline.sqlite_dbs'; Path = '$profile\.cline\data\db\tasks.db-shm' }
    @{ Agent = 'cline'; Id = 'cline.sqlite_dbs'; Path = '$profile\.cline\data\db\tasks.db-wal' }
    @{ Agent = 'cline'; Id = 'cline.team_data'; Path = '$profile\.cline\data\teams' }
    @{ Agent = 'cline'; Id = 'cline.vscode_task_transcripts'; Path = '$profile\AppData\Roaming\Code - Insiders\User\globalStorage\saoudrizwan.claude-dev\tasks' }
    @{ Agent = 'cline'; Id = 'cline.vscode_task_transcripts'; Path = '$profile\AppData\Roaming\Code\User\globalStorage\saoudrizwan.claude-dev\tasks' }
    @{ Agent = 'cline'; Id = 'cline.vscode_task_transcripts'; Path = '$profile\AppData\Roaming\Cursor\User\globalStorage\saoudrizwan.claude-dev\tasks' }
    @{ Agent = 'cline'; Id = 'cline.vscode_task_transcripts'; Path = '$profile\AppData\Roaming\Kiro\User\globalStorage\saoudrizwan.claude-dev\tasks' }
    @{ Agent = 'cline'; Id = 'cline.vscode_task_transcripts'; Path = '$profile\AppData\Roaming\Positron\User\globalStorage\saoudrizwan.claude-dev\tasks' }
    @{ Agent = 'cline'; Id = 'cline.vscode_task_transcripts'; Path = '$profile\AppData\Roaming\Trae\User\globalStorage\saoudrizwan.claude-dev\tasks' }
    @{ Agent = 'cline'; Id = 'cline.vscode_task_transcripts'; Path = '$profile\AppData\Roaming\VSCodium\User\globalStorage\saoudrizwan.claude-dev\tasks' }
    @{ Agent = 'cline'; Id = 'cline.vscode_task_transcripts'; Path = '$profile\AppData\Roaming\Windsurf\User\globalStorage\saoudrizwan.claude-dev\tasks' }
    @{ Agent = 'codex'; Id = 'codex.archived_sessions'; Path = '$profile\.codex\archived_sessions' }
    @{ Agent = 'codex'; Id = 'codex.auth'; Path = '$profile\.codex\auth.json' }
    @{ Agent = 'codex'; Id = 'codex.config'; Path = '$profile\.codex' }
    @{ Agent = 'codex'; Id = 'codex.config'; Path = '$profile\.codex\config.toml' }
    @{ Agent = 'codex'; Id = 'codex.log_dir'; Path = '$profile\.codex\log' }
    @{ Agent = 'codex'; Id = 'codex.mcp_and_notify'; Path = '$profile\.codex\config.toml' }
    @{ Agent = 'codex'; Id = 'codex.mcp_oauth_credentials'; Path = '$profile\.codex\.credentials.json' }
    @{ Agent = 'codex'; Id = 'codex.prompt_history'; Path = '$profile\.codex\history.jsonl' }
    @{ Agent = 'codex'; Id = 'codex.requirements_and_permissions'; Path = '$profile\.codex\permissions.toml' }
    @{ Agent = 'codex'; Id = 'codex.requirements_and_permissions'; Path = '$profile\.codex\requirements.toml' }
    @{ Agent = 'codex'; Id = 'codex.rollouts'; Path = '$profile\.codex\sessions' }
    @{ Agent = 'codex'; Id = 'codex.rollouts_compressed'; Path = '$profile\.codex\sessions' }
    @{ Agent = 'codex'; Id = 'codex.sqlite_glob'; Path = '$profile\.codex' }
    @{ Agent = 'codex'; Id = 'codex.sqlite_write_ahead_logs'; Path = '$profile\.codex' }
    @{ Agent = 'codex'; Id = 'codex.state_databases'; Path = '$profile\.codex\goals_1.sqlite' }
    @{ Agent = 'codex'; Id = 'codex.state_databases'; Path = '$profile\.codex\logs_2.sqlite' }
    @{ Agent = 'codex'; Id = 'codex.state_databases'; Path = '$profile\.codex\memories_1.sqlite' }
    @{ Agent = 'codex'; Id = 'codex.state_databases'; Path = '$profile\.codex\memories_v2_1.sqlite' }
    @{ Agent = 'codex'; Id = 'codex.state_databases'; Path = '$profile\.codex\queue_1.sqlite' }
    @{ Agent = 'codex'; Id = 'codex.state_databases'; Path = '$profile\.codex\state_5.sqlite' }
    @{ Agent = 'codex'; Id = 'codex.state_databases'; Path = '$profile\.codex\thread_history_1.sqlite' }
    @{ Agent = 'continue'; Id = 'continue.aux_config'; Path = '$profile\.continue\.configs' }
    @{ Agent = 'continue'; Id = 'continue.aux_config'; Path = '$profile\.continue\.continueignore' }
    @{ Agent = 'continue'; Id = 'continue.aux_config'; Path = '$profile\.continue\.migrations' }
    @{ Agent = 'continue'; Id = 'continue.aux_config'; Path = '$profile\.continue\prompts' }
    @{ Agent = 'continue'; Id = 'continue.dev_data'; Path = '$profile\.continue\dev_data' }
    @{ Agent = 'continue'; Id = 'continue.dev_data'; Path = '$profile\.continue\logs\core.log' }
    @{ Agent = 'continue'; Id = 'continue.diffs'; Path = '$profile\.continue\.diffs' }
    @{ Agent = 'continue'; Id = 'continue.index'; Path = '$profile\.continue\.utils\repo_map.txt' }
    @{ Agent = 'continue'; Id = 'continue.index'; Path = '$profile\.continue\index\autocompleteCache.sqlite' }
    @{ Agent = 'continue'; Id = 'continue.index'; Path = '$profile\.continue\index\autocompleteCache.sqlite-shm' }
    @{ Agent = 'continue'; Id = 'continue.index'; Path = '$profile\.continue\index\autocompleteCache.sqlite-wal' }
    @{ Agent = 'continue'; Id = 'continue.index'; Path = '$profile\.continue\index\docs.sqlite' }
    @{ Agent = 'continue'; Id = 'continue.index'; Path = '$profile\.continue\index\docs.sqlite-shm' }
    @{ Agent = 'continue'; Id = 'continue.index'; Path = '$profile\.continue\index\docs.sqlite-wal' }
    @{ Agent = 'continue'; Id = 'continue.index'; Path = '$profile\.continue\index\index.sqlite' }
    @{ Agent = 'continue'; Id = 'continue.index'; Path = '$profile\.continue\index\index.sqlite-shm' }
    @{ Agent = 'continue'; Id = 'continue.index'; Path = '$profile\.continue\index\index.sqlite-wal' }
    @{ Agent = 'continue'; Id = 'continue.index'; Path = '$profile\.continue\index\lancedb' }
    @{ Agent = 'continue'; Id = 'continue.sessions'; Path = '$profile\.continue\sessions' }
    @{ Agent = 'continue'; Id = 'continue.sessions'; Path = '$profile\.continue\sessions\sessions.json' }
    @{ Agent = 'copilot'; Id = 'copilot.agents_skills_hooks'; Path = '$profile\.copilot\agents' }
    @{ Agent = 'copilot'; Id = 'copilot.agents_skills_hooks'; Path = '$profile\.copilot\hooks' }
    @{ Agent = 'copilot'; Id = 'copilot.agents_skills_hooks'; Path = '$profile\.copilot\skills' }
    @{ Agent = 'copilot'; Id = 'copilot.cache'; Path = '$profile\AppData\Local\copilot' }
    @{ Agent = 'copilot'; Id = 'copilot.command_history'; Path = '$profile\.copilot\command-history-state' }
    @{ Agent = 'copilot'; Id = 'copilot.config_json'; Path = '$profile\.copilot\config.json' }
    @{ Agent = 'copilot'; Id = 'copilot.extensions_and_plugins'; Path = '$profile\.copilot\extensions' }
    @{ Agent = 'copilot'; Id = 'copilot.extensions_and_plugins'; Path = '$profile\.copilot\installed-plugins' }
    @{ Agent = 'copilot'; Id = 'copilot.extensions_and_plugins'; Path = '$profile\.copilot\plugin-data' }
    @{ Agent = 'copilot'; Id = 'copilot.ide_locks'; Path = '$profile\.copilot\ide' }
    @{ Agent = 'copilot'; Id = 'copilot.instructions'; Path = '$profile\.copilot\copilot-instructions.md' }
    @{ Agent = 'copilot'; Id = 'copilot.instructions'; Path = '$profile\.copilot\instructions' }
    @{ Agent = 'copilot'; Id = 'copilot.logs'; Path = '$profile\.copilot\logs' }
    @{ Agent = 'copilot'; Id = 'copilot.lsp_config'; Path = '$profile\.copilot\lsp-config.json' }
    @{ Agent = 'copilot'; Id = 'copilot.mcp_config'; Path = '$profile\.copilot\mcp-config.json' }
    @{ Agent = 'copilot'; Id = 'copilot.mcp_config_jetbrains'; Path = '$profile\AppData\Local\github-copilot\intellij\mcp.json' }
    @{ Agent = 'copilot'; Id = 'copilot.mcp_credentials'; Path = '$profile\.copilot\mcp-oauth-config' }
    @{ Agent = 'copilot'; Id = 'copilot.mcp_credentials'; Path = '$profile\.copilot\mcp-secrets' }
    @{ Agent = 'copilot'; Id = 'copilot.permissions'; Path = '$profile\.copilot\permissions-config.json' }
    @{ Agent = 'copilot'; Id = 'copilot.providers'; Path = '$profile\.copilot\providers.json' }
    @{ Agent = 'copilot'; Id = 'copilot.session_event_log'; Path = '$profile\.copilot\session-state' }
    @{ Agent = 'copilot'; Id = 'copilot.session_state'; Path = '$profile\.copilot\session-state' }
    @{ Agent = 'copilot'; Id = 'copilot.session_store'; Path = '$profile\.copilot\session-store.db' }
    @{ Agent = 'copilot'; Id = 'copilot.session_store_sidecars'; Path = '$profile\.copilot\session-store.db-shm' }
    @{ Agent = 'copilot'; Id = 'copilot.session_store_sidecars'; Path = '$profile\.copilot\session-store.db-wal' }
    @{ Agent = 'copilot'; Id = 'copilot.settings'; Path = '$profile\.copilot\settings.json' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.npm_debug_logs'; Path = '$profile\.npm\_logs' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.npm_debug_logs'; Path = '$profile\AppData\Local\npm-cache\_logs' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.npm_global_install_dirs'; Path = '$profile\.nvm\versions\node' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.npm_global_install_dirs'; Path = '$profile\AppData\Roaming\npm' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.npm_global_install_dirs'; Path = '$profile\AppData\Roaming\npm\node_modules' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.npm_npx_cache'; Path = '$profile\.npm\_npx' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.npm_npx_cache'; Path = '$profile\AppData\Local\npm-cache\_npx' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.pipx_home_and_bin'; Path = '$profile\AppData\Local\pipx\pipx\venvs' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.shell_psreadline_history'; Path = '$profile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.shell_psreadline_history'; Path = '$profile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.uv_tool_dir'; Path = '$profile\AppData\Local\uv\cache' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.uv_tool_dir'; Path = '$profile\AppData\Roaming\uv\data\tools' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.windows_appdata_program_dirs'; Path = '$profile\AppData\Local\Ollama' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.windows_appdata_program_dirs'; Path = '$profile\AppData\Local\Packages' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.windows_appdata_program_dirs'; Path = '$profile\AppData\Local\Programs' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.windows_appdata_program_dirs'; Path = '$profile\AppData\Local\Programs\Ollama' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.windows_appdata_program_dirs'; Path = '$profile\AppData\Roaming' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.windows_execution_evidence_files'; Path = 'C:\Windows\AppCompat\Programs\Amcache.hve' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.windows_execution_evidence_files'; Path = 'C:\Windows\AppCompat\Programs\Amcache.hve.LOG1' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.windows_execution_evidence_files'; Path = 'C:\Windows\AppCompat\Programs\Amcache.hve.LOG2' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.windows_execution_evidence_files'; Path = 'C:\Windows\Prefetch' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.windows_execution_evidence_files'; Path = 'C:\Windows\System32\Tasks' }
    @{ Agent = 'crosscutting'; Id = 'crosscutting.windows_execution_evidence_files'; Path = 'C:\Windows\System32\sru\SRUDB.dat' }
    @{ Agent = 'cursor'; Id = 'cursor.acp_session_store'; Path = '$profile\.cursor\acp-sessions' }
    @{ Agent = 'cursor'; Id = 'cursor.agent_cli_state'; Path = '$profile\.cursor\agent-cli-state.json' }
    @{ Agent = 'cursor'; Id = 'cursor.agent_cli_state'; Path = '$profile\.cursor\browser-logs' }
    @{ Agent = 'cursor'; Id = 'cursor.agent_cli_state'; Path = '$profile\.cursor\commands' }
    @{ Agent = 'cursor'; Id = 'cursor.agent_cli_state'; Path = '$profile\.cursor\hooks.json' }
    @{ Agent = 'cursor'; Id = 'cursor.agent_cli_state'; Path = '$profile\.cursor\sandbox-policies' }
    @{ Agent = 'cursor'; Id = 'cursor.agent_cli_state'; Path = '$profile\.cursor\skills-cursor' }
    @{ Agent = 'cursor'; Id = 'cursor.agent_cli_state'; Path = '$profile\.cursor\snapshots' }
    @{ Agent = 'cursor'; Id = 'cursor.agent_cli_state'; Path = '$profile\.cursor\worktrees' }
    @{ Agent = 'cursor'; Id = 'cursor.agent_transcripts_jsonl'; Path = '$profile\.cursor\projects' }
    @{ Agent = 'cursor'; Id = 'cursor.ai_code_tracking_db'; Path = '$profile\.cursor\ai-tracking' }
    @{ Agent = 'cursor'; Id = 'cursor.ai_code_tracking_db'; Path = '$profile\.cursor\ai-tracking\ai-code-tracking.db' }
    @{ Agent = 'cursor'; Id = 'cursor.ai_code_tracking_db'; Path = '$profile\.cursor\ai-tracking\ai-code-tracking.db-shm' }
    @{ Agent = 'cursor'; Id = 'cursor.ai_code_tracking_db'; Path = '$profile\.cursor\ai-tracking\ai-code-tracking.db-wal' }
    @{ Agent = 'cursor'; Id = 'cursor.auth_credentials'; Path = '$profile\.cursor\auth.json' }
    @{ Agent = 'cursor'; Id = 'cursor.auth_credentials'; Path = '$profile\AppData\Roaming\Cursor\auth.json' }
    @{ Agent = 'cursor'; Id = 'cursor.chat_session_meta_json'; Path = '$profile\.cursor\chats' }
    @{ Agent = 'cursor'; Id = 'cursor.chat_session_prompt_history'; Path = '$profile\.cursor\chats' }
    @{ Agent = 'cursor'; Id = 'cursor.chat_store_db'; Path = '$profile\.cursor\chats' }
    @{ Agent = 'cursor'; Id = 'cursor.commit_checkpoints'; Path = '$profile\AppData\Roaming\Cursor\User\globalStorage\anysphere.cursor-commits\checkpoints' }
    @{ Agent = 'cursor'; Id = 'cursor.conversation_search_db'; Path = '$profile\AppData\Roaming\Cursor\User\globalStorage\conversation-search.db' }
    @{ Agent = 'cursor'; Id = 'cursor.conversation_search_db'; Path = '$profile\AppData\Roaming\Cursor\User\globalStorage\conversation-search.db-shm' }
    @{ Agent = 'cursor'; Id = 'cursor.conversation_search_db'; Path = '$profile\AppData\Roaming\Cursor\User\globalStorage\conversation-search.db-wal' }
    @{ Agent = 'cursor'; Id = 'cursor.extensions'; Path = '$profile\.cursor-server\extensions' }
    @{ Agent = 'cursor'; Id = 'cursor.extensions'; Path = '$profile\.cursor\extensions' }
    @{ Agent = 'cursor'; Id = 'cursor.extensions'; Path = '$profile\.cursor\extensions\extensions.json' }
    @{ Agent = 'cursor'; Id = 'cursor.global_prompt_history'; Path = '$profile\.cursor\prompt_history.json' }
    @{ Agent = 'cursor'; Id = 'cursor.global_state_vscdb'; Path = '$profile\AppData\Roaming\Cursor\User\globalStorage\state.vscdb' }
    @{ Agent = 'cursor'; Id = 'cursor.global_state_vscdb'; Path = '$profile\AppData\Roaming\Cursor\User\globalStorage\state.vscdb-shm' }
    @{ Agent = 'cursor'; Id = 'cursor.global_state_vscdb'; Path = '$profile\AppData\Roaming\Cursor\User\globalStorage\state.vscdb-wal' }
    @{ Agent = 'cursor'; Id = 'cursor.local_file_history'; Path = '$profile\AppData\Roaming\Cursor\User\History' }
    @{ Agent = 'cursor'; Id = 'cursor.logs'; Path = '$profile\AppData\Roaming\Cursor\logs' }
    @{ Agent = 'cursor'; Id = 'cursor.pasted_text'; Path = '$profile\.cursor\chats' }
    @{ Agent = 'cursor'; Id = 'cursor.plugins'; Path = '$profile\.cursor\plugins' }
    @{ Agent = 'cursor'; Id = 'cursor.plugins'; Path = '$profile\.cursor\plugins\local' }
    @{ Agent = 'cursor'; Id = 'cursor.project_metadata'; Path = '$profile\.cursor\projects' }
    @{ Agent = 'cursor'; Id = 'cursor.project_metadata'; Path = '$profile\.cursor\projects-metadata.json' }
    @{ Agent = 'cursor'; Id = 'cursor.subagent_output'; Path = '$profile\.cursor\subagents' }
    @{ Agent = 'cursor'; Id = 'cursor.workspace_state_vscdb'; Path = '$profile\AppData\Roaming\Cursor\User\workspaceStorage' }
    @{ Agent = 'cursor'; Id = 'cursor.worktrees'; Path = '$profile\.cursor\worktrees' }
    @{ Agent = 'devin'; Id = 'devin.acp_events'; Path = '$profile\AppData\Roaming\Devin\User\acp-events' }
    @{ Agent = 'devin'; Id = 'devin.sessions_db'; Path = '$profile\.local\share\devin\cli\sessions.db' }
    @{ Agent = 'devin'; Id = 'devin.sessions_db'; Path = '$profile\.local\share\devin\cli\sessions.db-shm' }
    @{ Agent = 'devin'; Id = 'devin.sessions_db'; Path = '$profile\.local\share\devin\cli\sessions.db-wal' }
    @{ Agent = 'factory_droid'; Id = 'factory_droid.auth'; Path = '$profile\.factory' }
    @{ Agent = 'factory_droid'; Id = 'factory_droid.logs'; Path = '$profile\.factory\bug-reports' }
    @{ Agent = 'factory_droid'; Id = 'factory_droid.logs'; Path = '$profile\.factory\logs' }
    @{ Agent = 'gemini_cli'; Id = 'gemini_cli.chats'; Path = '$profile\.gemini\sessions' }
    @{ Agent = 'gemini_cli'; Id = 'gemini_cli.chats'; Path = '$profile\.gemini\tmp' }
    @{ Agent = 'gemini_cli'; Id = 'gemini_cli.credentials'; Path = '$profile\.gemini\oauth_creds.json' }
    @{ Agent = 'gemini_cli'; Id = 'gemini_cli.google_accounts'; Path = '$profile\.gemini\google_accounts.json' }
    @{ Agent = 'gemini_cli'; Id = 'gemini_cli.home_tree'; Path = '$profile\.gemini' }
    @{ Agent = 'gemini_cli'; Id = 'gemini_cli.shell_history'; Path = '$profile\.gemini\tmp' }
    @{ Agent = 'gemini_cli'; Id = 'gemini_cli.system_settings'; Path = 'C:\ProgramData\gemini-cli\settings.json' }
    @{ Agent = 'gemini_cli'; Id = 'gemini_cli.system_settings'; Path = 'C:\ProgramData\gemini-cli\system-defaults.json' }
    @{ Agent = 'gemini_cli'; Id = 'gemini_cli.trusted_folders'; Path = '$profile\.gemini\trustedFolders.json' }
    @{ Agent = 'gemini_cli'; Id = 'gemini_cli.user_settings'; Path = '$profile\.gemini\settings.json' }
    @{ Agent = 'goose'; Id = 'goose.cli_logs'; Path = '$profile\AppData\Roaming\Block\goose\data\logs\cli' }
    @{ Agent = 'goose'; Id = 'goose.config'; Path = '$profile\AppData\Roaming\Block\goose\config\config.yaml' }
    @{ Agent = 'goose'; Id = 'goose.desktop_log'; Path = '$profile\AppData\Roaming\Block\goose\logs\main.log' }
    @{ Agent = 'goose'; Id = 'goose.permissions'; Path = '$profile\AppData\Roaming\Block\goose\config\permission.yaml' }
    @{ Agent = 'goose'; Id = 'goose.permissions'; Path = '$profile\AppData\Roaming\Block\goose\config\permissions\tool_permissions.json' }
    @{ Agent = 'goose'; Id = 'goose.prompts'; Path = '$profile\AppData\Roaming\Block\goose\config\prompts' }
    @{ Agent = 'goose'; Id = 'goose.secrets'; Path = '$profile\AppData\Roaming\Block\goose\config\secrets.yaml' }
    @{ Agent = 'goose'; Id = 'goose.server_logs'; Path = '$profile\AppData\Roaming\Block\goose\data\logs\server' }
    @{ Agent = 'goose'; Id = 'goose.sessions_db_windows'; Path = '$profile\AppData\Roaming\Block\goose\data\sessions\sessions.db' }
    @{ Agent = 'goose'; Id = 'goose.sessions_db_windows'; Path = '$profile\AppData\Roaming\Block\goose\data\sessions\sessions.db-shm' }
    @{ Agent = 'goose'; Id = 'goose.sessions_db_windows'; Path = '$profile\AppData\Roaming\Block\goose\data\sessions\sessions.db-wal' }
    @{ Agent = 'goose'; Id = 'goose.sessions_jsonl_legacy'; Path = '$profile\AppData\Roaming\Block\goose\data\sessions' }
    @{ Agent = 'hermes'; Id = 'hermes.auth'; Path = '$profile\.hermes\auth.json' }
    @{ Agent = 'hermes'; Id = 'hermes.config'; Path = '$profile\.hermes\config.yaml' }
    @{ Agent = 'hermes'; Id = 'hermes.cron'; Path = '$profile\.hermes\cron' }
    @{ Agent = 'hermes'; Id = 'hermes.env'; Path = '$profile\.hermes\.env' }
    @{ Agent = 'hermes'; Id = 'hermes.logs'; Path = '$profile\.hermes\logs\errors.log' }
    @{ Agent = 'hermes'; Id = 'hermes.logs'; Path = '$profile\.hermes\logs\gateway.log' }
    @{ Agent = 'hermes'; Id = 'hermes.memories'; Path = '$profile\.hermes\memories\MEMORY.md' }
    @{ Agent = 'hermes'; Id = 'hermes.memories'; Path = '$profile\.hermes\memories\USER.md' }
    @{ Agent = 'hermes'; Id = 'hermes.profiles'; Path = '$profile\.hermes\profiles' }
    @{ Agent = 'hermes'; Id = 'hermes.sandboxes'; Path = '$profile\.hermes\sandboxes' }
    @{ Agent = 'hermes'; Id = 'hermes.sessions_dir'; Path = '$profile\.hermes\sessions' }
    @{ Agent = 'hermes'; Id = 'hermes.skills'; Path = '$profile\.hermes\skills' }
    @{ Agent = 'hermes'; Id = 'hermes.soul'; Path = '$profile\.hermes\SOUL.md' }
    @{ Agent = 'hermes'; Id = 'hermes.state_db'; Path = '$profile\.hermes\state.db' }
    @{ Agent = 'hermes'; Id = 'hermes.state_db'; Path = '$profile\.hermes\state.db-shm' }
    @{ Agent = 'hermes'; Id = 'hermes.state_db'; Path = '$profile\.hermes\state.db-wal' }
    @{ Agent = 'jetbrains_ai'; Id = 'jetbrains_ai.aia_task_history'; Path = '$profile\AppData\Roaming\JetBrains' }
    @{ Agent = 'jetbrains_ai'; Id = 'jetbrains_ai.base_directories'; Path = '$profile\AppData\Local\JetBrains' }
    @{ Agent = 'jetbrains_ai'; Id = 'jetbrains_ai.base_directories'; Path = '$profile\AppData\Roaming\JetBrains' }
    @{ Agent = 'jetbrains_ai'; Id = 'jetbrains_ai.ide_logs'; Path = '$profile\AppData\Local\JetBrains' }
    @{ Agent = 'jetbrains_ai'; Id = 'jetbrains_ai.log_data'; Path = '$profile\AppData\Local\JetBrains' }
    @{ Agent = 'jetbrains_ai'; Id = 'jetbrains_ai.password_safe'; Path = '$profile\AppData\Roaming\JetBrains' }
    @{ Agent = 'junie'; Id = 'junie.allowlist'; Path = '$profile\.junie\allowlist.json' }
    @{ Agent = 'junie'; Id = 'junie.cli_sessions'; Path = '$profile\.junie\sessions' }
    @{ Agent = 'junie'; Id = 'junie.home_config'; Path = '$profile\.junie\AGENTS.md' }
    @{ Agent = 'junie'; Id = 'junie.home_config'; Path = '$profile\.junie\config.json' }
    @{ Agent = 'junie'; Id = 'junie.home_config'; Path = '$profile\.junie\settings.json' }
    @{ Agent = 'junie'; Id = 'junie.jcp_outbox'; Path = '$profile\AppData\Local\JetBrains' }
    @{ Agent = 'junie'; Id = 'junie.matterhorn_project_logs'; Path = '$profile\AppData\Local\JetBrains' }
    @{ Agent = 'junie'; Id = 'junie.plugin_install_evidence'; Path = '$profile\AppData\Roaming\JetBrains' }
    @{ Agent = 'junie'; Id = 'junie.trust_and_auth_key'; Path = '$profile\.junie\trust' }
    @{ Agent = 'junie'; Id = 'junie.trust_and_auth_key'; Path = '$profile\.junie\trust\authentication-key' }
    @{ Agent = 'kilo_code'; Id = 'kilo_code.cli_db'; Path = '$profile\.local\share\kilo\kilo.db' }
    @{ Agent = 'kilo_code'; Id = 'kilo_code.cli_db'; Path = '$profile\.local\share\kilo\kilo.db-shm' }
    @{ Agent = 'kilo_code'; Id = 'kilo_code.cli_db'; Path = '$profile\.local\share\kilo\kilo.db-wal' }
    @{ Agent = 'kilo_code'; Id = 'kilo_code.extension_id_legacy_tree'; Path = '$profile\.vscode-server\data\User\globalStorage\kilocode.kilo-code\tasks' }
    @{ Agent = 'kilo_code'; Id = 'kilo_code.extension_id_legacy_tree'; Path = '$profile\AppData\Roaming\Code\User\globalStorage\kilocode.kilo-code\tasks' }
    @{ Agent = 'kilo_code'; Id = 'kilo_code.settings'; Path = '$profile\AppData\Roaming\Code\User\globalStorage\kilocode.kilo-code\settings\custom_modes.yaml' }
    @{ Agent = 'kiro'; Id = 'kiro.cli_log'; Path = '$profile\AppData\Local\Temp\kiro-log\logs\kiro-chat.log' }
    @{ Agent = 'kiro'; Id = 'kiro.cli_session_database'; Path = '$profile\.kiro' }
    @{ Agent = 'kiro'; Id = 'kiro.cli_session_files'; Path = '$profile\.kiro\sessions\cli' }
    @{ Agent = 'kiro'; Id = 'kiro.cli_settings'; Path = '$profile\.kiro\settings\cli.json' }
    @{ Agent = 'kiro'; Id = 'kiro.ide_legacy_global_storage'; Path = '$profile\AppData\Roaming\Kiro\User\globalStorage\kiro.kiroagent' }
    @{ Agent = 'kiro'; Id = 'kiro.ide_session_files'; Path = '$profile\.kiro\sessions' }
    @{ Agent = 'kiro'; Id = 'kiro.managed_settings'; Path = 'C:\ProgramData\Kiro\managed-settings.json' }
    @{ Agent = 'kiro'; Id = 'kiro.mcp_config_user'; Path = '$profile\.kiro\settings\mcp.json' }
    @{ Agent = 'kiro'; Id = 'kiro.permissions_user'; Path = '$profile\.kiro\settings\permissions.yaml' }
    @{ Agent = 'kiro'; Id = 'kiro.permissions_workspace'; Path = '$profile\.kiro\workspace-roots' }
    @{ Agent = 'kiro'; Id = 'kiro.steering_user'; Path = '$profile\.kiro\steering' }
    @{ Agent = 'kiro'; Id = 'kiro.steering_user'; Path = '$profile\.kiro\steering\AGENTS.md' }
    @{ Agent = 'lmstudio'; Id = 'lmstudio.cli_and_server'; Path = '$profile\.lmstudio\bin\lms' }
    @{ Agent = 'lmstudio'; Id = 'lmstudio.cli_and_server'; Path = '$profile\.lmstudio\bin\lms.exe' }
    @{ Agent = 'lmstudio'; Id = 'lmstudio.conversations'; Path = '$profile\.lmstudio\conversations' }
    @{ Agent = 'lmstudio'; Id = 'lmstudio.hub_downloads'; Path = '$profile\.lmstudio\hub' }
    @{ Agent = 'lmstudio'; Id = 'lmstudio.mcp_config'; Path = '$profile\.lmstudio\mcp.json' }
    @{ Agent = 'lmstudio'; Id = 'lmstudio.models'; Path = '$profile\.lmstudio\models' }
    @{ Agent = 'lmstudio'; Id = 'lmstudio.presets'; Path = '$profile\.lmstudio\config-presets' }
    @{ Agent = 'ollama'; Id = 'ollama.app_chat_database'; Path = '$profile\.ollama\db.sqlite' }
    @{ Agent = 'ollama'; Id = 'ollama.app_chat_database'; Path = '$profile\.ollama\db.sqlite-shm' }
    @{ Agent = 'ollama'; Id = 'ollama.app_chat_database'; Path = '$profile\.ollama\db.sqlite-wal' }
    @{ Agent = 'ollama'; Id = 'ollama.app_chat_database'; Path = '$profile\AppData\Local\Ollama\db.sqlite' }
    @{ Agent = 'ollama'; Id = 'ollama.app_chat_database'; Path = '$profile\AppData\Local\Ollama\db.sqlite-wal' }
    @{ Agent = 'ollama'; Id = 'ollama.app_config'; Path = '$profile\.ollama\config.json' }
    @{ Agent = 'ollama'; Id = 'ollama.app_config'; Path = '$profile\AppData\Local\Ollama\config.json' }
    @{ Agent = 'ollama'; Id = 'ollama.backup_dir'; Path = '$profile\.ollama\backup' }
    @{ Agent = 'ollama'; Id = 'ollama.cli_config'; Path = '$profile\.ollama\config.json' }
    @{ Agent = 'ollama'; Id = 'ollama.cli_config'; Path = '$profile\.ollama\config\config.json' }
    @{ Agent = 'ollama'; Id = 'ollama.cli_prompt_history'; Path = '$profile\.ollama\history' }
    @{ Agent = 'ollama'; Id = 'ollama.env_overrides'; Path = '$profile\.bashrc' }
    @{ Agent = 'ollama'; Id = 'ollama.env_overrides'; Path = '$profile\.zshrc' }
    @{ Agent = 'ollama'; Id = 'ollama.logs'; Path = '$profile\.ollama\logs\app.log' }
    @{ Agent = 'ollama'; Id = 'ollama.logs'; Path = '$profile\.ollama\logs\server.log' }
    @{ Agent = 'ollama'; Id = 'ollama.logs'; Path = '$profile\AppData\Local\Ollama\app.log' }
    @{ Agent = 'ollama'; Id = 'ollama.logs'; Path = '$profile\AppData\Local\Ollama\server-' }
    @{ Agent = 'ollama'; Id = 'ollama.logs'; Path = '$profile\AppData\Local\Ollama\server.log' }
    @{ Agent = 'ollama'; Id = 'ollama.logs'; Path = '$profile\AppData\Local\Ollama\upgrade.log' }
    @{ Agent = 'ollama'; Id = 'ollama.model_blobs'; Path = '$profile\.ollama\models\blobs\sha256-' }
    @{ Agent = 'ollama'; Id = 'ollama.model_manifests'; Path = '$profile\.ollama\models\manifests' }
    @{ Agent = 'ollama'; Id = 'ollama.private_key'; Path = '$profile\.ollama\id_ed25519' }
    @{ Agent = 'ollama'; Id = 'ollama.private_key'; Path = '$profile\.ollama\id_ed25519.pub' }
    @{ Agent = 'opencode'; Id = 'opencode.auth'; Path = '$profile\AppData\Local\opencode\auth.json' }
    @{ Agent = 'opencode'; Id = 'opencode.db'; Path = '$profile\.local\share\opencode\opencode.db' }
    @{ Agent = 'opencode'; Id = 'opencode.db'; Path = '$profile\.local\share\opencode\opencode.db-shm' }
    @{ Agent = 'opencode'; Id = 'opencode.db'; Path = '$profile\.local\share\opencode\opencode.db-wal' }
    @{ Agent = 'opencode'; Id = 'opencode.log'; Path = '$profile\.local\share\opencode\log' }
    @{ Agent = 'opencode'; Id = 'opencode.managed_config'; Path = 'C:\ProgramData\opencode' }
    @{ Agent = 'pi'; Id = 'pi.auth'; Path = '$profile\.pi\agent\auth.json' }
    @{ Agent = 'pi'; Id = 'pi.bin'; Path = '$profile\.pi\agent\bin' }
    @{ Agent = 'pi'; Id = 'pi.bin'; Path = '$profile\.pi\agent\themes' }
    @{ Agent = 'pi'; Id = 'pi.bin'; Path = '$profile\.pi\server' }
    @{ Agent = 'pi'; Id = 'pi.debug_log'; Path = '$profile\.pi\agent\pi-debug.log' }
    @{ Agent = 'pi'; Id = 'pi.extensions'; Path = '$profile\.pi\agent\extensions' }
    @{ Agent = 'pi'; Id = 'pi.extensions'; Path = '$profile\.pi\agent\tools' }
    @{ Agent = 'pi'; Id = 'pi.models'; Path = '$profile\.pi\agent\models.json' }
    @{ Agent = 'pi'; Id = 'pi.prompts'; Path = '$profile\.pi\agent\prompts' }
    @{ Agent = 'pi'; Id = 'pi.sessions'; Path = '$profile\.pi\agent\sessions\--' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.channels_scheduled_tasks'; Path = '$profile\.qwen\channels\cron.json' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.channels_scheduled_tasks'; Path = '$profile\.qwen\channels\daemon' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.channels_scheduled_tasks'; Path = '$profile\.qwen\channels\service.pid' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.channels_scheduled_tasks'; Path = '$profile\.qwen\channels\sessions.json' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.conversation_transcript'; Path = '$profile\.qwen\projects' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.debug_logs'; Path = '$profile\.qwen\debug' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.file_history_backups'; Path = '$profile\.qwen\file-history' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.install_evidence'; Path = '$profile\.qwen\bin' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.install_evidence'; Path = '$profile\.qwen\installation_id' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.install_evidence'; Path = '$profile\.qwen\source.json' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.install_evidence'; Path = '$profile\.qwen\updates\npm' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.mcp_approvals'; Path = '$profile\.qwen\mcpApprovals.json' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.mcp_oauth_tokens'; Path = '$profile\.qwen\mcp-oauth-tokens-v2.json' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.mcp_oauth_tokens'; Path = '$profile\.qwen\mcp-oauth-tokens.json' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.plan_files'; Path = '$profile\.qwen\plans' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.project_temp_spill'; Path = '$profile\.qwen\tmp' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.prompt_history_log'; Path = '$profile\.qwen\tmp' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.prompt_terminal_ledger'; Path = '$profile\.qwen\projects' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.qwen_oauth_credentials'; Path = '$profile\.qwen\oauth_creds.json' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.qwen_oauth_credentials'; Path = '$profile\.qwen\oauth_creds.lock' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.session_registry'; Path = '$profile\.qwen\sessions' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.session_sidecars'; Path = '$profile\.qwen\projects' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.shell_history'; Path = '$profile\.qwen\tmp' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.subagent_transcripts'; Path = '$profile\.qwen\projects' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.system_settings'; Path = 'C:\ProgramData\qwen-code\settings.json' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.system_settings'; Path = 'C:\ProgramData\qwen-code\system-defaults.json' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.trusted_folders'; Path = '$profile\.qwen\trustedFolders.json' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.usage_history'; Path = '$profile\.qwen\usage_record.jsonl' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.user_extension_points'; Path = '$profile\.agents\skills' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.user_extension_points'; Path = '$profile\.qwen\agents' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.user_extension_points'; Path = '$profile\.qwen\commands' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.user_extension_points'; Path = '$profile\.qwen\extensions' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.user_extension_points'; Path = '$profile\.qwen\locales' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.user_extension_points'; Path = '$profile\.qwen\rules' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.user_extension_points'; Path = '$profile\.qwen\skills' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.user_extension_points'; Path = '$profile\.qwen\workflows' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.user_instructions'; Path = '$profile\.qwen\AGENTS.md' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.user_instructions'; Path = '$profile\.qwen\QWEN.md' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.user_instructions'; Path = '$profile\.qwen\memory.md' }
    @{ Agent = 'qwen_code'; Id = 'qwen_code.user_settings'; Path = '$profile\.qwen\settings.json' }
    @{ Agent = 'roo_code'; Id = 'roo_code.checkpoints'; Path = '$profile\AppData\Roaming\Code - Insiders\User\globalStorage\rooveterinaryinc.roo-cline\checkpoints' }
    @{ Agent = 'roo_code'; Id = 'roo_code.checkpoints'; Path = '$profile\AppData\Roaming\Code - Insiders\User\globalStorage\rooveterinaryinc.roo-cline\tasks' }
    @{ Agent = 'roo_code'; Id = 'roo_code.checkpoints'; Path = '$profile\AppData\Roaming\Code\User\globalStorage\rooveterinaryinc.roo-cline\checkpoints' }
    @{ Agent = 'roo_code'; Id = 'roo_code.checkpoints'; Path = '$profile\AppData\Roaming\Code\User\globalStorage\rooveterinaryinc.roo-cline\tasks' }
    @{ Agent = 'roo_code'; Id = 'roo_code.checkpoints'; Path = '$profile\AppData\Roaming\Cursor\User\globalStorage\rooveterinaryinc.roo-cline\checkpoints' }
    @{ Agent = 'roo_code'; Id = 'roo_code.checkpoints'; Path = '$profile\AppData\Roaming\Cursor\User\globalStorage\rooveterinaryinc.roo-cline\tasks' }
    @{ Agent = 'roo_code'; Id = 'roo_code.checkpoints'; Path = '$profile\AppData\Roaming\Kiro\User\globalStorage\rooveterinaryinc.roo-cline\checkpoints' }
    @{ Agent = 'roo_code'; Id = 'roo_code.checkpoints'; Path = '$profile\AppData\Roaming\Kiro\User\globalStorage\rooveterinaryinc.roo-cline\tasks' }
    @{ Agent = 'roo_code'; Id = 'roo_code.checkpoints'; Path = '$profile\AppData\Roaming\Positron\User\globalStorage\rooveterinaryinc.roo-cline\checkpoints' }
    @{ Agent = 'roo_code'; Id = 'roo_code.checkpoints'; Path = '$profile\AppData\Roaming\Positron\User\globalStorage\rooveterinaryinc.roo-cline\tasks' }
    @{ Agent = 'roo_code'; Id = 'roo_code.checkpoints'; Path = '$profile\AppData\Roaming\Trae\User\globalStorage\rooveterinaryinc.roo-cline\checkpoints' }
    @{ Agent = 'roo_code'; Id = 'roo_code.checkpoints'; Path = '$profile\AppData\Roaming\Trae\User\globalStorage\rooveterinaryinc.roo-cline\tasks' }
    @{ Agent = 'roo_code'; Id = 'roo_code.checkpoints'; Path = '$profile\AppData\Roaming\VSCodium\User\globalStorage\rooveterinaryinc.roo-cline\checkpoints' }
    @{ Agent = 'roo_code'; Id = 'roo_code.checkpoints'; Path = '$profile\AppData\Roaming\VSCodium\User\globalStorage\rooveterinaryinc.roo-cline\tasks' }
    @{ Agent = 'roo_code'; Id = 'roo_code.checkpoints'; Path = '$profile\AppData\Roaming\Windsurf\User\globalStorage\rooveterinaryinc.roo-cline\checkpoints' }
    @{ Agent = 'roo_code'; Id = 'roo_code.checkpoints'; Path = '$profile\AppData\Roaming\Windsurf\User\globalStorage\rooveterinaryinc.roo-cline\tasks' }
    @{ Agent = 'roo_code'; Id = 'roo_code.extension_id'; Path = '$profile\AppData\Roaming\Code - Insiders\User\globalStorage\rooveterinaryinc.roo-cline' }
    @{ Agent = 'roo_code'; Id = 'roo_code.extension_id'; Path = '$profile\AppData\Roaming\Code\User\globalStorage\rooveterinaryinc.roo-cline' }
    @{ Agent = 'roo_code'; Id = 'roo_code.extension_id'; Path = '$profile\AppData\Roaming\Cursor\User\globalStorage\rooveterinaryinc.roo-cline' }
    @{ Agent = 'roo_code'; Id = 'roo_code.extension_id'; Path = '$profile\AppData\Roaming\Kiro\User\globalStorage\rooveterinaryinc.roo-cline' }
    @{ Agent = 'roo_code'; Id = 'roo_code.extension_id'; Path = '$profile\AppData\Roaming\Positron\User\globalStorage\rooveterinaryinc.roo-cline' }
    @{ Agent = 'roo_code'; Id = 'roo_code.extension_id'; Path = '$profile\AppData\Roaming\Trae\User\globalStorage\rooveterinaryinc.roo-cline' }
    @{ Agent = 'roo_code'; Id = 'roo_code.extension_id'; Path = '$profile\AppData\Roaming\VSCodium\User\globalStorage\rooveterinaryinc.roo-cline' }
    @{ Agent = 'roo_code'; Id = 'roo_code.extension_id'; Path = '$profile\AppData\Roaming\Windsurf\User\globalStorage\rooveterinaryinc.roo-cline' }
    @{ Agent = 'roo_code'; Id = 'roo_code.global_dirs'; Path = '$profile\.agents' }
    @{ Agent = 'roo_code'; Id = 'roo_code.global_dirs'; Path = '$profile\.roo' }
    @{ Agent = 'roo_code'; Id = 'roo_code.global_dirs'; Path = '$profile\.roo\rules' }
    @{ Agent = 'roo_code'; Id = 'roo_code.global_dirs'; Path = '$profile\.roo\rules-' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\Code - Insiders\User\globalStorage\rooveterinaryinc.roo-cline\cache' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\Code - Insiders\User\globalStorage\rooveterinaryinc.roo-cline\settings\custom_modes.yaml' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\Code - Insiders\User\globalStorage\rooveterinaryinc.roo-cline\settings\mcp_settings.json' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\Code\User\globalStorage\rooveterinaryinc.roo-cline\cache' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\Code\User\globalStorage\rooveterinaryinc.roo-cline\settings\custom_modes.yaml' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\Code\User\globalStorage\rooveterinaryinc.roo-cline\settings\mcp_settings.json' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\Cursor\User\globalStorage\rooveterinaryinc.roo-cline\cache' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\Cursor\User\globalStorage\rooveterinaryinc.roo-cline\settings\custom_modes.yaml' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\Cursor\User\globalStorage\rooveterinaryinc.roo-cline\settings\mcp_settings.json' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\Kiro\User\globalStorage\rooveterinaryinc.roo-cline\cache' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\Kiro\User\globalStorage\rooveterinaryinc.roo-cline\settings\custom_modes.yaml' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\Kiro\User\globalStorage\rooveterinaryinc.roo-cline\settings\mcp_settings.json' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\Positron\User\globalStorage\rooveterinaryinc.roo-cline\cache' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\Positron\User\globalStorage\rooveterinaryinc.roo-cline\settings\custom_modes.yaml' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\Positron\User\globalStorage\rooveterinaryinc.roo-cline\settings\mcp_settings.json' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\Trae\User\globalStorage\rooveterinaryinc.roo-cline\cache' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\Trae\User\globalStorage\rooveterinaryinc.roo-cline\settings\custom_modes.yaml' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\Trae\User\globalStorage\rooveterinaryinc.roo-cline\settings\mcp_settings.json' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\VSCodium\User\globalStorage\rooveterinaryinc.roo-cline\cache' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\VSCodium\User\globalStorage\rooveterinaryinc.roo-cline\settings\custom_modes.yaml' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\VSCodium\User\globalStorage\rooveterinaryinc.roo-cline\settings\mcp_settings.json' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\Windsurf\User\globalStorage\rooveterinaryinc.roo-cline\cache' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\Windsurf\User\globalStorage\rooveterinaryinc.roo-cline\settings\custom_modes.yaml' }
    @{ Agent = 'roo_code'; Id = 'roo_code.settings'; Path = '$profile\AppData\Roaming\Windsurf\User\globalStorage\rooveterinaryinc.roo-cline\settings\mcp_settings.json' }
    @{ Agent = 'roo_code'; Id = 'roo_code.tasks'; Path = '$profile\AppData\Roaming\Code - Insiders\User\globalStorage\rooveterinaryinc.roo-cline\tasks' }
    @{ Agent = 'roo_code'; Id = 'roo_code.tasks'; Path = '$profile\AppData\Roaming\Code\User\globalStorage\rooveterinaryinc.roo-cline\tasks' }
    @{ Agent = 'roo_code'; Id = 'roo_code.tasks'; Path = '$profile\AppData\Roaming\Cursor\User\globalStorage\rooveterinaryinc.roo-cline\tasks' }
    @{ Agent = 'roo_code'; Id = 'roo_code.tasks'; Path = '$profile\AppData\Roaming\Kiro\User\globalStorage\rooveterinaryinc.roo-cline\tasks' }
    @{ Agent = 'roo_code'; Id = 'roo_code.tasks'; Path = '$profile\AppData\Roaming\Positron\User\globalStorage\rooveterinaryinc.roo-cline\tasks' }
    @{ Agent = 'roo_code'; Id = 'roo_code.tasks'; Path = '$profile\AppData\Roaming\Trae\User\globalStorage\rooveterinaryinc.roo-cline\tasks' }
    @{ Agent = 'roo_code'; Id = 'roo_code.tasks'; Path = '$profile\AppData\Roaming\VSCodium\User\globalStorage\rooveterinaryinc.roo-cline\tasks' }
    @{ Agent = 'roo_code'; Id = 'roo_code.tasks'; Path = '$profile\AppData\Roaming\Windsurf\User\globalStorage\rooveterinaryinc.roo-cline\tasks' }
    @{ Agent = 'vscode'; Id = 'vscode.extension_dirs'; Path = '$profile\.cursor\extensions' }
    @{ Agent = 'vscode'; Id = 'vscode.extension_dirs'; Path = '$profile\.vscode-insiders\extensions' }
    @{ Agent = 'vscode'; Id = 'vscode.extension_dirs'; Path = '$profile\.vscode-server\extensions' }
    @{ Agent = 'vscode'; Id = 'vscode.extension_dirs'; Path = '$profile\.vscode\extensions' }
    @{ Agent = 'vscode'; Id = 'vscode.extension_dirs'; Path = '$profile\.windsurf\extensions' }
    @{ Agent = 'vscode'; Id = 'vscode.extension_install_evidence'; Path = '$profile\.vscode-server\extensions' }
    @{ Agent = 'vscode'; Id = 'vscode.extension_install_evidence'; Path = '$profile\.vscode\extensions' }
    @{ Agent = 'vscode'; Id = 'vscode.extension_install_evidence'; Path = '$profile\.vscode\extensions\extensions.json' }
    @{ Agent = 'vscode'; Id = 'vscode.extension_install_evidence'; Path = '$profile\.vscode\extensions\kilocode.kilo-code-' }
    @{ Agent = 'vscode'; Id = 'vscode.extension_install_evidence'; Path = '$profile\.vscode\extensions\rooveterinaryinc.roo-cline-' }
    @{ Agent = 'vscode'; Id = 'vscode.extension_install_evidence'; Path = '$profile\.vscode\extensions\saoudrizwan.claude-dev-' }
    @{ Agent = 'vscode'; Id = 'vscode.state_vscdb'; Path = '$profile\AppData\Roaming\Code\User\globalStorage\state.vscdb' }
    @{ Agent = 'vscode'; Id = 'vscode.state_vscdb'; Path = '$profile\AppData\Roaming\Code\User\globalStorage\state.vscdb-shm' }
    @{ Agent = 'vscode'; Id = 'vscode.state_vscdb'; Path = '$profile\AppData\Roaming\Code\User\globalStorage\state.vscdb-wal' }
    @{ Agent = 'vscode'; Id = 'vscode.user_data_roots'; Path = '$profile\.vscode-server\data\User\globalStorage' }
    @{ Agent = 'vscode'; Id = 'vscode.user_data_roots'; Path = '$profile\AppData\Roaming\Code\User\globalStorage' }
    @{ Agent = 'warp'; Id = 'warp.sqlite'; Path = '$profile\AppData\Local\warp\Warp\data\warp.sqlite' }
    @{ Agent = 'warp'; Id = 'warp.sqlite'; Path = '$profile\AppData\Local\warp\Warp\data\warp.sqlite-shm' }
    @{ Agent = 'warp'; Id = 'warp.sqlite'; Path = '$profile\AppData\Local\warp\Warp\data\warp.sqlite-wal' }
    @{ Agent = 'windsurf'; Id = 'windsurf.acp_registry'; Path = '$profile\.windsurf-next\acp\registry.json' }
    @{ Agent = 'windsurf'; Id = 'windsurf.acp_registry'; Path = '$profile\.windsurf\acp\registry.json' }
    @{ Agent = 'windsurf'; Id = 'windsurf.auth_credentials'; Path = '$profile\.codeium\config.json' }
    @{ Agent = 'windsurf'; Id = 'windsurf.auth_credentials'; Path = '$profile\AppData\Local\devin\credentials.toml' }
    @{ Agent = 'windsurf'; Id = 'windsurf.cascade_trajectories'; Path = '$profile\.codeium\windsurf-insiders\cascade' }
    @{ Agent = 'windsurf'; Id = 'windsurf.cascade_trajectories'; Path = '$profile\.codeium\windsurf-next\cascade' }
    @{ Agent = 'windsurf'; Id = 'windsurf.cascade_trajectories'; Path = '$profile\.codeium\windsurf\cascade' }
    @{ Agent = 'windsurf'; Id = 'windsurf.cascade_transcripts'; Path = '$profile\.devin\transcripts' }
    @{ Agent = 'windsurf'; Id = 'windsurf.cascade_transcripts'; Path = '$profile\.windsurf\transcripts' }
    @{ Agent = 'windsurf'; Id = 'windsurf.code_tracker_and_settings'; Path = '$profile\.codeium\user_settings.pb' }
    @{ Agent = 'windsurf'; Id = 'windsurf.code_tracker_and_settings'; Path = '$profile\.codeium\windsurf\code_tracker' }
    @{ Agent = 'windsurf'; Id = 'windsurf.code_tracker_and_settings'; Path = '$profile\.codeium\windsurf\installation_id' }
    @{ Agent = 'windsurf'; Id = 'windsurf.code_tracker_and_settings'; Path = '$profile\.codeium\windsurf\user_settings.pb' }
    @{ Agent = 'windsurf'; Id = 'windsurf.embedding_database'; Path = '$profile\.codeium\windsurf\database' }
    @{ Agent = 'windsurf'; Id = 'windsurf.global_rules'; Path = '$profile\.codeium\windsurf-insiders\memories\global_rules.md' }
    @{ Agent = 'windsurf'; Id = 'windsurf.global_rules'; Path = '$profile\.codeium\windsurf-next\memories\global_rules.md' }
    @{ Agent = 'windsurf'; Id = 'windsurf.global_rules'; Path = '$profile\.codeium\windsurf\memories\global_rules.md' }
    @{ Agent = 'windsurf'; Id = 'windsurf.ide_global_state_vscdb'; Path = '$profile\AppData\Roaming\Devin\User\globalStorage\state.vscdb' }
    @{ Agent = 'windsurf'; Id = 'windsurf.ide_global_state_vscdb'; Path = '$profile\AppData\Roaming\Devin\User\globalStorage\state.vscdb-shm' }
    @{ Agent = 'windsurf'; Id = 'windsurf.ide_global_state_vscdb'; Path = '$profile\AppData\Roaming\Devin\User\globalStorage\state.vscdb-wal' }
    @{ Agent = 'windsurf'; Id = 'windsurf.ide_global_state_vscdb'; Path = '$profile\AppData\Roaming\Windsurf - Next\User\globalStorage\state.vscdb' }
    @{ Agent = 'windsurf'; Id = 'windsurf.ide_global_state_vscdb'; Path = '$profile\AppData\Roaming\Windsurf - Next\User\globalStorage\state.vscdb-shm' }
    @{ Agent = 'windsurf'; Id = 'windsurf.ide_global_state_vscdb'; Path = '$profile\AppData\Roaming\Windsurf - Next\User\globalStorage\state.vscdb-wal' }
    @{ Agent = 'windsurf'; Id = 'windsurf.ide_global_state_vscdb'; Path = '$profile\AppData\Roaming\Windsurf Insiders\User\globalStorage\state.vscdb' }
    @{ Agent = 'windsurf'; Id = 'windsurf.ide_global_state_vscdb'; Path = '$profile\AppData\Roaming\Windsurf Insiders\User\globalStorage\state.vscdb-shm' }
    @{ Agent = 'windsurf'; Id = 'windsurf.ide_global_state_vscdb'; Path = '$profile\AppData\Roaming\Windsurf Insiders\User\globalStorage\state.vscdb-wal' }
    @{ Agent = 'windsurf'; Id = 'windsurf.ide_global_state_vscdb'; Path = '$profile\AppData\Roaming\Windsurf\User\globalStorage\state.vscdb' }
    @{ Agent = 'windsurf'; Id = 'windsurf.ide_global_state_vscdb'; Path = '$profile\AppData\Roaming\Windsurf\User\globalStorage\state.vscdb-shm' }
    @{ Agent = 'windsurf'; Id = 'windsurf.ide_global_state_vscdb'; Path = '$profile\AppData\Roaming\Windsurf\User\globalStorage\state.vscdb-wal' }
    @{ Agent = 'windsurf'; Id = 'windsurf.ide_user_data'; Path = '$profile\AppData\Roaming\Devin\User\settings.json' }
    @{ Agent = 'windsurf'; Id = 'windsurf.ide_user_data'; Path = '$profile\AppData\Roaming\Windsurf\User\keybindings.json' }
    @{ Agent = 'windsurf'; Id = 'windsurf.ide_user_data'; Path = '$profile\AppData\Roaming\Windsurf\User\settings.json' }
    @{ Agent = 'windsurf'; Id = 'windsurf.ide_user_data'; Path = '$profile\AppData\Roaming\Windsurf\argv.json' }
    @{ Agent = 'windsurf'; Id = 'windsurf.ide_workspace_state_vscdb'; Path = '$profile\AppData\Roaming\Windsurf\User\workspaceStorage' }
    @{ Agent = 'windsurf'; Id = 'windsurf.implicit_trajectories'; Path = '$profile\.codeium\windsurf\implicit' }
    @{ Agent = 'windsurf'; Id = 'windsurf.language_server_binaries_and_logs'; Path = '$profile\.codeium' }
    @{ Agent = 'windsurf'; Id = 'windsurf.language_server_binaries_and_logs'; Path = '$profile\.windsurf-server\data\logs' }
    @{ Agent = 'windsurf'; Id = 'windsurf.language_server_binaries_and_logs'; Path = '$profile\AppData\Local\Programs\Windsurf' }
    @{ Agent = 'windsurf'; Id = 'windsurf.language_server_binaries_and_logs'; Path = 'C:\Program Files\Windsurf' }
    @{ Agent = 'windsurf'; Id = 'windsurf.memories'; Path = '$profile\.codeium\windsurf-insiders\memories' }
    @{ Agent = 'windsurf'; Id = 'windsurf.memories'; Path = '$profile\.codeium\windsurf-next\memories' }
    @{ Agent = 'windsurf'; Id = 'windsurf.memories'; Path = '$profile\.codeium\windsurf\memories' }
    @{ Agent = 'windsurf'; Id = 'windsurf.plugin_log'; Path = '$profile\.codeium\codeium.log' }
    @{ Agent = 'windsurf'; Id = 'windsurf.system_config'; Path = 'C:\ProgramData\Windsurf\hooks.json' }
    @{ Agent = 'windsurf'; Id = 'windsurf.system_config'; Path = 'C:\ProgramData\Windsurf\rules' }
    @{ Agent = 'windsurf'; Id = 'windsurf.system_config'; Path = 'C:\ProgramData\Windsurf\skills' }
    @{ Agent = 'windsurf'; Id = 'windsurf.system_config'; Path = 'C:\ProgramData\Windsurf\workflows' }
    @{ Agent = 'windsurf'; Id = 'windsurf.worktrees'; Path = '$profile\.devin\worktrees' }
    @{ Agent = 'windsurf'; Id = 'windsurf.worktrees'; Path = '$profile\.windsurf\worktrees' }
    @{ Agent = 'zed'; Id = 'zed.extensions'; Path = '$profile\AppData\Local\Zed\debug_adapters' }
    @{ Agent = 'zed'; Id = 'zed.extensions'; Path = '$profile\AppData\Local\Zed\extensions' }
    @{ Agent = 'zed'; Id = 'zed.extensions'; Path = '$profile\AppData\Local\Zed\external_agents' }
    @{ Agent = 'zed'; Id = 'zed.extensions'; Path = '$profile\AppData\Local\Zed\prompt_overrides' }
    @{ Agent = 'zed'; Id = 'zed.logs'; Path = '$profile\AppData\Local\Zed\logs' }
    @{ Agent = 'zed'; Id = 'zed.sidebar_threads'; Path = '$profile\AppData\Local\Zed\db\0-' }
    @{ Agent = 'zed'; Id = 'zed.threads_db'; Path = '$profile\AppData\Local\Zed\threads\threads.db' }
    @{ Agent = 'zed'; Id = 'zed.threads_db'; Path = '$profile\AppData\Local\Zed\threads\threads.db-shm' }
    @{ Agent = 'zed'; Id = 'zed.threads_db'; Path = '$profile\AppData\Local\Zed\threads\threads.db-wal' }
)

$found = @{}
$errors = @()
foreach ($target in $targets) {
    $paths = @()
    if ($target.Path -like '$profile*') {
        foreach ($profileDir in $profiles) {
            $paths += ($target.Path -replace '^\$profile', [regex]::Escape($profileDir) -replace '\\\\', '\')
        }
    } else {
        $paths += $target.Path
    }
    foreach ($candidate in $paths) {
        try {
            if (Test-Path -LiteralPath $candidate) {
                $count = 1
                if ((Get-Item -LiteralPath $candidate).PSIsContainer) {
                    $count = (Get-ChildItem -LiteralPath $candidate -Recurse -File -ErrorAction SilentlyContinue |
                        Measure-Object).Count
                }
                if (-not $found.ContainsKey($target.Agent)) { $found[$target.Agent] = 0 }
                $found[$target.Agent] += $count
            }
        } catch {
            # A path that cannot be read is reported rather than skipped: an
            # access denial is a different answer from an absent directory, and
            # collapsing the two is how a used agent looks unused.
            $errors += ($candidate + ': ' + $_.Exception.Message)
        }
    }
}

if ($found.Count -eq 0) {
    Write-Output 'no agent artifacts found at any catalogued Windows path'
} else {
    foreach ($agent in ($found.Keys | Sort-Object)) {
        Write-Output ($agent + ': ' + $found[$agent] + ' file(s)')
    }
}
foreach ($problem in ($errors | Sort-Object -Unique)) {
    Write-Output ('unreadable ' + $problem)
}
