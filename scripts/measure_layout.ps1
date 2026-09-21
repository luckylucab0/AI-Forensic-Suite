# Measure which of an agent's catalogued paths actually exist on this machine, on Windows.
# Read only, and names only.
#
# The companion to measure_layout.sh, and it exists separately for the reason the two
# collectors do: a single file with no modules, so it runs on a stock Windows PowerShell
# 5.1 without anything being installed first.
#
# Why this exists. More than a hundred catalogue entries rest on somebody else's reading of
# a closed-source product rather than on a vendor page, and the Windows spellings are the
# weakest of those: several were derived from a macOS layout rather than observed. A path
# that was derived wrongly is the worst defect this catalogue can carry, because a
# collection searches it, finds nothing, and an analyst concludes the agent was never used.
#
# The probe list is generated from catalog/ by scripts/gen_layout_probes.py and every line
# of it names the entries it came from, so an ABSENT line says something exact: these
# entries claim this location and this machine does not have it. The first version of this
# script carried a list typed by hand, which probed a path in no entry and missed two that
# were in one.
#
# What it takes, and what it refuses to take. Directory names, file names, sizes and
# modification times. Never the content of a file. Paths are printed with the profile
# directory replaced by a placeholder so the user name does not travel, but some file and
# directory names carry project names: read the output before sending it and delete
# whatever should not be shared. A gap recorded as a gap is worth more than a guess.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\measure_layout.ps1 > layout.txt
#   powershell -ExecutionPolicy Bypass -File scripts\measure_layout.ps1 -Family cursor > layout.txt
#   powershell -ExecutionPolicy Bypass -File scripts\measure_layout.ps1 -List

[CmdletBinding()]
param(
    [string] $Family = 'all',
    [int] $Depth = 4,
    [switch] $List
)

$ErrorActionPreference = 'Continue'

$profileRoot = $env:USERPROFILE

function Shorten($text) {
    if (-not $text) { return $text }
    # A literal replacement rather than a regular expression: a profile path contains
    # backslashes, which a pattern would read as escapes.
    return $text.Replace($profileRoot, '%USERPROFILE%')
}

function Write-Section($name) {
    Write-Output ''
    Write-Output ("===== " + $name)
}

# One probe, to a bounded depth, names and metadata only. An absent path is reported rather
# than skipped, because telling a wrong path apart from an uninstalled product is the whole
# purpose of this measurement, and the ids say which entries the absence is about.
function Write-Tree($path, $ids, $how) {
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Output ("ABSENT   " + (Shorten $path) + " [" + $ids + "]")
        return
    }
    Write-Output ("PRESENT  " + (Shorten $path) + " [" + $ids + "]")
    # A path some other probe already walks is answered and not walked again, so no tree
    # appears twice in the output.
    if ($how -ne 'walk') { return }
    $item = Get-Item -LiteralPath $path -Force
    if (-not $item.PSIsContainer) {
        Write-Output ("  {0} {1,10}  {2}" -f 'f', $item.Length, (Shorten $item.FullName))
        if ($item.VersionInfo -and $item.VersionInfo.ProductVersion) {
            Write-Output ("VERSION  {0} = {1}" -f (Shorten $path), $item.VersionInfo.ProductVersion)
        }
        return
    }
    $rootDepth = ($item.FullName.TrimEnd('\').Split('\')).Count
    Get-ChildItem -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { (($_.FullName.Split('\')).Count - $rootDepth) -le $Depth } |
        Sort-Object FullName |
        ForEach-Object {
            if ($_.PSIsContainer) { $kind = 'd'; $size = '-' }
            else { $kind = 'f'; $size = $_.Length }
            Write-Output ("  {0} {1,10}  {2}" -f $kind, $size, (Shorten $_.FullName))
        }
}

# The packaged-application and vendor directories a product actually ships under, found by
# name rather than assumed. On Windows the packaged name carries a publisher hash that no
# vendor page states, so this is the only way to learn it.
function Write-Identifiers($words) {
    $parents = @(
        (Join-Path $env:LOCALAPPDATA 'Packages'),
        (Join-Path $env:LOCALAPPDATA 'Programs'),
        $env:LOCALAPPDATA,
        $env:APPDATA,
        $profileRoot
    )
    foreach ($word in $words) {
        foreach ($parent in $parents) {
            if (-not $parent) { continue }
            if (-not (Test-Path -LiteralPath $parent)) { continue }
            Get-ChildItem -LiteralPath $parent -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like ("*" + $word + "*") } |
                ForEach-Object { Write-Output (Shorten $_.FullName) }
        }
    }
}

function Measure-Family($name) {
    if (-not $Probes.ContainsKey($name)) {
        Write-Error ("unknown family: " + $name)
        return
    }
    Write-Section $name
    foreach ($line in $Probes[$name]) {
        # The ids come first on the line and the path second, so a path containing a space
        # survives the split: only the first field is taken off.
        $parts = $line -split ' ', 3
        $how = $parts[0]
        $ids = $parts[1]
        $path = [System.Environment]::ExpandEnvironmentVariables($parts[2])
        if ($path -match '[\*\?]') {
            # A pattern whose wildcard is in the file name. Resolve-Path expands it and
            # says nothing when it matches nothing, so the pattern itself is reported.
            $matched = Resolve-Path -Path $path -ErrorAction SilentlyContinue
            if ($matched) {
                foreach ($one in $matched) { Write-Tree $one.Path $ids $how }
            }
            else {
                Write-Output ("ABSENT   " + (Shorten $path) + " [" + $ids + "]")
            }
            continue
        }
        Write-Tree $path $ids $how
    }
    if ($Tokens.ContainsKey($name)) {
        Write-Section ($name + ": identifiers found by name")
        Write-Identifiers $Tokens[$name]
    }
}

# BEGIN generated probes -- scripts/gen_layout_probes.py
# Regenerate with: uv run python scripts/gen_layout_probes.py
#
# One line per probe: walk or check, the catalogue entries that claim it, then
# the path. A walk lists the tree below it, a check answers present or absent
# for a path some other walk already covers. An environment variable in percent
# signs is expanded at run time.
#
# Not probed from this catalogue, and the reasons are in the generator's docstring:
#     27 path(s) a registry key
#    361 path(s) anchored in a working copy
#    336 path(s) anchored in an environment variable
#   1460 path(s) for the other platform
$Probes = @{
    'amazonq' = @(
        'walk amazonq.cli_settings,amazonq.cli_state_database %LOCALAPPDATA%\amazon-q'
        'check amazonq.cli_state_database %LOCALAPPDATA%\amazon-q\data.sqlite3'
        'check amazonq.cli_state_database %LOCALAPPDATA%\amazon-q\data.sqlite3-shm'
        'check amazonq.cli_state_database %LOCALAPPDATA%\amazon-q\data.sqlite3-wal'
        'check amazonq.cli_settings %LOCALAPPDATA%\amazon-q\settings.json'
        'walk amazonq.cli_logs %TEMP%\amazon-q\logs\*.log'
        'walk amazonq.cli_logs %TEMP%\qlog\*.log'
        'walk amazonq.cli_checkpoints,amazonq.cli_mcp_config,amazonq.cli_prompt_history,amazonq.ide_agent_config,amazonq.legacy_profiles_and_context %USERPROFILE%\.aws'
        'check amazonq.cli_prompt_history %USERPROFILE%\.aws\amazonq\.cli_bash_history'
        'check amazonq.cli_agents %USERPROFILE%\.aws\amazonq\cli-agents\*.json'
        'check amazonq.cli_checkpoints %USERPROFILE%\.aws\amazonq\cli-checkouts'
        'check amazonq.ide_agent_config %USERPROFILE%\.aws\amazonq\default.json'
        'check amazonq.legacy_profiles_and_context %USERPROFILE%\.aws\amazonq\global_context.json'
        'check amazonq.ide_chat_history %USERPROFILE%\.aws\amazonq\history\*.json'
        'check amazonq.knowledge_bases %USERPROFILE%\.aws\amazonq\knowledge_bases\**'
        'check amazonq.cli_mcp_config %USERPROFILE%\.aws\amazonq\mcp.json'
        'check amazonq.legacy_profiles_and_context %USERPROFILE%\.aws\amazonq\profiles\**'
        'check amazonq.prompt_library %USERPROFILE%\.aws\amazonq\prompts\*.md'
        'check amazonq.cli_user_rules %USERPROFILE%\.aws\amazonq\rules\*'
        'check amazonq.sso_token_cache %USERPROFILE%\.aws\sso\cache\*.json'
        'walk amazonq.ide_extension_install %USERPROFILE%\.vscode\extensions'
    )
    'amp' = @(
        'walk amp.ledger,amp.secrets %APPDATA%\amp'
        'check amp.ledger %APPDATA%\amp\ledger.jsonl'
        'check amp.secrets %APPDATA%\amp\secrets.json'
        'check amp.threads %APPDATA%\amp\threads\T-*.json'
        'walk amp.managed_instructions,amp.settings %PROGRAMDATA%\ampcode'
        'check amp.managed_instructions %PROGRAMDATA%\ampcode\AGENTS.md'
        'check amp.settings %PROGRAMDATA%\ampcode\managed-settings.json'
        'walk amp.global_instructions %USERPROFILE%\.config\AGENTS.md'
        'walk amp.global_instructions,amp.plugins,amp.settings %USERPROFILE%\.config\amp'
        'check amp.global_instructions %USERPROFILE%\.config\amp\AGENTS.md'
        'check amp.plugins %USERPROFILE%\.config\amp\plugins'
        'check amp.settings %USERPROFILE%\.config\amp\settings.json'
        'check amp.settings %USERPROFILE%\.config\amp\settings.jsonc'
    )
    'chatgpt_desktop' = @(
        'walk chatgpt_desktop.windows_msix_localcache %LOCALAPPDATA%\Packages\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0'
        'check chatgpt_desktop.windows_msix_localcache %LOCALAPPDATA%\Packages\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0\LocalCache\Roaming\ChatGPT'
        'check chatgpt_desktop.windows_msix_localcache %LOCALAPPDATA%\Packages\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0\LocalCache\Roaming\ChatGPT\IndexedDB\https_chatgpt.com_0.indexeddb.leveldb'
        'check chatgpt_desktop.windows_msix_localcache %LOCALAPPDATA%\Packages\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0\LocalCache\Roaming\ChatGPT\Local Storage\leveldb'
    )
    'claude_code' = @(
        'walk claude_code.anthropic_active_config %APPDATA%\Anthropic\active_config'
        'walk claude_code.anthropic_profile_configs %APPDATA%\Anthropic\configs\<profile>.json'
        'walk claude_code.anthropic_profile_credentials %APPDATA%\Anthropic\credentials\<profile>.json'
        'walk claude_code.install_legacy_and_npm %APPDATA%\npm\node_modules\@anthropic-ai\claude-code'
        'walk claude_code.mcp_logs %LOCALAPPDATA%\claude-cli-nodejs\Cache'
        'walk claude_code.auto_memory,claude_code.changelog_cache,claude_code.credentials,claude_code.daemon_state,claude_code.file_history_snapshots,claude_code.history_jsonl,claude_code.image_cache,claude_code.jobs,claude_code.org_policy_cache,claude_code.stats_cache,claude_code.subagent_transcripts,claude_code.task_lists,claude_code.tool_result_spills,claude_code.transcripts,claude_code.transcripts_set_aside,claude_code.uploads %USERPROFILE%\.claude'
        'walk claude_code.global_config %USERPROFILE%\.claude.json'
        'check claude_code.credentials %USERPROFILE%\.claude\.credentials.json'
        'check claude_code.agent_memory %USERPROFILE%\.claude\agent-memory\*'
        'check claude_code.config_backups %USERPROFILE%\.claude\backups\*'
        'check claude_code.changelog_cache %USERPROFILE%\.claude\cache\changelog.md'
        'check claude_code.daemon_state %USERPROFILE%\.claude\daemon.log'
        'check claude_code.daemon_state %USERPROFILE%\.claude\daemon\roster.json'
        'check claude_code.debug_logs %USERPROFILE%\.claude\debug\*.txt'
        'check claude_code.feedback_bundles %USERPROFILE%\.claude\feedback-bundles\*'
        'check claude_code.feedback_drafts %USERPROFILE%\.claude\feedback\drafts\*'
        'check claude_code.file_history_snapshots %USERPROFILE%\.claude\file-history'
        'check claude_code.history_jsonl %USERPROFILE%\.claude\history.jsonl'
        'check claude_code.image_cache %USERPROFILE%\.claude\image-cache'
        'check claude_code.jobs %USERPROFILE%\.claude\jobs'
        'check claude_code.legacy_dirs %USERPROFILE%\.claude\logs\*'
        'check claude_code.paste_cache %USERPROFILE%\.claude\paste-cache\*'
        'check claude_code.plans %USERPROFILE%\.claude\plans\*.md'
        'check claude_code.org_policy_cache %USERPROFILE%\.claude\policy-limits.json'
        'check claude_code.auto_memory,claude_code.subagent_transcripts,claude_code.tool_result_spills,claude_code.transcripts,claude_code.transcripts_set_aside %USERPROFILE%\.claude\projects'
        'check claude_code.org_policy_cache %USERPROFILE%\.claude\remote-settings.json'
        'check claude_code.session_env %USERPROFILE%\.claude\session-env\*'
        'check claude_code.sessions_dir %USERPROFILE%\.claude\sessions\*'
        'check claude_code.shell_snapshots %USERPROFILE%\.claude\shell-snapshots\*'
        'check claude_code.stats_cache %USERPROFILE%\.claude\stats-cache.json'
        'check claude_code.legacy_dirs %USERPROFILE%\.claude\statsig\*'
        'check claude_code.task_lists %USERPROFILE%\.claude\tasks'
        'check claude_code.legacy_dirs %USERPROFILE%\.claude\todos\*'
        'check claude_code.uploads %USERPROFILE%\.claude\uploads'
        'check claude_code.usage_reports %USERPROFILE%\.claude\usage-data\*'
        'walk claude_code.install_native %USERPROFILE%\.local\bin\claude.exe'
        'walk claude_code.managed_claude_md,claude_code.managed_mcp_json,claude_code.managed_settings_file,claude_code.skills C:\Program Files\ClaudeCode'
        'check claude_code.skills C:\Program Files\ClaudeCode\.claude\skills'
        'check claude_code.managed_claude_md C:\Program Files\ClaudeCode\CLAUDE.md'
        'check claude_code.managed_mcp_json C:\Program Files\ClaudeCode\managed-mcp.json'
        'check claude_code.managed_settings_dropins C:\Program Files\ClaudeCode\managed-settings.d\*.json'
        'check claude_code.managed_settings_file C:\Program Files\ClaudeCode\managed-settings.json'
        'walk claude_code.managed_settings_file C:\ProgramData\ClaudeCode\managed-settings.json'
    )
    'claude_desktop' = @(
        'walk claude_desktop.app_logs,claude_desktop.code_session_index,claude_desktop.cowork_account_settings,claude_desktop.cowork_audit_key,claude_desktop.cowork_audit_log,claude_desktop.cowork_memory,claude_desktop.cowork_session_files,claude_desktop.cowork_session_store,claude_desktop.cowork_vm_bundle,claude_desktop.embedded_claude_code,claude_desktop.mcp_config,claude_desktop.renderer_state,claude_desktop.user_plugins %APPDATA%\Claude'
        'check claude_desktop.renderer_state %APPDATA%\Claude\IndexedDB'
        'check claude_desktop.renderer_state %APPDATA%\Claude\Local Storage'
        'check claude_desktop.transient_session_credentials %APPDATA%\Claude\ccd-session-secrets\<session-id>'
        'check claude_desktop.embedded_claude_code %APPDATA%\Claude\claude-code'
        'check claude_desktop.code_session_index %APPDATA%\Claude\claude-code-sessions'
        'check claude_desktop.mcp_config %APPDATA%\Claude\claude_desktop_config.json'
        'check claude_desktop.user_plugins %APPDATA%\Claude\cowork_plugins'
        'check claude_desktop.transient_session_credentials %APPDATA%\Claude\host-creds-<hash>.json'
        'check claude_desktop.cowork_account_settings,claude_desktop.cowork_audit_key,claude_desktop.cowork_audit_log,claude_desktop.cowork_memory,claude_desktop.cowork_session_files,claude_desktop.cowork_session_store %APPDATA%\Claude\local-agent-mode-sessions'
        'check claude_desktop.app_logs %APPDATA%\Claude\logs\main.log'
        'check claude_desktop.cowork_vm_bundle %APPDATA%\Claude\vm_bundles\claudevm.bundle'
        'walk claude_desktop.app_logs,claude_desktop.code_session_index,claude_desktop.cowork_session_store,claude_desktop.renderer_state %LOCALAPPDATA%\Claude'
        'walk claude_desktop.app_logs,claude_desktop.code_session_index,claude_desktop.cowork_account_settings,claude_desktop.cowork_audit_key,claude_desktop.cowork_audit_log,claude_desktop.cowork_memory,claude_desktop.cowork_session_store,claude_desktop.cowork_vm_bundle,claude_desktop.device_identifier,claude_desktop.local_config_library,claude_desktop.renderer_state,claude_desktop.user_plugins %LOCALAPPDATA%\Claude-3p'
        'check claude_desktop.renderer_state %LOCALAPPDATA%\Claude-3p\IndexedDB'
        'check claude_desktop.device_identifier %LOCALAPPDATA%\Claude-3p\ant-did'
        'check claude_desktop.code_session_index %LOCALAPPDATA%\Claude-3p\claude-code-sessions'
        'check claude_desktop.embedded_claude_code %LOCALAPPDATA%\Claude-3p\claude-code\<version>'
        'check claude_desktop.local_config_library %LOCALAPPDATA%\Claude-3p\configLibrary'
        'check claude_desktop.user_plugins %LOCALAPPDATA%\Claude-3p\cowork_plugins'
        'check claude_desktop.cowork_account_settings,claude_desktop.cowork_audit_key,claude_desktop.cowork_audit_log,claude_desktop.cowork_memory,claude_desktop.cowork_session_store %LOCALAPPDATA%\Claude-3p\local-agent-mode-sessions'
        'check claude_desktop.app_logs %LOCALAPPDATA%\Claude-3p\logs\main.log'
        'check claude_desktop.cowork_vm_bundle %LOCALAPPDATA%\Claude-3p\vm_bundles'
        'check claude_desktop.renderer_state %LOCALAPPDATA%\Claude\IndexedDB'
        'check claude_desktop.app_logs %LOCALAPPDATA%\Claude\Logs\main.log'
        'check claude_desktop.code_session_index %LOCALAPPDATA%\Claude\claude-code-sessions'
        'check claude_desktop.cowork_session_store %LOCALAPPDATA%\Claude\local-agent-mode-sessions'
        'walk claude_desktop.oauth_and_signin_tokens %LOCALAPPDATA%\Microsoft\Credentials'
        'walk claude_desktop.app_logs,claude_desktop.code_session_index,claude_desktop.cowork_account_settings,claude_desktop.cowork_audit_key,claude_desktop.cowork_audit_log,claude_desktop.cowork_memory,claude_desktop.cowork_session_files,claude_desktop.cowork_session_store,claude_desktop.cowork_vm_bundle,claude_desktop.embedded_claude_code,claude_desktop.install_evidence_windows,claude_desktop.mcp_config,claude_desktop.renderer_state,claude_desktop.user_plugins %LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc'
        'check claude_desktop.renderer_state %LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\IndexedDB'
        'check claude_desktop.renderer_state %LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\Local Storage'
        'check claude_desktop.transient_session_credentials %LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\ccd-session-secrets\<session-id>'
        'check claude_desktop.embedded_claude_code %LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude-code'
        'check claude_desktop.code_session_index %LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude-code-sessions'
        'check claude_desktop.mcp_config %LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json'
        'check claude_desktop.user_plugins %LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\cowork_plugins'
        'check claude_desktop.transient_session_credentials %LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\host-creds-<hash>.json'
        'check claude_desktop.cowork_account_settings,claude_desktop.cowork_audit_key,claude_desktop.cowork_audit_log,claude_desktop.cowork_memory,claude_desktop.cowork_session_files,claude_desktop.cowork_session_store %LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\local-agent-mode-sessions'
        'check claude_desktop.app_logs %LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\logs'
        'check claude_desktop.app_logs %LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\logs\main.log'
        'check claude_desktop.cowork_vm_bundle %LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\vm_bundles\claudevm.bundle'
        'check claude_desktop.cowork_vm_bundle %LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\vm_bundles\claudevm.bundle\sessiondata.vhdx'
        'walk claude_desktop.scheduled_tasks %USERPROFILE%\.claude\scheduled-tasks'
        'walk claude_desktop.user_output_folder %USERPROFILE%\Claude'
        'check claude_desktop.user_output_folder %USERPROFILE%\Claude\Projects\<name>'
        'walk claude_desktop.org_plugins C:\Program Files\Claude\org-plugins'
        'walk claude_desktop.install_evidence_windows C:\Program Files\WindowsApps\Claude_<version>_<arch>__pzs8sxrjxfjjc'
        'walk claude_desktop.coworkd_service_log C:\ProgramData\Claude\Logs\coworkd\user-<sid>.log'
    )
    'cline' = @(
        'walk cline.data_dir_root %USERPROFILE%\.cline\data'
    )
    'codex' = @(
        'walk codex.archived_sessions,codex.auth,codex.config,codex.log_dir,codex.mcp_and_notify,codex.mcp_oauth_credentials,codex.prompt_history,codex.requirements_and_permissions,codex.rollouts,codex.rollouts_compressed,codex.state_databases %USERPROFILE%\.codex'
        'check codex.config %USERPROFILE%\.codex\*.config.toml'
        'check codex.sqlite_glob %USERPROFILE%\.codex\*.sqlite'
        'check codex.sqlite_write_ahead_logs %USERPROFILE%\.codex\*.sqlite-shm'
        'check codex.sqlite_write_ahead_logs %USERPROFILE%\.codex\*.sqlite-wal'
        'check codex.mcp_oauth_credentials %USERPROFILE%\.codex\.credentials.json'
        'check codex.archived_sessions %USERPROFILE%\.codex\archived_sessions'
        'check codex.auth %USERPROFILE%\.codex\auth.json'
        'check codex.config,codex.mcp_and_notify %USERPROFILE%\.codex\config.toml'
        'check codex.state_databases %USERPROFILE%\.codex\goals_1.sqlite'
        'check codex.prompt_history %USERPROFILE%\.codex\history.jsonl'
        'check codex.log_dir %USERPROFILE%\.codex\log'
        'check codex.state_databases %USERPROFILE%\.codex\logs_2.sqlite'
        'check codex.state_databases %USERPROFILE%\.codex\memories_1.sqlite'
        'check codex.state_databases %USERPROFILE%\.codex\memories_v2_1.sqlite'
        'check codex.requirements_and_permissions %USERPROFILE%\.codex\permissions.toml'
        'check codex.state_databases %USERPROFILE%\.codex\queue_1.sqlite'
        'check codex.requirements_and_permissions %USERPROFILE%\.codex\requirements.toml'
        'check codex.rollouts,codex.rollouts_compressed %USERPROFILE%\.codex\sessions'
        'check codex.state_databases %USERPROFILE%\.codex\state_5.sqlite'
        'check codex.state_databases %USERPROFILE%\.codex\thread_history_1.sqlite'
    )
    'continue' = @(
        'walk continue.cli_auth,continue.compiled_config,continue.dev_data_db,continue.dotenv,continue.downloaded_binaries,continue.environment_markers,continue.global_context,continue.hook_settings,continue.input_history,continue.permissions,continue.prompt_log %USERPROFILE%\.continue'
        'check continue.environment_markers %USERPROFILE%\.continue\.continuerc.json'
        'check continue.dotenv %USERPROFILE%\.continue\.env'
        'check continue.environment_markers %USERPROFILE%\.continue\.local'
        'check continue.environment_markers %USERPROFILE%\.continue\.onboarding_complete'
        'check continue.environment_markers %USERPROFILE%\.continue\.staging'
        'check continue.downloaded_binaries %USERPROFILE%\.continue\.utils\.chromium-browser-snapshots'
        'check continue.downloaded_binaries %USERPROFILE%\.continue\.utils\esbuild'
        'check continue.cli_auth %USERPROFILE%\.continue\auth.json'
        'check continue.dev_data_db %USERPROFILE%\.continue\dev_data\devdata.sqlite'
        'check continue.dev_data_db %USERPROFILE%\.continue\dev_data\devdata.sqlite-shm'
        'check continue.dev_data_db %USERPROFILE%\.continue\dev_data\devdata.sqlite-wal'
        'check continue.global_context %USERPROFILE%\.continue\index\globalContext.json'
        'check continue.input_history %USERPROFILE%\.continue\input_history.json'
        'check continue.logs %USERPROFILE%\.continue\logs\**'
        'check continue.prompt_log %USERPROFILE%\.continue\logs\prompt.log'
        'check continue.compiled_config %USERPROFILE%\.continue\out\config.js'
        'check continue.permissions %USERPROFILE%\.continue\permissions.yaml'
        'check continue.rules_and_skills %USERPROFILE%\.continue\prompts\**'
        'check continue.rules_and_skills %USERPROFILE%\.continue\rules\**'
        'check continue.sessions %USERPROFILE%\.continue\sessions\*.json'
        'check continue.hook_settings %USERPROFILE%\.continue\settings.json'
        'check continue.global_context %USERPROFILE%\.continue\sharedConfig.json'
        'check continue.rules_and_skills %USERPROFILE%\.continue\skills\**'
    )
    'copilot' = @(
        'walk copilot.cache %LOCALAPPDATA%\copilot'
        'walk copilot.mcp_config_jetbrains %LOCALAPPDATA%\github-copilot\intellij\mcp.json'
        'walk copilot.agents_skills_hooks,copilot.command_history,copilot.config_json,copilot.extensions_and_plugins,copilot.ide_locks,copilot.instructions,copilot.logs,copilot.lsp_config,copilot.mcp_config,copilot.mcp_credentials,copilot.permissions,copilot.providers,copilot.session_state,copilot.session_store,copilot.session_store_sidecars,copilot.settings %USERPROFILE%\.copilot'
        'check copilot.agents_skills_hooks %USERPROFILE%\.copilot\agents'
        'check copilot.command_history %USERPROFILE%\.copilot\command-history-state'
        'check copilot.config_json %USERPROFILE%\.copilot\config.json'
        'check copilot.instructions %USERPROFILE%\.copilot\copilot-instructions.md'
        'check copilot.extensions_and_plugins %USERPROFILE%\.copilot\extensions'
        'check copilot.agents_skills_hooks %USERPROFILE%\.copilot\hooks'
        'check copilot.ide_locks %USERPROFILE%\.copilot\ide'
        'check copilot.extensions_and_plugins %USERPROFILE%\.copilot\installed-plugins'
        'check copilot.instructions %USERPROFILE%\.copilot\instructions'
        'check copilot.logs %USERPROFILE%\.copilot\logs'
        'check copilot.lsp_config %USERPROFILE%\.copilot\lsp-config.json'
        'check copilot.mcp_config %USERPROFILE%\.copilot\mcp-config.json'
        'check copilot.mcp_credentials %USERPROFILE%\.copilot\mcp-oauth-config'
        'check copilot.mcp_credentials %USERPROFILE%\.copilot\mcp-secrets'
        'check copilot.permissions %USERPROFILE%\.copilot\permissions-config.json'
        'check copilot.extensions_and_plugins %USERPROFILE%\.copilot\plugin-data'
        'check copilot.providers %USERPROFILE%\.copilot\providers.json'
        'check copilot.session_state %USERPROFILE%\.copilot\session-state'
        'check copilot.session_store %USERPROFILE%\.copilot\session-store.db'
        'check copilot.session_store_sidecars %USERPROFILE%\.copilot\session-store.db-shm'
        'check copilot.session_store_sidecars %USERPROFILE%\.copilot\session-store.db-wal'
        'check copilot.settings %USERPROFILE%\.copilot\settings.json'
        'check copilot.agents_skills_hooks %USERPROFILE%\.copilot\skills'
    )
    'crosscutting' = @(
        'check crosscutting.windows_appdata_program_dirs %APPDATA%'
        'walk crosscutting.shell_psreadline_history %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\*_history.txt'
        'walk crosscutting.shell_psreadline_history %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        'walk crosscutting.npm_global_install_dirs %APPDATA%\npm'
        'check crosscutting.npm_global_install_dirs %APPDATA%\npm\node_modules'
        'walk crosscutting.uv_tool_dir %APPDATA%\uv\data\tools\*'
        'walk crosscutting.windows_appdata_program_dirs %LOCALAPPDATA%\Ollama'
        'check crosscutting.windows_appdata_program_dirs %LOCALAPPDATA%\Packages'
        'check crosscutting.windows_appdata_program_dirs %LOCALAPPDATA%\Programs'
        'walk crosscutting.windows_appdata_program_dirs %LOCALAPPDATA%\Programs\Ollama'
        'walk crosscutting.npm_debug_logs %LOCALAPPDATA%\npm-cache\_logs\*-debug-*.log'
        'walk crosscutting.npm_npx_cache %LOCALAPPDATA%\npm-cache\_npx'
        'walk crosscutting.pipx_home_and_bin %LOCALAPPDATA%\pipx\pipx\venvs\*'
        'walk crosscutting.uv_tool_dir %LOCALAPPDATA%\uv\cache'
        'walk crosscutting.windows_execution_evidence_files %SystemRoot%\AppCompat'
        'check crosscutting.windows_execution_evidence_files %SystemRoot%\AppCompat\Programs\Amcache.hve'
        'check crosscutting.windows_execution_evidence_files %SystemRoot%\AppCompat\Programs\Amcache.hve.LOG1'
        'check crosscutting.windows_execution_evidence_files %SystemRoot%\AppCompat\Programs\Amcache.hve.LOG2'
        'walk crosscutting.windows_execution_evidence_files %SystemRoot%\Prefetch\*.pf'
        'walk crosscutting.windows_execution_evidence_files %SystemRoot%\System32'
        'check crosscutting.windows_execution_evidence_files %SystemRoot%\System32\Tasks'
        'check crosscutting.windows_execution_evidence_files %SystemRoot%\System32\sru\SRUDB.dat'
        'walk crosscutting.instructions_claude_md C:\Program Files\ClaudeCode\CLAUDE.md'
    )
    'cursor' = @(
        'walk cursor.commit_checkpoints,cursor.conversation_search_db,cursor.global_state_vscdb,cursor.local_file_history,cursor.logs,cursor.machine_identity_file,cursor.workspace_state_vscdb %APPDATA%\Cursor'
        'check cursor.machine_identity_file %APPDATA%\Cursor\SharedStorage'
        'check cursor.local_file_history %APPDATA%\Cursor\User\History'
        'check cursor.commit_checkpoints %APPDATA%\Cursor\User\globalStorage\anysphere.cursor-commits\checkpoints'
        'check cursor.commit_checkpoints %APPDATA%\Cursor\User\globalStorage\anysphere.cursor-retrieval\checkpoints'
        'check cursor.conversation_search_db %APPDATA%\Cursor\User\globalStorage\conversation-search.db'
        'check cursor.conversation_search_db %APPDATA%\Cursor\User\globalStorage\conversation-search.db-shm'
        'check cursor.conversation_search_db %APPDATA%\Cursor\User\globalStorage\conversation-search.db-wal'
        'check cursor.global_state_vscdb %APPDATA%\Cursor\User\globalStorage\state.vscdb'
        'check cursor.global_state_vscdb %APPDATA%\Cursor\User\globalStorage\state.vscdb-shm'
        'check cursor.global_state_vscdb %APPDATA%\Cursor\User\globalStorage\state.vscdb-wal'
        'check cursor.workspace_state_vscdb %APPDATA%\Cursor\User\workspaceStorage'
        'check cursor.logs %APPDATA%\Cursor\logs'
        'check cursor.machine_identity_file %APPDATA%\Cursor\machineid'
        'walk cursor.agent_store_sync %LOCALAPPDATA%\Cursor\AgentStores\cursor_agent_stores'
        'walk cursor.install_dirs %LOCALAPPDATA%\Programs\cursor'
        'walk cursor.temp_residue %LOCALAPPDATA%\Temp'
        'walk cursor.install_dirs %LOCALAPPDATA%\cursor-agent\*.cmd'
        'walk cursor.install_dirs %LOCALAPPDATA%\cursor-agent\*.ps1'
        'walk cursor.install_dirs %LOCALAPPDATA%\cursor-agent\versions\<version>'
        'walk cursor.install_dirs %LOCALAPPDATA%\cursor-compile-cache'
        'walk cursor.install_dirs %LOCALAPPDATA%\cursor-updater'
        'walk cursor.agent_transcripts_jsonl,cursor.bundled_skills,cursor.chat_store_db,cursor.cli_config,cursor.extensions,cursor.feature_flag_cache,cursor.global_prompt_history,cursor.mcp_config,cursor.project_mcp_definitions,cursor.project_mcp_instructions,cursor.runtime_arguments %USERPROFILE%\.cursor'
        'check cursor.runtime_arguments %USERPROFILE%\.cursor\argv.json'
        'check cursor.chat_store_db %USERPROFILE%\.cursor\chats'
        'check cursor.cli_config %USERPROFILE%\.cursor\cli-config.json'
        'check cursor.cli_config %USERPROFILE%\.cursor\cli-config.json.bad'
        'check cursor.extensions %USERPROFILE%\.cursor\extensions\extensions.json'
        'check cursor.mcp_config %USERPROFILE%\.cursor\mcp.json'
        'check cursor.agent_transcripts_jsonl,cursor.project_mcp_definitions,cursor.project_mcp_instructions %USERPROFILE%\.cursor\projects'
        'check cursor.agent_data_cleanup_marker %USERPROFILE%\.cursor\projects\.agent-data-cleanup-<yyyy-mm-dd>'
        'check cursor.global_prompt_history %USERPROFILE%\.cursor\prompt_history.json'
        'check cursor.bundled_skills %USERPROFILE%\.cursor\skills-cursor'
        'check cursor.bundled_skills %USERPROFILE%\.cursor\skills-cursor\.sync-manifest.json'
        'check cursor.feature_flag_cache %USERPROFILE%\.cursor\statsig-cache.json'
        'check cursor.worktrees %USERPROFILE%\.cursor\worktrees\*'
        'walk cursor.hooks C:\ProgramData\Cursor\hooks.json'
    )
    'devin' = @(
        'walk devin.acp_events %APPDATA%\Devin\User\acp-events'
        'walk devin.cli_config,devin.cli_mcp_config,devin.cli_subagents %APPDATA%\devin'
        'check devin.cli_subagents %APPDATA%\devin\agents'
        'check devin.cli_config %APPDATA%\devin\config.json'
        'check devin.cli_mcp_config %APPDATA%\devin\mcp_config.json'
        'walk devin.sessions_db %USERPROFILE%\.local\share\devin'
        'check devin.sessions_db %USERPROFILE%\.local\share\devin\cli\sessions.db'
        'check devin.sessions_db %USERPROFILE%\.local\share\devin\cli\sessions.db-shm'
        'check devin.sessions_db %USERPROFILE%\.local\share\devin\cli\sessions.db-wal'
        'walk devin.cli_system_policy C:\ProgramData\Devin\system.json'
    )
    'factory_droid' = @(
        'walk factory_droid.output_styles %USERPROFILE%\.factory\output-styles\*.md'
        'walk factory_droid.config %USERPROFILE%\.factory\settings.json'
        'walk factory_droid.specs %USERPROFILE%\.factory\specs\**'
        'walk factory_droid.worktrees %USERPROFILE%\.factory\worktrees\**'
        'walk factory_droid.managed_settings C:\Program Files\Factory\settings.json'
    )
    'gemini_cli' = @(
        'walk gemini_cli.system_settings %PROGRAMDATA%\gemini-cli'
        'check gemini_cli.policies %PROGRAMDATA%\gemini-cli\policies\**'
        'check gemini_cli.system_settings %PROGRAMDATA%\gemini-cli\settings.json'
        'check gemini_cli.system_settings %PROGRAMDATA%\gemini-cli\system-defaults.json'
        'walk gemini_cli.agent_definitions %USERPROFILE%\.agents\skills\**'
        'walk gemini_cli.agent_acknowledgments,gemini_cli.chats,gemini_cli.commands,gemini_cli.credentials,gemini_cli.google_accounts,gemini_cli.home_tree,gemini_cli.install_evidence,gemini_cli.mcp_oauth_tokens,gemini_cli.policy_integrity,gemini_cli.project_registry,gemini_cli.prompt_history_log,gemini_cli.shell_history,gemini_cli.trusted_folders,gemini_cli.user_settings %USERPROFILE%\.gemini'
        'check gemini_cli.mcp_oauth_tokens %USERPROFILE%\.gemini\a2a-oauth-tokens.json'
        'check gemini_cli.agent_acknowledgments %USERPROFILE%\.gemini\acknowledgments\agents.json'
        'check gemini_cli.agent_definitions %USERPROFILE%\.gemini\agents\**'
        'check gemini_cli.commands %USERPROFILE%\.gemini\commands'
        'check gemini_cli.google_accounts %USERPROFILE%\.gemini\google_accounts.json'
        'check gemini_cli.project_runtime_trees %USERPROFILE%\.gemini\history\<project-hash>'
        'check gemini_cli.install_evidence %USERPROFILE%\.gemini\installation_id'
        'check gemini_cli.mcp_oauth_tokens %USERPROFILE%\.gemini\mcp-oauth-tokens.json'
        'check gemini_cli.credentials %USERPROFILE%\.gemini\oauth_creds.json'
        'check gemini_cli.policies %USERPROFILE%\.gemini\policies\**'
        'check gemini_cli.policy_integrity %USERPROFILE%\.gemini\policy_integrity.json'
        'check gemini_cli.project_registry %USERPROFILE%\.gemini\projects.json'
        'check gemini_cli.chats %USERPROFILE%\.gemini\sessions'
        'check gemini_cli.user_settings %USERPROFILE%\.gemini\settings.json'
        'check gemini_cli.agent_definitions %USERPROFILE%\.gemini\skills\**'
        'check gemini_cli.chats,gemini_cli.prompt_history_log,gemini_cli.shell_history %USERPROFILE%\.gemini\tmp'
        'check gemini_cli.project_runtime_trees %USERPROFILE%\.gemini\tmp\<project-hash>'
        'check gemini_cli.trusted_folders %USERPROFILE%\.gemini\trustedFolders.json'
    )
    'goose' = @(
        'walk goose.agents,goose.cli_logs,goose.command_history,goose.config,goose.desktop_log,goose.hints,goose.permissions,goose.prompts,goose.secrets,goose.server_logs,goose.sessions_db_windows,goose.settings,goose.skills %APPDATA%\Block'
        'check goose.hints %APPDATA%\Block\goose\config\.goosehints'
        'check goose.agents %APPDATA%\Block\goose\config\agents'
        'check goose.config %APPDATA%\Block\goose\config\config.yaml'
        'check goose.permissions %APPDATA%\Block\goose\config\permission.yaml'
        'check goose.permissions %APPDATA%\Block\goose\config\permissions\tool_permissions.json'
        'check goose.prompts %APPDATA%\Block\goose\config\prompts'
        'check goose.secrets %APPDATA%\Block\goose\config\secrets.yaml'
        'check goose.settings %APPDATA%\Block\goose\config\settings.json'
        'check goose.skills %APPDATA%\Block\goose\config\skills'
        'check goose.command_history %APPDATA%\Block\goose\data\history.txt'
        'check goose.cli_logs %APPDATA%\Block\goose\data\logs\cli'
        'check goose.llm_request_logs %APPDATA%\Block\goose\data\logs\llm_request.*.jsonl'
        'check goose.server_logs %APPDATA%\Block\goose\data\logs\server'
        'check goose.sessions_jsonl_legacy %APPDATA%\Block\goose\data\sessions\*.jsonl'
        'check goose.sessions_db_windows %APPDATA%\Block\goose\data\sessions\sessions.db'
        'check goose.sessions_db_windows %APPDATA%\Block\goose\data\sessions\sessions.db-shm'
        'check goose.sessions_db_windows %APPDATA%\Block\goose\data\sessions\sessions.db-wal'
        'check goose.desktop_log %APPDATA%\Block\goose\logs\main.log'
        'walk goose.agents,goose.hooks,goose.plugins,goose.skills %USERPROFILE%\.agents'
        'check goose.agents %USERPROFILE%\.agents\agents'
        'check goose.hooks,goose.plugins %USERPROFILE%\.agents\plugins'
        'check goose.skills %USERPROFILE%\.agents\skills'
        'walk goose.agents,goose.skills %USERPROFILE%\.claude'
        'check goose.agents %USERPROFILE%\.claude\agents'
        'check goose.skills %USERPROFILE%\.claude\skills'
        'walk goose.agents %USERPROFILE%\.goose\agents'
    )
    'hermes' = @(
        'walk hermes.a2a_audit,hermes.a2a_conversations,hermes.auth,hermes.background_processes,hermes.backups,hermes.blocked_scripts,hermes.browser_agent_profiles,hermes.browser_media,hermes.browser_profile,hermes.checkpoint_projects,hermes.checkpoints,hermes.config,hermes.cron,hermes.cron_executions,hermes.cron_external_workers,hermes.cron_jobs,hermes.cron_usage_audit,hermes.debug_share_pastes,hermes.env,hermes.gateway_state,hermes.hooks,hermes.logs,hermes.mcp_installs,hermes.mcp_tokens,hermes.memories,hermes.memory_store,hermes.model_traces,hermes.oauth_tokens,hermes.pairing,hermes.pastes,hermes.pending_skills,hermes.platform_sessions,hermes.process_results,hermes.profile_home,hermes.profile_tombstones,hermes.profiles,hermes.projects_db,hermes.remote_sandbox_snapshots,hermes.response_store,hermes.retired_wal_generations,hermes.retired_wal_manifests,hermes.retired_wal_transcripts,hermes.sandboxes,hermes.saved_sessions,hermes.session_exports,hermes.sessions_dir,hermes.skills,hermes.skills_prompt_snapshot,hermes.soul,hermes.spillover,hermes.state_db,hermes.state_snapshot_transcripts,hermes.state_snapshots,hermes.terminal_sessions,hermes.vault,hermes.verification_evidence %LOCALAPPDATA%\hermes'
        'check hermes.oauth_tokens %LOCALAPPDATA%\hermes\.anthropic_oauth.json'
        'check hermes.env %LOCALAPPDATA%\hermes\.env'
        'check hermes.skills_prompt_snapshot %LOCALAPPDATA%\hermes\.skills_prompt_snapshot.json'
        'check hermes.soul %LOCALAPPDATA%\hermes\SOUL.md'
        'check hermes.a2a_audit %LOCALAPPDATA%\hermes\a2a_audit.jsonl'
        'check hermes.a2a_conversations %LOCALAPPDATA%\hermes\a2a_conversations\*.jsonl'
        'check hermes.auth %LOCALAPPDATA%\hermes\auth.json'
        'check hermes.backups %LOCALAPPDATA%\hermes\backups\*.zip'
        'check hermes.browser_profile %LOCALAPPDATA%\hermes\browser-profile\**'
        'check hermes.browser_agent_profiles %LOCALAPPDATA%\hermes\browser_auth\**'
        'check hermes.browser_media %LOCALAPPDATA%\hermes\browser_recordings\session_*.webm'
        'check hermes.browser_media %LOCALAPPDATA%\hermes\browser_screenshots\browser_screenshot_*.png'
        'check hermes.blocked_scripts %LOCALAPPDATA%\hermes\cache\blocked-scripts\blocked-*.sh'
        'check hermes.oauth_tokens %LOCALAPPDATA%\hermes\cache\bws_cache.enc.json'
        'check hermes.oauth_tokens %LOCALAPPDATA%\hermes\cache\bws_cache.json'
        'check hermes.browser_media %LOCALAPPDATA%\hermes\cache\screenshots\browser_screenshot_*.png'
        'check hermes.spillover %LOCALAPPDATA%\hermes\cache\spillover\*.txt'
        'check hermes.gateway_state %LOCALAPPDATA%\hermes\channel_aliases.json'
        'check hermes.gateway_state %LOCALAPPDATA%\hermes\channel_directory.json'
        'check hermes.checkpoints %LOCALAPPDATA%\hermes\checkpoints'
        'check hermes.checkpoints %LOCALAPPDATA%\hermes\checkpoints\store\**'
        'check hermes.checkpoint_projects %LOCALAPPDATA%\hermes\checkpoints\store\ledgers\*.json'
        'check hermes.checkpoint_projects %LOCALAPPDATA%\hermes\checkpoints\store\projects\*.json'
        'check hermes.browser_agent_profiles %LOCALAPPDATA%\hermes\chrome-debug\**'
        'check hermes.config %LOCALAPPDATA%\hermes\config.yaml'
        'check hermes.cron %LOCALAPPDATA%\hermes\cron'
        'check hermes.cron_executions %LOCALAPPDATA%\hermes\cron\executions.db'
        'check hermes.cron_executions %LOCALAPPDATA%\hermes\cron\executions.db-shm'
        'check hermes.cron_executions %LOCALAPPDATA%\hermes\cron\executions.db-wal'
        'check hermes.cron_external_workers %LOCALAPPDATA%\hermes\cron\external-workers\**'
        'check hermes.cron_jobs %LOCALAPPDATA%\hermes\cron\jobs.json'
        'check hermes.cron_usage_audit %LOCALAPPDATA%\hermes\cron\usage_audit.jsonl'
        'check hermes.gateway_state %LOCALAPPDATA%\hermes\gateway.pid'
        'check hermes.gateway_state %LOCALAPPDATA%\hermes\gateway_state.json'
        'check hermes.oauth_tokens %LOCALAPPDATA%\hermes\google_chat_user_client_secret.json'
        'check hermes.oauth_tokens %LOCALAPPDATA%\hermes\google_chat_user_oauth_pending.json'
        'check hermes.oauth_tokens %LOCALAPPDATA%\hermes\google_chat_user_oauth_pending\*.json'
        'check hermes.oauth_tokens %LOCALAPPDATA%\hermes\google_chat_user_token.json'
        'check hermes.oauth_tokens %LOCALAPPDATA%\hermes\google_chat_user_tokens\*.json'
        'check hermes.oauth_tokens %LOCALAPPDATA%\hermes\google_token.json'
        'check hermes.profile_home %LOCALAPPDATA%\hermes\home\**'
        'check hermes.hooks %LOCALAPPDATA%\hermes\hooks\**'
        'check hermes.logs %LOCALAPPDATA%\hermes\logs\**'
        'check hermes.process_results %LOCALAPPDATA%\hermes\logs\process-results\proc_*.json'
        'check hermes.platform_sessions %LOCALAPPDATA%\hermes\matrix\store\crypto.db'
        'check hermes.mcp_installs %LOCALAPPDATA%\hermes\mcp-installs\**'
        'check hermes.mcp_tokens %LOCALAPPDATA%\hermes\mcp-tokens\*.cimd-off'
        'check hermes.mcp_tokens %LOCALAPPDATA%\hermes\mcp-tokens\*.json'
        'check hermes.memories %LOCALAPPDATA%\hermes\memories\MEMORY.md'
        'check hermes.memories %LOCALAPPDATA%\hermes\memories\USER.md'
        'check hermes.memory_store %LOCALAPPDATA%\hermes\memory_store.db'
        'check hermes.memory_store %LOCALAPPDATA%\hermes\memory_store.db-shm'
        'check hermes.memory_store %LOCALAPPDATA%\hermes\memory_store.db-wal'
        'check hermes.model_traces %LOCALAPPDATA%\hermes\moa-traces\*.jsonl'
        'check hermes.remote_sandbox_snapshots %LOCALAPPDATA%\hermes\modal_snapshots.json'
        'check hermes.pairing %LOCALAPPDATA%\hermes\pairing\**'
        'check hermes.pastes %LOCALAPPDATA%\hermes\pastes\paste_*.txt'
        'check hermes.debug_share_pastes %LOCALAPPDATA%\hermes\pastes\pending.json'
        'check hermes.pending_skills %LOCALAPPDATA%\hermes\pending\skills\*.json'
        'check hermes.platform_sessions %LOCALAPPDATA%\hermes\platforms\matrix\store\crypto.db'
        'check hermes.pairing %LOCALAPPDATA%\hermes\platforms\pairing\**'
        'check hermes.platform_sessions %LOCALAPPDATA%\hermes\platforms\whatsapp\session\**'
        'check hermes.background_processes %LOCALAPPDATA%\hermes\processes.json'
        'check hermes.a2a_audit,hermes.a2a_conversations,hermes.auth,hermes.background_processes,hermes.backups,hermes.blocked_scripts,hermes.browser_agent_profiles,hermes.browser_media,hermes.browser_profile,hermes.checkpoint_projects,hermes.checkpoints,hermes.config,hermes.cron,hermes.cron_executions,hermes.cron_external_workers,hermes.cron_jobs,hermes.cron_usage_audit,hermes.debug_share_pastes,hermes.env,hermes.gateway_state,hermes.hooks,hermes.logs,hermes.mcp_installs,hermes.mcp_tokens,hermes.memories,hermes.memory_store,hermes.model_traces,hermes.oauth_tokens,hermes.pairing,hermes.pastes,hermes.pending_skills,hermes.platform_sessions,hermes.process_results,hermes.profile_home,hermes.profiles,hermes.projects_db,hermes.remote_sandbox_snapshots,hermes.response_store,hermes.retired_wal_generations,hermes.retired_wal_manifests,hermes.retired_wal_transcripts,hermes.sandboxes,hermes.saved_sessions,hermes.session_exports,hermes.sessions_dir,hermes.skills,hermes.skills_prompt_snapshot,hermes.soul,hermes.spillover,hermes.state_db,hermes.state_snapshot_transcripts,hermes.state_snapshots,hermes.terminal_sessions,hermes.vault,hermes.verification_evidence %LOCALAPPDATA%\hermes\profiles'
        'check hermes.profile_tombstones %LOCALAPPDATA%\hermes\profiles\.deleted'
        'check hermes.projects_db %LOCALAPPDATA%\hermes\projects.db'
        'check hermes.projects_db %LOCALAPPDATA%\hermes\projects.db-shm'
        'check hermes.projects_db %LOCALAPPDATA%\hermes\projects.db-wal'
        'check hermes.response_store %LOCALAPPDATA%\hermes\response_store.db'
        'check hermes.response_store %LOCALAPPDATA%\hermes\response_store.db-shm'
        'check hermes.response_store %LOCALAPPDATA%\hermes\response_store.db-wal'
        'check hermes.sandboxes %LOCALAPPDATA%\hermes\sandboxes'
        'check hermes.session_exports %LOCALAPPDATA%\hermes\session-exports\**'
        'check hermes.sessions_dir %LOCALAPPDATA%\hermes\sessions'
        'check hermes.saved_sessions %LOCALAPPDATA%\hermes\sessions\saved\*.json'
        'check hermes.saved_sessions %LOCALAPPDATA%\hermes\sessions\sessions.json'
        'check hermes.remote_sandbox_snapshots %LOCALAPPDATA%\hermes\singularity_snapshots.json'
        'check hermes.skills %LOCALAPPDATA%\hermes\skills'
        'check hermes.oauth_tokens %LOCALAPPDATA%\hermes\slack_tokens.json'
        'check hermes.state_snapshot_transcripts %LOCALAPPDATA%\hermes\state-snapshots'
        'check hermes.state_snapshots %LOCALAPPDATA%\hermes\state-snapshots\**'
        'check hermes.state_db %LOCALAPPDATA%\hermes\state.db'
        'check hermes.state_db %LOCALAPPDATA%\hermes\state.db-shm'
        'check hermes.state_db %LOCALAPPDATA%\hermes\state.db-wal'
        'check hermes.terminal_sessions %LOCALAPPDATA%\hermes\terminal-sessions\*.json'
        'check hermes.vault %LOCALAPPDATA%\hermes\vault\vault.json.enc'
        'check hermes.vault %LOCALAPPDATA%\hermes\vault\vault.key'
        'check hermes.remote_sandbox_snapshots %LOCALAPPDATA%\hermes\vercel_sandbox_snapshots.json'
        'check hermes.verification_evidence %LOCALAPPDATA%\hermes\verification_evidence.db'
        'check hermes.verification_evidence %LOCALAPPDATA%\hermes\verification_evidence.db-shm'
        'check hermes.verification_evidence %LOCALAPPDATA%\hermes\verification_evidence.db-wal'
        'check hermes.gateway_state %LOCALAPPDATA%\hermes\webhook_subscriptions.json'
        'check hermes.platform_sessions %LOCALAPPDATA%\hermes\whatsapp\session\**'
    )
    'jetbrains_ai' = @(
        'walk jetbrains_ai.aia_task_history,jetbrains_ai.base_directories,jetbrains_ai.disabled_plugins,jetbrains_ai.password_safe,jetbrains_ai.path_properties %APPDATA%\JetBrains'
        'check jetbrains_ai.base_directories %APPDATA%\JetBrains\<Product><Version>'
        'check jetbrains_ai.mcp_config %APPDATA%\JetBrains\Air\mcp.json'
        'walk jetbrains_ai.base_directories,jetbrains_ai.ide_logs,jetbrains_ai.log_data %LOCALAPPDATA%\JetBrains'
        'check jetbrains_ai.base_directories %LOCALAPPDATA%\JetBrains\<Product><Version>'
        'walk jetbrains_ai.path_properties %USERPROFILE%\idea.properties'
    )
    'junie' = @(
        'walk junie.plugin_install_evidence %APPDATA%\JetBrains'
        'walk junie.jcp_outbox,junie.matterhorn_project_logs %LOCALAPPDATA%\JetBrains'
        'walk junie.allowlist,junie.home_config,junie.mcp_config,junie.trust_and_auth_key %USERPROFILE%\.junie'
        'check junie.home_config %USERPROFILE%\.junie\AGENTS.md'
        'check junie.allowlist %USERPROFILE%\.junie\allowlist.json'
        'check junie.home_config %USERPROFILE%\.junie\config.json'
        'check junie.mcp_config %USERPROFILE%\.junie\mcp\mcp.json'
        'check junie.cli_sessions %USERPROFILE%\.junie\sessions\<session-id>'
        'check junie.trust_and_auth_key %USERPROFILE%\.junie\trust'
    )
    'kilo_code' = @(
        'walk kilo_code.extension_id_legacy_tree,kilo_code.settings %APPDATA%\Code'
        'check kilo_code.settings %APPDATA%\Code\User\globalStorage\kilocode.kilo-code\settings\custom_modes.yaml'
        'check kilo_code.extension_id_legacy_tree %APPDATA%\Code\User\globalStorage\kilocode.kilo-code\tasks'
        'walk kilo_code.agents,kilo_code.config %USERPROFILE%\.config\kilo'
        'check kilo_code.agents %USERPROFILE%\.config\kilo\agent'
        'check kilo_code.config %USERPROFILE%\.config\kilo\kilo.jsonc'
        'walk kilo_code.cli_db %USERPROFILE%\.local\share\kilo'
        'check kilo_code.cli_db %USERPROFILE%\.local\share\kilo\kilo.db'
        'check kilo_code.cli_db %USERPROFILE%\.local\share\kilo\kilo.db-shm'
        'check kilo_code.cli_db %USERPROFILE%\.local\share\kilo\kilo.db-wal'
    )
    'kiro' = @(
        'walk kiro.ide_legacy_global_storage %APPDATA%\Kiro\User\globalStorage\kiro.kiroagent\**'
        'walk kiro.cli_log %TEMP%\kiro-log\logs\kiro-chat.log'
        'walk kiro.cli_settings,kiro.mcp_config_user,kiro.permissions_user,kiro.permissions_workspace %USERPROFILE%\.kiro'
        'check kiro.cli_session_database %USERPROFILE%\.kiro\*.sqlite3'
        'check kiro.cli_session_database %USERPROFILE%\.kiro\*.sqlite3-shm'
        'check kiro.cli_session_database %USERPROFILE%\.kiro\*.sqlite3-wal'
        'check kiro.agents %USERPROFILE%\.kiro\agents\*'
        'check kiro.hooks %USERPROFILE%\.kiro\hooks\*.json'
        'check kiro.prompt_library %USERPROFILE%\.kiro\prompts\*'
        'check kiro.cli_settings %USERPROFILE%\.kiro\settings\cli.json'
        'check kiro.mcp_config_user %USERPROFILE%\.kiro\settings\mcp.json'
        'check kiro.permissions_user %USERPROFILE%\.kiro\settings\permissions.yaml'
        'check kiro.steering_user %USERPROFILE%\.kiro\steering\*.md'
        'check kiro.permissions_workspace %USERPROFILE%\.kiro\workspace-roots'
        'walk kiro.managed_settings C:\ProgramData\Kiro\managed-settings.json'
    )
    'lmstudio' = @(
        'walk lmstudio.cli_and_server,lmstudio.conversations,lmstudio.hub_downloads,lmstudio.mcp_config,lmstudio.models,lmstudio.presets %USERPROFILE%\.lmstudio'
        'check lmstudio.cli_and_server %USERPROFILE%\.lmstudio\bin\lms.exe'
        'check lmstudio.presets %USERPROFILE%\.lmstudio\config-presets'
        'check lmstudio.conversations %USERPROFILE%\.lmstudio\conversations'
        'check lmstudio.hub_downloads %USERPROFILE%\.lmstudio\hub'
        'check lmstudio.mcp_config %USERPROFILE%\.lmstudio\mcp.json'
        'check lmstudio.models %USERPROFILE%\.lmstudio\models'
    )
    'ollama' = @(
        'walk ollama.app_chat_database,ollama.app_config,ollama.logs %LOCALAPPDATA%\Ollama'
        'check ollama.logs %LOCALAPPDATA%\Ollama\app.log'
        'check ollama.app_config %LOCALAPPDATA%\Ollama\config.json'
        'check ollama.app_chat_database %LOCALAPPDATA%\Ollama\db.sqlite'
        'check ollama.app_chat_database %LOCALAPPDATA%\Ollama\db.sqlite-wal'
        'check ollama.logs %LOCALAPPDATA%\Ollama\server-*.log'
        'check ollama.logs %LOCALAPPDATA%\Ollama\server.log'
        'check ollama.logs %LOCALAPPDATA%\Ollama\upgrade.log'
        'walk ollama.cli_config,ollama.cli_prompt_history,ollama.model_manifests %USERPROFILE%\.ollama'
        'check ollama.cli_prompt_history %USERPROFILE%\.ollama\history'
        'check ollama.model_blobs %USERPROFILE%\.ollama\models\blobs\sha256-*'
        'check ollama.model_manifests %USERPROFILE%\.ollama\models\manifests'
        'check ollama.cli_config %USERPROFILE%\.ollama\server.json'
    )
    'opencode' = @(
        'walk opencode.auth %LOCALAPPDATA%\opencode\auth.json'
        'walk opencode.managed_config %ProgramData%\opencode'
        'walk opencode.install_and_runtime_trees %USERPROFILE%\.cache\opencode\bin\**'
        'walk opencode.db,opencode.log %USERPROFILE%\.local\share\opencode'
        'check opencode.log %USERPROFILE%\.local\share\opencode\log'
        'check opencode.db %USERPROFILE%\.local\share\opencode\opencode.db'
        'check opencode.db %USERPROFILE%\.local\share\opencode\opencode.db-shm'
        'check opencode.db %USERPROFILE%\.local\share\opencode\opencode.db-wal'
        'walk opencode.state_and_temp %USERPROFILE%\.local\state\opencode'
    )
    'qwen_code' = @(
        'walk qwen_code.ide_connection_locks %TEMP%\qwen-code-ide-server-*.json'
        'walk qwen_code.user_extension_points %USERPROFILE%\.agents\skills\**'
        'walk qwen_code.env_files %USERPROFILE%\.env'
        'walk qwen_code.arena_worktrees,qwen_code.audit_landing,qwen_code.auto_memory,qwen_code.channels_scheduled_tasks,qwen_code.conversation_transcript,qwen_code.env_files,qwen_code.file_history_backups,qwen_code.install_evidence,qwen_code.mcp_approvals,qwen_code.mcp_oauth_tokens,qwen_code.project_temp_spill,qwen_code.prompt_history_log,qwen_code.prompt_terminal_ledger,qwen_code.qwen_oauth_credentials,qwen_code.session_sidecars,qwen_code.shell_history,qwen_code.subagent_transcripts,qwen_code.trusted_folders,qwen_code.usage_history,qwen_code.user_instructions,qwen_code.user_settings,qwen_code.workflow_generated_scripts,qwen_code.workflow_run_journals,qwen_code.workflow_run_snapshots %USERPROFILE%\.qwen'
        'check qwen_code.env_files %USERPROFILE%\.qwen\.env'
        'check qwen_code.user_instructions %USERPROFILE%\.qwen\AGENTS.md'
        'check qwen_code.user_instructions %USERPROFILE%\.qwen\QWEN.md'
        'check qwen_code.user_extension_points %USERPROFILE%\.qwen\agents\<name>.md'
        'check qwen_code.arena_worktrees %USERPROFILE%\.qwen\arena'
        'check qwen_code.audit_landing %USERPROFILE%\.qwen\audits'
        'check qwen_code.install_evidence %USERPROFILE%\.qwen\bin\**'
        'check qwen_code.channels_scheduled_tasks %USERPROFILE%\.qwen\channels\cron.json'
        'check qwen_code.channels_scheduled_tasks %USERPROFILE%\.qwen\channels\service.pid'
        'check qwen_code.channels_scheduled_tasks %USERPROFILE%\.qwen\channels\sessions.json'
        'check qwen_code.user_extension_points %USERPROFILE%\.qwen\commands\**'
        'check qwen_code.debug_logs %USERPROFILE%\.qwen\debug\<session-id>.txt'
        'check qwen_code.user_extension_points %USERPROFILE%\.qwen\extensions\**'
        'check qwen_code.file_history_backups %USERPROFILE%\.qwen\file-history'
        'check qwen_code.ide_connection_locks %USERPROFILE%\.qwen\ide\*.lock'
        'check qwen_code.install_evidence %USERPROFILE%\.qwen\installation_id'
        'check qwen_code.mcp_oauth_tokens %USERPROFILE%\.qwen\mcp-oauth-tokens-v2.json'
        'check qwen_code.mcp_oauth_tokens %USERPROFILE%\.qwen\mcp-oauth-tokens.json'
        'check qwen_code.mcp_approvals %USERPROFILE%\.qwen\mcpApprovals.json'
        'check qwen_code.auto_memory %USERPROFILE%\.qwen\memories\*'
        'check qwen_code.user_instructions %USERPROFILE%\.qwen\memory.md'
        'check qwen_code.qwen_oauth_credentials %USERPROFILE%\.qwen\oauth_creds.json'
        'check qwen_code.qwen_oauth_credentials %USERPROFILE%\.qwen\oauth_creds.lock'
        'check qwen_code.plan_files %USERPROFILE%\.qwen\plans\<session-id>.md'
        'check qwen_code.auto_memory,qwen_code.conversation_transcript,qwen_code.prompt_terminal_ledger,qwen_code.session_sidecars,qwen_code.subagent_transcripts,qwen_code.workflow_generated_scripts,qwen_code.workflow_run_journals,qwen_code.workflow_run_snapshots %USERPROFILE%\.qwen\projects'
        'check qwen_code.user_extension_points %USERPROFILE%\.qwen\rules\**'
        'check qwen_code.session_registry %USERPROFILE%\.qwen\sessions\<pid>.json'
        'check qwen_code.user_settings %USERPROFILE%\.qwen\settings.json'
        'check qwen_code.user_extension_points %USERPROFILE%\.qwen\skills\**'
        'check qwen_code.install_evidence %USERPROFILE%\.qwen\source.json'
        'check qwen_code.project_temp_spill,qwen_code.prompt_history_log,qwen_code.shell_history %USERPROFILE%\.qwen\tmp'
        'check qwen_code.trusted_folders %USERPROFILE%\.qwen\trustedFolders.json'
        'check qwen_code.install_evidence %USERPROFILE%\.qwen\updates\npm'
        'check qwen_code.usage_history %USERPROFILE%\.qwen\usage_record.jsonl'
        'check qwen_code.user_extension_points %USERPROFILE%\.qwen\workflows\<name>.js'
        'walk qwen_code.system_settings C:\ProgramData'
        'check qwen_code.system_settings C:\ProgramData\qwen-code\settings.json'
        'check qwen_code.system_settings C:\ProgramData\qwen-code\system-defaults.json'
    )
    'roo_code' = @(
        'walk roo_code.global_dirs %USERPROFILE%\.roo'
    )
    'vscode' = @(
        'walk vscode.state_vscdb,vscode.user_data_roots %APPDATA%\Code'
        'check vscode.user_data_roots %APPDATA%\Code\User\globalStorage'
        'check vscode.state_vscdb %APPDATA%\Code\User\globalStorage\state.vscdb'
        'check vscode.state_vscdb %APPDATA%\Code\User\globalStorage\state.vscdb-shm'
        'check vscode.state_vscdb %APPDATA%\Code\User\globalStorage\state.vscdb-wal'
        'walk vscode.extension_dirs,vscode.extension_install_evidence,vscode.file_policy,vscode.runtime_arguments %USERPROFILE%\.vscode'
        'walk vscode.file_policy,vscode.runtime_arguments %USERPROFILE%\.vscode-insiders'
        'check vscode.runtime_arguments %USERPROFILE%\.vscode-insiders\argv.json'
        'check vscode.file_policy %USERPROFILE%\.vscode-insiders\policy.json'
        'check vscode.runtime_arguments %USERPROFILE%\.vscode\argv.json'
        'check vscode.extension_dirs,vscode.extension_install_evidence %USERPROFILE%\.vscode\extensions'
        'check vscode.file_policy %USERPROFILE%\.vscode\policy.json'
    )
    'warp' = @(
        'walk warp.cli_settings,warp.mcp_logs,warp.sqlite %LOCALAPPDATA%\warp'
        'check warp.cli_settings %LOCALAPPDATA%\warp\Warp\config\cli\settings.toml'
        'check warp.mcp_logs %LOCALAPPDATA%\warp\Warp\data\logs\mcp'
        'check warp.sqlite %LOCALAPPDATA%\warp\Warp\data\warp.sqlite'
        'check warp.sqlite %LOCALAPPDATA%\warp\Warp\data\warp.sqlite-shm'
        'check warp.sqlite %LOCALAPPDATA%\warp\Warp\data\warp.sqlite-wal'
    )
    'windsurf' = @(
        'walk windsurf.cli_feature_state,windsurf.cli_sessions_db,windsurf.device_identity,windsurf.ide_global_state_vscdb,windsurf.ide_user_data,windsurf.ide_workspace_state_vscdb,windsurf.local_file_history,windsurf.mcp_oauth_state %APPDATA%\Devin'
        'check windsurf.device_identity %APPDATA%\Devin\.devin-migration-complete'
        'check windsurf.local_file_history %APPDATA%\Devin\User\History'
        'check windsurf.acp_message_stores %APPDATA%\Devin\User\acp-messages\<session-uuid>.db'
        'check windsurf.acp_message_stores %APPDATA%\Devin\User\acp-messages\<session-uuid>.db-shm'
        'check windsurf.acp_message_stores %APPDATA%\Devin\User\acp-messages\<session-uuid>.db-wal'
        'check windsurf.ide_user_data %APPDATA%\Devin\User\chatLanguageModels.json'
        'check windsurf.ide_global_state_vscdb %APPDATA%\Devin\User\globalStorage\state.vscdb'
        'check windsurf.ide_global_state_vscdb %APPDATA%\Devin\User\globalStorage\state.vscdb-shm'
        'check windsurf.ide_global_state_vscdb %APPDATA%\Devin\User\globalStorage\state.vscdb-wal'
        'check windsurf.ide_global_state_vscdb %APPDATA%\Devin\User\globalStorage\state.vscdb.backup'
        'check windsurf.ide_user_data %APPDATA%\Devin\User\settings.json'
        'check windsurf.ide_workspace_state_vscdb %APPDATA%\Devin\User\workspaceStorage'
        'check windsurf.ide_user_data %APPDATA%\Devin\Workspaces'
        'check windsurf.device_identity %APPDATA%\Devin\cli\installation_id'
        'check windsurf.cli_logs %APPDATA%\Devin\cli\logs\devin_<yyyymmdd-hhmmss>_<pid>.log'
        'check windsurf.cli_feature_state %APPDATA%\Devin\cli\plugins\discovered.json'
        'check windsurf.cli_feature_state %APPDATA%\Devin\cli\plugins\lock.json'
        'check windsurf.cli_session_locks %APPDATA%\Devin\cli\session_locks\<session-name>.lock'
        'check windsurf.cli_sessions_db %APPDATA%\Devin\cli\sessions.db'
        'check windsurf.cli_sessions_db %APPDATA%\Devin\cli\sessions.db-shm'
        'check windsurf.cli_sessions_db %APPDATA%\Devin\cli\sessions.db-wal'
        'check windsurf.ide_user_data %APPDATA%\Devin\config.json'
        'check windsurf.device_identity %APPDATA%\Devin\machineid'
        'check windsurf.mcp_oauth_state %APPDATA%\Devin\mcp\oauth'
        'walk windsurf.ide_global_state_vscdb,windsurf.ide_user_data,windsurf.ide_workspace_state_vscdb,windsurf.local_file_history %APPDATA%\Windsurf'
        'walk windsurf.ide_global_state_vscdb %APPDATA%\Windsurf - Next'
        'check windsurf.ide_global_state_vscdb %APPDATA%\Windsurf - Next\User\globalStorage\state.vscdb'
        'check windsurf.ide_global_state_vscdb %APPDATA%\Windsurf - Next\User\globalStorage\state.vscdb-shm'
        'check windsurf.ide_global_state_vscdb %APPDATA%\Windsurf - Next\User\globalStorage\state.vscdb-wal'
        'walk windsurf.ide_global_state_vscdb %APPDATA%\Windsurf Insiders'
        'check windsurf.ide_global_state_vscdb %APPDATA%\Windsurf Insiders\User\globalStorage\state.vscdb'
        'check windsurf.ide_global_state_vscdb %APPDATA%\Windsurf Insiders\User\globalStorage\state.vscdb-shm'
        'check windsurf.ide_global_state_vscdb %APPDATA%\Windsurf Insiders\User\globalStorage\state.vscdb-wal'
        'check windsurf.local_file_history %APPDATA%\Windsurf\User\History'
        'check windsurf.ide_global_state_vscdb %APPDATA%\Windsurf\User\globalStorage\state.vscdb'
        'check windsurf.ide_global_state_vscdb %APPDATA%\Windsurf\User\globalStorage\state.vscdb-shm'
        'check windsurf.ide_global_state_vscdb %APPDATA%\Windsurf\User\globalStorage\state.vscdb-wal'
        'check windsurf.ide_user_data %APPDATA%\Windsurf\User\keybindings.json'
        'check windsurf.ide_user_data %APPDATA%\Windsurf\User\settings.json'
        'check windsurf.ide_workspace_state_vscdb %APPDATA%\Windsurf\User\workspaceStorage'
        'check windsurf.ide_user_data %APPDATA%\Windsurf\argv.json'
        'walk windsurf.language_server_binaries_and_logs %LOCALAPPDATA%\Programs\Windsurf'
        'walk windsurf.temp_residue %LOCALAPPDATA%\Temp'
        'check windsurf.temp_residue %LOCALAPPDATA%\Temp\devin-inno-updater-<epoch>.log'
        'check windsurf.temp_residue %LOCALAPPDATA%\Temp\unleash-backup-codeium-extension.json'
        'check windsurf.temp_residue %LOCALAPPDATA%\Temp\unleash-repo-schema-v1-codeium-language-server.json'
        'walk windsurf.cli_feature_state %LOCALAPPDATA%\devin\cli\<name>.<hash>.bin'
        'walk windsurf.cli_feature_state %LOCALAPPDATA%\devin\telemetry_state.json'
        'walk windsurf.code_tracker_and_settings,windsurf.global_rules,windsurf.hooks,windsurf.ignore_files,windsurf.mcp_config,windsurf.plugin_log %USERPROFILE%\.codeium'
        'check windsurf.ignore_files %USERPROFILE%\.codeium\.codeiumignore'
        'check windsurf.plugin_log %USERPROFILE%\.codeium\codeium.log'
        'check windsurf.hooks %USERPROFILE%\.codeium\hooks.json'
        'check windsurf.code_tracker_and_settings %USERPROFILE%\.codeium\user_settings.pb'
        'check windsurf.code_tracker_and_settings %USERPROFILE%\.codeium\windsurf\brain'
        'check windsurf.cascade_trajectories %USERPROFILE%\.codeium\windsurf\cascade\*'
        'check windsurf.code_tracker_and_settings %USERPROFILE%\.codeium\windsurf\code_tracker'
        'check windsurf.code_tracker_and_settings %USERPROFILE%\.codeium\windsurf\codemaps\codemapindex.json'
        'check windsurf.code_tracker_and_settings %USERPROFILE%\.codeium\windsurf\context_state'
        'check windsurf.embedding_database %USERPROFILE%\.codeium\windsurf\database\<hash>'
        'check windsurf.hooks %USERPROFILE%\.codeium\windsurf\hooks.json'
        'check windsurf.implicit_trajectories %USERPROFILE%\.codeium\windsurf\implicit\*.pb'
        'check windsurf.code_tracker_and_settings %USERPROFILE%\.codeium\windsurf\installation_id'
        'check windsurf.mcp_config %USERPROFILE%\.codeium\windsurf\mcp_config.json'
        'check windsurf.memories %USERPROFILE%\.codeium\windsurf\memories\*'
        'check windsurf.global_rules %USERPROFILE%\.codeium\windsurf\memories\global_rules.md'
        'check windsurf.code_tracker_and_settings %USERPROFILE%\.codeium\windsurf\user_settings.pb'
        'walk windsurf.ide_user_data %USERPROFILE%\.devin'
        'walk windsurf.server_data %USERPROFILE%\.devin-server\**'
        'walk windsurf.shared_storage %USERPROFILE%\.devin-shared'
        'check windsurf.shared_storage %USERPROFILE%\.devin-shared\sharedStorage\state.vscdb'
        'check windsurf.shared_storage %USERPROFILE%\.devin-shared\sharedStorage\state.vscdb-shm'
        'check windsurf.shared_storage %USERPROFILE%\.devin-shared\sharedStorage\state.vscdb-wal'
        'check windsurf.shared_storage %USERPROFILE%\.devin-shared\sharedStorage\state.vscdb.backup'
        'check windsurf.ide_user_data %USERPROFILE%\.devin\.devin-argv-precopy'
        'check windsurf.ide_user_data %USERPROFILE%\.devin\argv.json'
        'check windsurf.ide_user_data %USERPROFILE%\.devin\extensions\extensions.json'
        'walk windsurf.acp_registry,windsurf.plans %USERPROFILE%\.windsurf'
        'walk windsurf.server_data %USERPROFILE%\.windsurf-server\**'
        'check windsurf.acp_registry %USERPROFILE%\.windsurf\acp\registry.json'
        'check windsurf.plans %USERPROFILE%\.windsurf\plans'
        'check windsurf.cascade_transcripts %USERPROFILE%\.windsurf\transcripts\*.jsonl'
        'check windsurf.worktrees %USERPROFILE%\.windsurf\worktrees\*'
        'walk windsurf.language_server_binaries_and_logs C:\Program Files\Windsurf'
        'walk windsurf.system_config C:\ProgramData'
        'check windsurf.system_config C:\ProgramData\Devin\rules\*.md'
        'check windsurf.system_config C:\ProgramData\Windsurf\hooks.json'
        'check windsurf.system_config C:\ProgramData\Windsurf\rules\*.md'
        'check windsurf.system_config C:\ProgramData\Windsurf\skills'
        'check windsurf.system_config C:\ProgramData\Windsurf\workflows'
        'walk windsurf.enterprise_policy_templates C:\Windows\PolicyDefinitions'
        'check windsurf.enterprise_policy_templates C:\Windows\PolicyDefinitions\en-US\windsurf.adml'
        'check windsurf.enterprise_policy_templates C:\Windows\PolicyDefinitions\windsurf.admx'
    )
    'zed' = @(
        'walk zed.settings,zed.user_agent_instructions,zed.user_configuration %APPDATA%\Zed'
        'check zed.user_agent_instructions %APPDATA%\Zed\AGENTS.md'
        'check zed.user_configuration %APPDATA%\Zed\debug.json'
        'check zed.user_configuration %APPDATA%\Zed\global_settings.json'
        'check zed.user_configuration %APPDATA%\Zed\keymap.json'
        'check zed.user_configuration %APPDATA%\Zed\keymap_backup.json'
        'check zed.settings %APPDATA%\Zed\settings.json'
        'check zed.user_configuration %APPDATA%\Zed\settings_backup.json'
        'check zed.user_configuration %APPDATA%\Zed\tasks.json'
        'walk zed.extensions,zed.logs,zed.prompt_library,zed.semantic_index,zed.sidebar_threads,zed.state_tree,zed.threads_db %LOCALAPPDATA%\Zed'
        'check zed.extensions %LOCALAPPDATA%\Zed\copilot'
        'check zed.sidebar_threads %LOCALAPPDATA%\Zed\db'
        'check zed.extensions %LOCALAPPDATA%\Zed\debug_adapters'
        'check zed.extensions %LOCALAPPDATA%\Zed\devcontainer'
        'check zed.semantic_index %LOCALAPPDATA%\Zed\embeddings'
        'check zed.extensions %LOCALAPPDATA%\Zed\extensions'
        'check zed.extensions %LOCALAPPDATA%\Zed\external_agents'
        'check zed.logs %LOCALAPPDATA%\Zed\logs'
        'check zed.extensions %LOCALAPPDATA%\Zed\prompt_overrides'
        'check zed.prompt_library %LOCALAPPDATA%\Zed\prompts'
        'check zed.extensions %LOCALAPPDATA%\Zed\remote_extensions'
        'check zed.extensions %LOCALAPPDATA%\Zed\remote_servers'
        'check zed.extensions %LOCALAPPDATA%\Zed\server_state'
        'check zed.threads_db %LOCALAPPDATA%\Zed\threads\threads.db'
        'check zed.threads_db %LOCALAPPDATA%\Zed\threads\threads.db-shm'
        'check zed.threads_db %LOCALAPPDATA%\Zed\threads\threads.db-wal'
    )
}

$Tokens = @{
    'amazonq' = @('amazonq', 'amazon')
    'amp' = @('amp', 'sourcegraph')
    'chatgpt_desktop' = @('chatgpt', 'openai')
    'claude_code' = @('claude', 'anthropic')
    'claude_desktop' = @('claude', 'anthropic')
    'cline' = @('cline')
    'codex' = @('codex', 'openai')
    'continue' = @('continue')
    'copilot' = @('copilot', 'github')
    'cursor' = @('cursor', 'anysphere')
    'devin' = @('devin', 'cognition')
    'factory_droid' = @('factory', 'droid')
    'gemini_cli' = @('gemini', 'google')
    'goose' = @('goose', 'block')
    'hermes' = @('hermes')
    'jetbrains_ai' = @('jetbrains')
    'junie' = @('junie', 'jetbrains')
    'kilo_code' = @('kilo')
    'kiro' = @('kiro', 'amazon')
    'lmstudio' = @('lmstudio', 'element')
    'ollama' = @('ollama')
    'opencode' = @('opencode')
    'qwen_code' = @('qwen', 'alibaba')
    'roo_code' = @('roo')
    'vscode' = @('vscode', 'microsoft')
    'warp' = @('warp')
    'windsurf' = @('windsurf', 'cognition')
    'zed' = @('zed', 'industries')
}
# END generated probes

if ($List) {
    ($Probes.Keys | Sort-Object) | ForEach-Object { Write-Output $_ }
    exit 0
}

Write-Output ("host: " + [System.Environment]::OSVersion.VersionString)
Write-Output ("powershell: " + $PSVersionTable.PSVersion.ToString())
Write-Output ("depth: " + $Depth)
Write-Output ("taken: " + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))

if ($Family -eq 'all') {
    foreach ($name in ($Probes.Keys | Sort-Object)) { Measure-Family $name }
}
else {
    Measure-Family $Family
}

Write-Section 'done'
Write-Output 'Read this file before sending it. Delete any line you would rather not share.'
