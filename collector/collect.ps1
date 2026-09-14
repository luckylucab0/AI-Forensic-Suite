<#
.SYNOPSIS
    Collect AI coding agent artifacts from a Windows endpoint into an evidence bundle.

.DESCRIPTION
    Single file, no modules, PowerShell 5.1 or newer. That is not minimalism: it is what
    lets this be pushed through EDR live response or a remote session and run on a machine
    where nothing may be installed and nothing may be downloaded. Several agents delete
    their own history on a 30 day default schedule, so the difference between collecting
    today and scheduling it for next week is evidence.

    This is the Windows half of a format implemented twice. The other half is collect.py
    for macOS and Linux, and the format both must produce is specified in
    docs/BUNDLE_FORMAT.md. Where this file and that document disagree, the document is
    right and this is a bug.

    Non-negotiable behaviors, each of which the conformance suite checks:

      * Nothing outside -Out is ever written. No temp files, no logs, no config.
      * Nothing on the target is modified, moved, renamed or deleted, and no agent binary
        is executed.
      * Artifacts marked sensitivity: secret are recorded as metadata and a hash only.
        Their content is copied only with -IncludeSecrets, and that choice goes in the
        manifest.
      * Collection is ordered by how fast an artifact disappears, not alphabetically.
      * Output is byte-identical to what collect.py writes for the same tree, apart from
        the fields docs/BUNDLE_FORMAT.md lists as allowed to differ. That is why this file
        carries its own JSON serializer: ConvertTo-Json does not produce the same bytes,
        and a manifest that cannot be compared byte for byte cannot be diffed between the
        two implementations.

    PowerShell 5.1 specifics that would silently break parity, each handled explicitly:

      * Set-Content and Out-File default to UTF-16LE on 5.1. Every write here goes through
        [System.IO.File]::WriteAllText with a UTF8 encoding that emits no byte order mark.
      * Hashtable key order is not insertion order, so every ordered structure uses
        [ordered]@{} and the serializer sorts keys anyway.
      * Date formatting is culture dependent, so every timestamp uses InvariantCulture.
      * MAX_PATH truncates long paths, so file access uses the \\?\ prefix where needed.
      * A one-element array returned from a function is unwrapped to the element and an
        empty one becomes $null, which would serialize a one-file manifest as an object and
        a no-file manifest as null. Every array-valued field is a List[object] built in
        place, and lists are built with ::new() rather than New-Object, because @() cannot
        copy a List[object] that New-Object produced.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File collect.ps1 -Out C:\case-001

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File collect.ps1 -Out C:\case-001 -AllUsers -Zip

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File collect.ps1 -DryRun -Json
#>

[CmdletBinding()]
param(
    [string] $Out,
    [switch] $Zip,
    [string[]] $User,
    [switch] $AllUsers,
    [string[]] $Agents,
    [switch] $IncludeSecrets,
    [long] $MaxFileSize = 268435456,
    [int] $MaxFilesPerArtifact = 20000,
    [string] $Root,
    [ValidateSet('macos', 'linux', 'windows')]
    [string] $TargetOs,
    [switch] $DryRun,
    [switch] $Json,
    [switch] $Version,
    [switch] $SelfTest,
    [switch] $Sourced
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Everything this script writes to standard output is UTF-8 without a byte order mark,
# whether it goes to a console or into a pipe.
#
# Not cosmetic. On PowerShell 5.1 a redirected [Console]::Out inherits the console's output
# encoding, which is an OEM code page, so the -Json summary came out mangled the moment a
# path contained a non-ASCII character, and `>` in 5.1 writes UTF-16LE, which anything
# reading the output as UTF-8 rejects at the first byte. A fleet script that pipes this
# collector into something else has to get the same bytes on every host.
try {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
} catch {
    # A host without a real console, such as some remote-execution agents, refuses to have
    # this set. The bundle on disk is written through System.IO with an explicit encoding
    # and is unaffected; only the summary on stdout is.
}

$script:ToolName = 'collect.ps1'
$script:ToolVersion = '0.1.0'
$script:FormatVersion = 1

$script:ExitOk = 0
$script:ExitErrors = 1
$script:ExitUsage = 2
$script:ExitNothingFound = 3

# Collection order. live_only artifacts are destroyed by a clean shutdown and cannot be
# recovered from a powered-off image, so they come first however small they are.
$script:PriorityOrder = @('live_only', 'first', 'normal', 'durable')

# Recorded in the manifest so a bundle says how it was collected. $MyInvocation.Line would
# carry the whole command including the interpreter and the path to this file, which on a
# live-response console can hold a case number or an operator's name, so only the bound
# arguments are kept.
$script:RawArguments = [System.Collections.Generic.List[string]]::new()
foreach ($name in ($PSBoundParameters.Keys | Sort-Object -CaseSensitive)) {
    $value = $PSBoundParameters[$name]
    if ($value -is [switch]) {
        if ([bool]$value) { $script:RawArguments.Add('-' + $name) }
        continue
    }
    $script:RawArguments.Add('-' + $name)
    foreach ($item in @($value)) { $script:RawArguments.Add([string]$item) }
}

# --- BEGIN EMBEDDED CATALOGUE ---
# Rendered from catalog/*.yaml by scripts/build_collectors.py. Do not edit by hand: CI
# regenerates it and fails if this block is stale.
$EmbeddedCatalogueJson = @'
{
    "agents": [
        {
            "agent": "aider",
            "artifacts": [
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "aider.analytics",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.aider/analytics.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "cache",
                    "collect_priority": "normal",
                    "id": "aider.caches",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.aider/caches/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "aider.chat_history",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.aider.chat.history.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "aider.config",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.aider.conf.yml",
                        "~/.aider.conf.yml"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "aider.dotenv",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.env",
                        "~/.env"
                    ],
                    "root": "project",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "prompt_history",
                    "collect_priority": "normal",
                    "id": "aider.input_history",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.aider.input.history"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "aider.model_metadata",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.aider.model.metadata.json",
                        "~/.aider.model.metadata.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "aider.model_settings",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.aider.model.settings.yml",
                        "~/.aider.model.settings.yml"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "cache",
                    "collect_priority": "live_only",
                    "id": "aider.tags_cache",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.aider.tags.cache.v3/",
                        "<project>/.aider.tags.cache.v4/"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                }
            ]
        },
        {
            "agent": "amp",
            "artifacts": [
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "amp.continuations",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.local/share/amp/continuations/*.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "amp.ledger",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$XDG_DATA_HOME/amp/ledger.jsonl",
                        "%APPDATA%\\amp\\ledger.jsonl",
                        "~/.local/share/amp/ledger.jsonl"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "amp.secrets",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%APPDATA%\\amp\\secrets.json",
                        "~/.amp/oauth/",
                        "~/.local/share/amp/secrets.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "unverified"
                },
                {
                    "category": "config",
                    "collect_priority": "first",
                    "id": "amp.session_pointer",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.local/share/amp/session.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "amp.settings",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$XDG_CONFIG_HOME/amp/settings.json",
                        "<project>/.amp/settings.json",
                        "<project>/.amp/settings.jsonc",
                        "~/.config/amp/settings.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "amp.thread_logs",
                    "os": [
                        "macos",
                        "linux"
                    ],
                    "paths": [
                        "~/.cache/amp/logs/threads/*.log"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "amp.threads",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$XDG_DATA_HOME/amp/threads/T-*.json",
                        "%APPDATA%\\amp\\threads\\T-*.json",
                        "~/.local/share/amp/threads/T-*.json",
                        "~/Library/Application Support/amp/threads/T-*.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                }
            ]
        },
        {
            "agent": "chatgpt_desktop",
            "artifacts": [
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "chatgpt_desktop.macos_app_pairing_extensions",
                    "os": [
                        "macos"
                    ],
                    "paths": [
                        "~/Library/Application Support/com.openai.chat/app_pairing_extensions/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "chatgpt_desktop.macos_codex_app_support",
                    "os": [
                        "macos"
                    ],
                    "paths": [
                        "~/Library/Application Support/Codex/",
                        "~/Library/Application Support/OpenAI/Codex/",
                        "~/Library/Application Support/com.openai.codex/",
                        "~/Library/Caches/Codex/",
                        "~/Library/Caches/com.openai.codex/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "chatgpt_desktop.macos_codex_home",
                    "os": [
                        "macos"
                    ],
                    "paths": [
                        "~/.codex/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "chatgpt_desktop.macos_computer_use_service",
                    "os": [
                        "macos"
                    ],
                    "paths": [
                        "/Library/Application Support/CodexComputerUseAuthorizationPlugin/",
                        "~/Library/Caches/com.openai.sky.CUAService/",
                        "~/Library/Group Containers/*.com.openai.sky.CUAService/",
                        "~/Library/HTTPStorages/com.openai.sky.CUAService/",
                        "~/Library/Preferences/com.openai.sky.CUAService.cli.plist",
                        "~/Library/Preferences/com.openai.sky.CUAService.plist"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "chatgpt_desktop.macos_cookies",
                    "os": [
                        "macos"
                    ],
                    "paths": [
                        "~/Library/HTTPStorages/com.openai.chat.binarycookies",
                        "~/Library/HTTPStorages/com.openai.codex.binarycookies",
                        "~/Library/HTTPStorages/com.openai.sky.CUAService.binarycookies"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "unverified"
                },
                {
                    "category": "cache",
                    "collect_priority": "normal",
                    "id": "chatgpt_desktop.macos_httpstorages",
                    "os": [
                        "macos"
                    ],
                    "paths": [
                        "~/Library/HTTPStorages/ChatGPTHelper.binarycookies",
                        "~/Library/HTTPStorages/com.openai.chat/",
                        "~/Library/HTTPStorages/com.openai.codex/",
                        "~/Library/HTTPStorages/com.openai.sky.CUAService/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "chatgpt_desktop.macos_legacy_app_support",
                    "os": [
                        "macos"
                    ],
                    "paths": [
                        "~/Library/Application Scripts/com.openai.chat.Widgets/",
                        "~/Library/Application Scripts/group.com.openai.chat/",
                        "~/Library/Application Support/ChatGPT/",
                        "~/Library/Application Support/com.openai.chat/",
                        "~/Library/Caches/com.openai.chat/",
                        "~/Library/Containers/com.openai.chat.Widgets/",
                        "~/Library/Group Containers/group.com.openai.chat/",
                        "~/Library/WebKit/com.openai.chat/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "chatgpt_desktop.macos_legacy_conversations_dir",
                    "os": [
                        "macos"
                    ],
                    "paths": [
                        "~/Library/Application Support/com.openai.chat/conversations-*/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "chatgpt_desktop.macos_preferences",
                    "os": [
                        "macos"
                    ],
                    "paths": [
                        "~/Library/Preferences/ChatGPTHelper.plist",
                        "~/Library/Preferences/com.openai.chat.*.plist",
                        "~/Library/Preferences/com.openai.chat.plist",
                        "~/Library/Preferences/com.openai.codex.plist"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "chatgpt_desktop.macos_saved_state_and_logs",
                    "os": [
                        "macos"
                    ],
                    "paths": [
                        "~/Library/Logs/com.openai.codex/",
                        "~/Library/Saved Application State/com.openai.chat.savedState/",
                        "~/Library/Saved Application State/com.openai.codex.savedState/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "chatgpt_desktop.windows_msix_localcache",
                    "os": [
                        "windows"
                    ],
                    "paths": [
                        "%LOCALAPPDATA%\\Packages\\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0\\LocalCache\\Roaming\\ChatGPT\\",
                        "%LOCALAPPDATA%\\Packages\\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0\\LocalCache\\Roaming\\ChatGPT\\IndexedDB\\https_chatgpt.com_0.indexeddb.leveldb\\",
                        "%LOCALAPPDATA%\\Packages\\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0\\LocalCache\\Roaming\\ChatGPT\\Local Storage\\leveldb\\"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                }
            ]
        },
        {
            "agent": "claude_code",
            "artifacts": [
                {
                    "category": "memory",
                    "collect_priority": "durable",
                    "id": "claude_code.agent_memory",
                    "os": [
                        "linux",
                        "macos",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.claude\\agent-memory\\*",
                        "<project>/.claude/agent-memory-local/<agent-name>/",
                        "<project>/.claude/agent-memory/<agent-name>/",
                        "<project>/.claude/agent-memory/<agent-name>/MEMORY.md",
                        "~/.claude/agent-memory/<agent-name>/",
                        "~/.claude/agent-memory/<agent-name>/MEMORY.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "durable",
                    "id": "claude_code.agents",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/agents/*.md",
                        "<project>/.claude/agents/*.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "claude_code.anthropic_active_config",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.config/anthropic/active_config",
                        "%APPDATA%\\Anthropic\\active_config",
                        "$ANTHROPIC_CONFIG_DIR/active_config"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "claude_code.anthropic_profile_configs",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.config/anthropic/configs/<profile>.json",
                        "%APPDATA%\\Anthropic\\configs\\<profile>.json",
                        "$ANTHROPIC_CONFIG_DIR/configs/<profile>.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "claude_code.anthropic_profile_credentials",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.config/anthropic/credentials/<profile>.json",
                        "%APPDATA%\\Anthropic\\credentials\\<profile>.json",
                        "$ANTHROPIC_CONFIG_DIR/credentials/<profile>.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "memory",
                    "collect_priority": "durable",
                    "id": "claude_code.auto_memory",
                    "os": [
                        "linux",
                        "macos",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.claude\\projects\\*\\memory\\*.md",
                        "~/.claude/projects/<project>/memory/*.md",
                        "~/.claude/projects/<project>/memory/MEMORY.md"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "claude_code.changelog_cache",
                    "os": [
                        "linux",
                        "macos",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.claude\\cache\\changelog.md",
                        "~/.claude/cache/changelog.md"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "durable",
                    "id": "claude_code.commands",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/commands/*.md",
                        "<project>/.claude/commands/*.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "first",
                    "id": "claude_code.config_backups",
                    "os": [
                        "linux",
                        "macos",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.claude\\backups\\*",
                        "~/.claude/backups/",
                        "~/.claude/backups/*",
                        "~/.claude/backups/.claude.json.corrupted.<timestamp>"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "first",
                    "id": "claude_code.credentials",
                    "os": [
                        "linux",
                        "macos",
                        "windows"
                    ],
                    "paths": [
                        "$CLAUDE_CONFIG_DIR/.credentials.json",
                        "%USERPROFILE%\\.claude\\.credentials.json",
                        "~/.claude/.credentials.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "claude_code.daemon_state",
                    "os": [
                        "linux",
                        "macos",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.claude\\daemon.log",
                        "%USERPROFILE%\\.claude\\daemon\\roster.json",
                        "~/.claude/daemon.lock",
                        "~/.claude/daemon.log",
                        "~/.claude/daemon/roster.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "claude_code.debug_logs",
                    "os": [
                        "linux",
                        "macos",
                        "windows"
                    ],
                    "paths": [
                        "$CLAUDE_CODE_DEBUG_LOGS_DIR/",
                        "%USERPROFILE%\\.claude\\debug\\*.txt",
                        "~/.claude/debug/*.txt",
                        "~/.claude/debug/<session-id>.txt"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "claude_code.feedback_bundles",
                    "os": [
                        "linux",
                        "macos",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.claude\\feedback-bundles\\*",
                        "~/.claude/feedback-bundles/",
                        "~/.claude/feedback-bundles/*",
                        "~/.claude/feedback/drafts/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "first",
                    "id": "claude_code.feedback_drafts",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/feedback/drafts/",
                        "~/.claude/feedback/drafts/*",
                        "%USERPROFILE%\\.claude\\feedback\\drafts\\*"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "file_snapshot",
                    "collect_priority": "first",
                    "id": "claude_code.file_history_snapshots",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/file-history/<session-id>/",
                        "~/.claude/file-history/*/*",
                        "%USERPROFILE%\\.claude\\file-history\\*\\*"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "claude_code.git_global_excludes",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$XDG_CONFIG_HOME/git/ignore",
                        "~/.config/git/ignore"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "durable",
                    "id": "claude_code.global_config",
                    "os": [
                        "linux",
                        "macos",
                        "windows"
                    ],
                    "paths": [
                        "$CLAUDE_CONFIG_DIR/.claude.json",
                        "%USERPROFILE%\\.claude.json",
                        "~/.claude.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "prompt_history",
                    "collect_priority": "durable",
                    "id": "claude_code.history_jsonl",
                    "os": [
                        "linux",
                        "macos",
                        "windows"
                    ],
                    "paths": [
                        "$CLAUDE_CONFIG_DIR/history.jsonl",
                        "%USERPROFILE%\\.claude\\history.jsonl",
                        "~/.claude/history.jsonl"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "cache",
                    "collect_priority": "first",
                    "id": "claude_code.image_cache",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/image-cache/<session-id>/",
                        "~/.claude/image-cache/*/*",
                        "%USERPROFILE%\\.claude\\image-cache\\*\\*"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "claude_code.install_legacy_and_npm",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.claude/local/",
                        "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code",
                        "/usr/lib/node_modules/@anthropic-ai/claude-code",
                        "/usr/local/lib/node_modules/@anthropic-ai/claude-code",
                        "%APPDATA%\\npm\\node_modules\\@anthropic-ai\\claude-code",
                        "~/.npm-global/lib/node_modules/@anthropic-ai/claude-code",
                        "~/.npm-packages/lib/node_modules/@anthropic-ai/claude-code",
                        "~/.nvm/versions/node/<version>/lib/node_modules/@anthropic-ai/claude-code",
                        "~/Library/Application Support/Claude/claude-code/<version>/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "claude_code.install_native",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.local/bin/claude",
                        "~/.local/share/claude/versions/<version>",
                        "%USERPROFILE%\\.local\\bin\\claude.exe"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "durable",
                    "id": "claude_code.jobs",
                    "os": [
                        "linux",
                        "macos",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.claude\\jobs\\*\\state.json",
                        "~/.claude/jobs/*/state.json",
                        "~/.claude/jobs/*/tmp/*",
                        "~/.claude/jobs/<id>/state.json",
                        "~/.claude/jobs/<id>/tmp/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "durable",
                    "id": "claude_code.keybindings",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/keybindings.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "durable",
                    "id": "claude_code.known_marketplaces",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/plugins/known_marketplaces.json",
                        "$CLAUDE_CODE_PLUGIN_CACHE_DIR/known_marketplaces.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "claude_code.legacy_dirs",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/todos/",
                        "~/.claude/statsig/",
                        "~/.claude/logs/",
                        "%USERPROFILE%\\.claude\\todos\\*",
                        "%USERPROFILE%\\.claude\\statsig\\*",
                        "%USERPROFILE%\\.claude\\logs\\*"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "cache",
                    "collect_priority": "normal",
                    "id": "claude_code.legacy_state_dirs",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/todos/",
                        "~/.claude/statsig/",
                        "~/.claude/logs/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "durable",
                    "id": "claude_code.loop_instructions",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/loop.md",
                        "<project>/.claude/loop.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "first",
                    "id": "claude_code.macos_keychain_credentials",
                    "os": [
                        "macos"
                    ],
                    "paths": [
                        "~/Library/Keychains/login.keychain-db"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "durable",
                    "id": "claude_code.managed_claude_md",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "/Library/Application Support/ClaudeCode/CLAUDE.md",
                        "/etc/claude-code/CLAUDE.md",
                        "C:\\Program Files\\ClaudeCode\\CLAUDE.md"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "mcp_config",
                    "collect_priority": "durable",
                    "id": "claude_code.managed_mcp_json",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "/Library/Application Support/ClaudeCode/managed-mcp.json",
                        "/etc/claude-code/managed-mcp.json",
                        "C:\\Program Files\\ClaudeCode\\managed-mcp.json"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "normal",
                    "id": "claude_code.managed_settings_dropins",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "/Library/Application Support/ClaudeCode/managed-settings.d/*.json",
                        "/etc/claude-code/managed-settings.d/*.json",
                        "C:\\Program Files\\ClaudeCode\\managed-settings.d\\*.json"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "durable",
                    "id": "claude_code.managed_settings_file",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "/Library/Application Support/ClaudeCode/managed-settings.json",
                        "/etc/claude-code/managed-settings.json",
                        "C:\\Program Files\\ClaudeCode\\managed-settings.json",
                        "C:\\ProgramData\\ClaudeCode\\managed-settings.json"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "normal",
                    "id": "claude_code.managed_settings_macos_profile",
                    "os": [
                        "macos"
                    ],
                    "paths": [
                        "/Library/Managed Preferences/com.anthropic.claudecode.plist",
                        "/Library/Managed Preferences/<user>/com.anthropic.claudecode.plist"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "normal",
                    "id": "claude_code.managed_settings_registry",
                    "os": [
                        "windows"
                    ],
                    "paths": [
                        "HKLM\\SOFTWARE\\Policies\\ClaudeCode",
                        "HKCU\\SOFTWARE\\Policies\\ClaudeCode"
                    ],
                    "root": "registry",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "durable",
                    "id": "claude_code.mcp_logs",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/Library/Caches/claude-cli-nodejs/<encoded-cwd>/mcp-logs-<server>/<timestamp>.jsonl",
                        "%LOCALAPPDATA%\\claude-cli-nodejs\\Cache\\<encoded-cwd>\\mcp-logs-<server>\\<timestamp>.jsonl",
                        "$XDG_CACHE_HOME/claude-cli-nodejs/<encoded-cwd>/mcp-logs-<server>/<timestamp>.jsonl",
                        "~/.cache/claude-cli-nodejs/<encoded-cwd>/mcp-logs-<server>/<timestamp>.jsonl"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "claude_code.org_policy_cache",
                    "os": [
                        "linux",
                        "macos",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.claude\\policy-limits.json",
                        "%USERPROFILE%\\.claude\\remote-settings.json",
                        "~/.claude/policy-limits.json",
                        "~/.claude/remote-settings.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "durable",
                    "id": "claude_code.output_styles",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/output-styles/*.md",
                        "<project>/.claude/output-styles/*.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "cache",
                    "collect_priority": "normal",
                    "id": "claude_code.paste_cache",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/paste-cache/",
                        "~/.claude/paste-cache/*",
                        "%USERPROFILE%\\.claude\\paste-cache\\*"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "claude_code.plans",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/plans/*.md",
                        "%USERPROFILE%\\.claude\\plans\\*.md"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "cache",
                    "collect_priority": "normal",
                    "id": "claude_code.plugin_cache",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "cache",
                    "collect_priority": "normal",
                    "id": "claude_code.plugin_data",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/plugins/data/<sanitized-plugin-id>/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "claude_code.plugin_manifests",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<plugin-root>/.claude-plugin/plugin.json",
                        "<marketplace-root>/.claude-plugin/marketplace.json",
                        "<plugin-root>/hooks/hooks.json",
                        "<plugin-root>/.mcp.json",
                        "<plugin-root>/.lsp.json",
                        "<plugin-root>/monitors/monitors.json"
                    ],
                    "root": "plugin",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "claude_code.plugin_marketplaces_clones",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/plugins/marketplaces/<name>/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "claude_code.plugins_root",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/plugins/",
                        "$CLAUDE_CODE_PLUGIN_CACHE_DIR/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "claude_code.plugins_synced",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/plugins/synced/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "first",
                    "id": "claude_code.policy_limits",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/policy-limits.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "claude_code.project_claude_local_md",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/CLAUDE.local.md",
                        "<project>/**/CLAUDE.local.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "claude_code.project_claude_md",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/CLAUDE.md",
                        "<project>/.claude/CLAUDE.md",
                        "<project>/**/CLAUDE.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "mcp_config",
                    "collect_priority": "normal",
                    "id": "claude_code.project_mcp_json",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.mcp.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "claude_code.project_rules",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.claude/rules/**/*.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "claude_code.project_settings",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.claude/settings.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "durable",
                    "id": "claude_code.project_settings_local",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.claude/settings.local.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "claude_code.session_env",
                    "os": [
                        "linux",
                        "macos",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.claude\\session-env\\*",
                        "~/.claude/session-env/",
                        "~/.claude/session-env/*"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "live_only",
                    "id": "claude_code.sessions_dir",
                    "os": [
                        "linux",
                        "macos",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.claude\\sessions\\*",
                        "~/.claude/sessions/",
                        "~/.claude/sessions/*"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "claude_code.settings_referenced_executables",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.claude/hooks/*",
                        "~/.claude/hooks/*"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "durable",
                    "id": "claude_code.shell_profile_evidence",
                    "os": [
                        "macos",
                        "linux"
                    ],
                    "paths": [
                        "~/.zshrc",
                        "$ZDOTDIR/.zshrc",
                        "~/.bashrc",
                        "~/.bash_profile",
                        "~/.bash_login",
                        "~/.profile",
                        "~/.config/fish/config.fish"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "shell_history",
                    "collect_priority": "live_only",
                    "id": "claude_code.shell_snapshots",
                    "os": [
                        "linux",
                        "macos",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.claude\\shell-snapshots\\*",
                        "/tmp/claude-shell-snapshot*",
                        "~/.claude/shell-snapshots/",
                        "~/.claude/shell-snapshots/*"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "durable",
                    "id": "claude_code.skills",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/skills/<skill-name>/SKILL.md",
                        "<project>/.claude/skills/<skill-name>/SKILL.md",
                        "/Library/Application Support/ClaudeCode/.claude/skills/<skill-name>/SKILL.md",
                        "/etc/claude-code/.claude/skills/<skill-name>/SKILL.md",
                        "C:\\Program Files\\ClaudeCode\\.claude\\skills\\<skill-name>\\SKILL.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "claude_code.skills_trash",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/skills/.trash/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "cache",
                    "collect_priority": "durable",
                    "id": "claude_code.stats_cache",
                    "os": [
                        "linux",
                        "macos",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.claude\\stats-cache.json",
                        "~/.claude/stats-cache.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "claude_code.subagent_transcripts",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/projects/<project>/<session-id>/subagents/agent-<agentId>.jsonl",
                        "~/.claude/projects/<project>/<session-id>/subagents/agent-<agentId>.meta.json",
                        "~/.claude/projects/*/*/subagents/*.jsonl",
                        "%USERPROFILE%\\.claude\\projects\\*\\*\\subagents\\*.jsonl"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "claude_code.synced_skills",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/skills/synced/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "memory",
                    "collect_priority": "durable",
                    "id": "claude_code.task_lists",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/tasks/",
                        "~/.claude/tasks/*/*",
                        "%USERPROFILE%\\.claude\\tasks\\*\\*"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "durable",
                    "id": "claude_code.themes",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/themes/*.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "claude_code.tool_result_spills",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/projects/<project>/<session-id>/tool-results/",
                        "~/.claude/projects/*/*/tool-results/*",
                        "%USERPROFILE%\\.claude\\projects\\*\\*\\tool-results\\*"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "claude_code.transcripts",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/projects/<project>/<session-id>.jsonl",
                        "~/.claude/projects/*/*.jsonl",
                        "%USERPROFILE%\\.claude\\projects\\*\\*.jsonl",
                        "$CLAUDE_CONFIG_DIR/projects/*/*.jsonl"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "claude_code.transcripts_set_aside",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/projects/<project>/<session-id>.orphaned-<timestamp>-<suffix>.jsonl",
                        "~/.claude/projects/<project>/<session-id>.jsonl.superseded-<timestamp>",
                        "~/.claude/projects/*/*.orphaned-*.jsonl",
                        "~/.claude/projects/*/*.jsonl.superseded-*",
                        "%USERPROFILE%\\.claude\\projects\\*\\*.jsonl.superseded-*"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "cache",
                    "collect_priority": "normal",
                    "id": "claude_code.uploads",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/uploads/<session-id>/",
                        "~/.claude/uploads/*/*",
                        "%USERPROFILE%\\.claude\\uploads\\*\\*"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "claude_code.usage_data",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/usage-data/",
                        "~/.claude/usage-data/report.html"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "claude_code.usage_reports",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/usage-data/report.html",
                        "~/.claude/usage-data/*",
                        "%USERPROFILE%\\.claude\\usage-data\\*"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "durable",
                    "id": "claude_code.user_claude_md",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/CLAUDE.md"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "durable",
                    "id": "claude_code.user_rules",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/rules/**/*.md"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "durable",
                    "id": "claude_code.user_settings",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/settings.json",
                        "$CLAUDE_CONFIG_DIR/settings.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "durable",
                    "id": "claude_code.user_settings_local",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/settings.local.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "claude_code.workflow_runs",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/projects/<project>/<session-id>/subagents/workflows/<runId>/journal.jsonl",
                        "~/.claude/projects/<project>/<session-id>/subagents/workflows/<runId>/agent-<agentId>.jsonl",
                        "~/.claude/projects/<project>/<session-id>/subagents/workflows/<runId>/agent-<agentId>.meta.json",
                        "~/.claude/projects/<project>/<session-id>/workflows/<runId>.json",
                        "~/.claude/projects/*/*/subagents/workflows/*/*.jsonl"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "config",
                    "collect_priority": "durable",
                    "id": "claude_code.workflows",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/workflows/*.js",
                        "<project>/.claude/workflows/*.js"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "claude_code.worktreeinclude",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.worktreeinclude"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "file_snapshot",
                    "collect_priority": "normal",
                    "id": "claude_code.worktrees",
                    "os": [
                        "linux",
                        "macos",
                        "windows"
                    ],
                    "paths": [
                        "<project>/.claude/worktrees/",
                        "<repo-root>/.claude/worktrees/*"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                }
            ]
        },
        {
            "agent": "cline",
            "artifacts": [
                {
                    "category": "cache",
                    "collect_priority": "normal",
                    "id": "cline.cache_and_remote_config",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<vscode-user>/globalStorage/saoudrizwan.claude-dev/cache/",
                        "<vscode-user>/globalStorage/saoudrizwan.claude-dev/settings/cline_recommended_models.json",
                        "<vscode-user>/globalStorage/saoudrizwan.claude-dev/settings/remote_config_<orgId>.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "file_snapshot",
                    "collect_priority": "normal",
                    "id": "cline.checkpoint_refs_in_workspace",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.git/logs/refs/cline/checkpoints/",
                        "<project>/.git/packed-refs",
                        "<project>/.git/refs/cline/checkpoints/<session-id>/<runCount>"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "file_snapshot",
                    "collect_priority": "normal",
                    "id": "cline.checkpoint_scratch",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.cline/data/checkpoint-scratch/<key>/index",
                        "~/.cline/data/checkpoint-scratch/<key>/pathspec"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "file_snapshot",
                    "collect_priority": "normal",
                    "id": "cline.checkpoints_shadow_git_legacy",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<vscode-user>/globalStorage/saoudrizwan.claude-dev/checkpoints/<cwdHash>/.git/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "cline.cli_sessions",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.cline/data/sessions/<session-id>/<session-id>.hooks.jsonl",
                        "~/.cline/data/sessions/<session-id>/<session-id>.json",
                        "~/.cline/data/sessions/<session-id>/<session-id>.messages.json",
                        "~/.cline/data/sessions/<session-id>/subagents/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "cline.connector_settings_and_logs",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.cline/data/connectors/settings.json",
                        "~/.cline/data/logs/",
                        "~/.cline/data/logs/connectors/<channel>/<instanceKey>.log"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "cline.data_dir_root",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.cline\\data\\",
                        "~/.cline/",
                        "~/.cline/data/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "cline.data_tasks",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.cline/data/tasks/<taskId>/api_conversation_history.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "cline.extension_id",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<vscode-user>/globalStorage/saoudrizwan.claude-dev/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "cline.global_settings",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.cline/data/settings/global-settings.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "cline.global_state_json",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.cline/data/globalState.json",
                        "~/.cline/data/workspaces/<hash>/workspaceState.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "cline.home_config_tree",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.agents/plugins/",
                        "~/.cline/agents/",
                        "~/.cline/cron/",
                        "~/.cline/hooks/",
                        "~/.cline/plugins/",
                        "~/.cline/rules/",
                        "~/.cline/skills/",
                        "~/.cline/tasks/",
                        "~/.cline/workflows/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "mcp_config",
                    "collect_priority": "normal",
                    "id": "cline.mcp_settings",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<vscode-user>/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
                        "~/.cline/data/settings/cline_mcp_settings.json",
                        "~/Documents/Cline/MCP/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "cline.provider_settings",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.cline/data/settings/providers.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "cline.rules_global",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/Cline/Rules/",
                        "~/Documents/Cline/Hooks/",
                        "~/Documents/Cline/MCP/",
                        "~/Documents/Cline/Rules/",
                        "~/Documents/Cline/Workflows/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "cline.rules_project",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.agents/skills/",
                        "<project>/.claude/skills/",
                        "<project>/.cline/skills/",
                        "<project>/.clinerules",
                        "<project>/.clinerules/**/*.md",
                        "<project>/.clinerules/hooks/",
                        "<project>/.clinerules/skills/",
                        "<project>/.clinerules/workflows/",
                        "<project>/.cursor/rules/",
                        "<project>/.cursorrules",
                        "<project>/.windsurfrules",
                        "<project>/AGENTS.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "cline.secrets_json",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.cline/data/secrets.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "cline.sqlite_dbs",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.cline/data/db/connectors.db",
                        "~/.cline/data/db/cron.db",
                        "~/.cline/data/db/tasks.db"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "cline.vscode_task_transcripts",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<vscode-user>/globalStorage/saoudrizwan.claude-dev/tasks/<taskId>/api_conversation_history.json",
                        "<vscode-user>/globalStorage/saoudrizwan.claude-dev/tasks/<taskId>/context_history.json",
                        "<vscode-user>/globalStorage/saoudrizwan.claude-dev/tasks/<taskId>/task_metadata.json",
                        "<vscode-user>/globalStorage/saoudrizwan.claude-dev/tasks/<taskId>/ui_messages.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "cline.workspace_specs",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.cline/cron/",
                        "<project>/.cline/tasks/"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                }
            ]
        },
        {
            "agent": "codex",
            "artifacts": [
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "codex.archived_sessions",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.codex\\archived_sessions\\",
                        "~/.codex/archived_sessions/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "codex.auth",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.codex\\auth.json",
                        "~/.codex/auth.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "codex.config",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.codex\\*.config.toml",
                        "%USERPROFILE%\\.codex\\config.toml",
                        "~/.codex/*.config.toml",
                        "~/.codex/config.toml"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "first",
                    "id": "codex.log_dir",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.codex\\log\\",
                        "~/.codex/log/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "mcp_config",
                    "collect_priority": "normal",
                    "id": "codex.mcp_and_notify",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.codex\\config.toml",
                        "~/.codex/config.toml"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "codex.mcp_oauth_credentials",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.codex\\.credentials.json",
                        "~/.codex/.credentials.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "prompt_history",
                    "collect_priority": "first",
                    "id": "codex.prompt_history",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.codex\\history.jsonl",
                        "~/.codex/history.jsonl"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "normal",
                    "id": "codex.requirements_and_permissions",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.codex\\permissions.toml",
                        "%USERPROFILE%\\.codex\\requirements.toml",
                        "~/.codex/permissions.toml",
                        "~/.codex/requirements.toml"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "codex.rollouts",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.codex\\sessions\\",
                        "~/.codex/sessions/",
                        "~/.codex/sessions/<year>/<month>/<day>/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "codex.rollouts_compressed",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.codex\\sessions\\**\\rollout-*.jsonl.tmp",
                        "%USERPROFILE%\\.codex\\sessions\\**\\rollout-*.jsonl.zst",
                        "~/.codex/sessions/**/rollout-*.jsonl.tmp",
                        "~/.codex/sessions/**/rollout-*.jsonl.zst"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "codex.sqlite_glob",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.codex\\*.sqlite",
                        "~/.codex/*.sqlite"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "live_only",
                    "id": "codex.sqlite_write_ahead_logs",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.codex\\*.sqlite-shm",
                        "%USERPROFILE%\\.codex\\*.sqlite-wal",
                        "~/.codex/*.sqlite-shm",
                        "~/.codex/*.sqlite-wal"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "codex.state_databases",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.codex\\goals_1.sqlite",
                        "%USERPROFILE%\\.codex\\logs_2.sqlite",
                        "%USERPROFILE%\\.codex\\memories_1.sqlite",
                        "%USERPROFILE%\\.codex\\memories_v2_1.sqlite",
                        "%USERPROFILE%\\.codex\\queue_1.sqlite",
                        "%USERPROFILE%\\.codex\\state_5.sqlite",
                        "%USERPROFILE%\\.codex\\thread_history_1.sqlite",
                        "~/.codex/goals_1.sqlite",
                        "~/.codex/logs_2.sqlite",
                        "~/.codex/memories_1.sqlite",
                        "~/.codex/memories_v2_1.sqlite",
                        "~/.codex/queue_1.sqlite",
                        "~/.codex/state_5.sqlite",
                        "~/.codex/thread_history_1.sqlite"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                }
            ]
        },
        {
            "agent": "continue",
            "artifacts": [
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "continue.agents",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/.continue/agents/*.yaml",
                        "<project>/.continue/assistants/*.yaml",
                        "~/.continue/agents/*.yaml",
                        "~/.continue/assistants/*.yaml"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "continue.aux_config",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.continue/.configs/",
                        "~/.continue/.continueignore",
                        "~/.continue/.migrations/",
                        "~/.continue/prompts/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "continue.config",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/.continuerc.json",
                        "~/.continue/config.json",
                        "~/.continue/config.ts",
                        "~/.continue/config.yaml"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "continue.dev_data",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.continue/dev_data/",
                        "~/.continue/logs/core.log"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "continue.devbox_env",
                    "os": [
                        "linux"
                    ],
                    "paths": [
                        "~/.continue/devbox-env"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "file_snapshot",
                    "collect_priority": "normal",
                    "id": "continue.diffs",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.continue/.diffs/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "cache",
                    "collect_priority": "normal",
                    "id": "continue.index",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.continue/index/autocompleteCache.sqlite",
                        "~/.continue/index/docs.sqlite",
                        "~/.continue/index/index.sqlite",
                        "~/.continue/index/lancedb/",
                        "~/.continue/repo_map.txt"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "continue.sessions",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$CONTINUE_GLOBAL_DIR/sessions/",
                        "%USERPROFILE%\\.continue\\sessions\\*.json",
                        "~/.continue/sessions/<session-id>.json",
                        "~/.continue/sessions/sessions.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                }
            ]
        },
        {
            "agent": "copilot",
            "artifacts": [
                {
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "copilot.agents_skills_hooks",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.copilot\\agents\\",
                        "%USERPROFILE%\\.copilot\\hooks\\",
                        "%USERPROFILE%\\.copilot\\skills\\",
                        "~/.copilot/agents/",
                        "~/.copilot/hooks/",
                        "~/.copilot/skills/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "cache",
                    "collect_priority": "durable",
                    "id": "copilot.cache",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%LOCALAPPDATA%\\copilot\\",
                        "$XDG_CACHE_HOME/copilot/",
                        "~/.cache/copilot/",
                        "~/Library/Caches/copilot/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "prompt_history",
                    "collect_priority": "first",
                    "id": "copilot.command_history",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.copilot\\command-history-state\\",
                        "~/.copilot/command-history-state/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "copilot.config_json",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.copilot\\config.json",
                        "~/.copilot/config.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "copilot.extensions_and_plugins",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.copilot\\extensions\\",
                        "%USERPROFILE%\\.copilot\\installed-plugins\\",
                        "%USERPROFILE%\\.copilot\\plugin-data\\",
                        "~/.copilot/extensions/",
                        "~/.copilot/installed-plugins/",
                        "~/.copilot/plugin-data/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "live_only",
                    "id": "copilot.ide_locks",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.copilot\\ide\\",
                        "~/.copilot/ide/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "copilot.instructions",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.copilot\\copilot-instructions.md",
                        "%USERPROFILE%\\.copilot\\instructions\\",
                        "~/.copilot/copilot-instructions.md",
                        "~/.copilot/instructions/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "first",
                    "id": "copilot.logs",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.copilot\\logs\\",
                        "~/.copilot/logs/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "copilot.lsp_config",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.copilot\\lsp-config.json",
                        "~/.copilot/lsp-config.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "copilot.lsp_config_repo",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.github/lsp.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "mcp_config",
                    "collect_priority": "normal",
                    "id": "copilot.mcp_config",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.copilot\\mcp-config.json",
                        "~/.copilot/mcp-config.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "mcp_config",
                    "collect_priority": "normal",
                    "id": "copilot.mcp_config_jetbrains",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%LOCALAPPDATA%\\github-copilot\\intellij\\mcp.json",
                        "~/.config/github-copilot/",
                        "~/.config/github-copilot/intellij/mcp.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "copilot.mcp_credentials",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.copilot\\mcp-oauth-config\\",
                        "%USERPROFILE%\\.copilot\\mcp-secrets\\",
                        "~/.copilot/mcp-oauth-config/",
                        "~/.copilot/mcp-secrets/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "normal",
                    "id": "copilot.permissions",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.copilot\\permissions-config.json",
                        "~/.copilot/permissions-config.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "copilot.providers",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.copilot\\providers.json",
                        "~/.copilot/providers.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "copilot.session_event_log",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.copilot/session-state/<session-id>/events.jsonl",
                        "~/.copilot/session-state/<session-id>/workspace.yaml"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "copilot.session_state",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.copilot\\session-state\\",
                        "~/.copilot/session-state/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "copilot.session_store",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.copilot\\session-store.db",
                        "~/.copilot/session-store.db"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "live_only",
                    "id": "copilot.session_store_sidecars",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.copilot\\session-store.db-shm",
                        "%USERPROFILE%\\.copilot\\session-store.db-wal",
                        "~/.copilot/session-store.db-shm",
                        "~/.copilot/session-store.db-wal"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "copilot.settings",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.copilot\\settings.json",
                        "~/.copilot/settings.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                }
            ]
        },
        {
            "agent": "crosscutting",
            "artifacts": [
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "crosscutting.homebrew_prefixes",
                    "os": [
                        "macos",
                        "linux"
                    ],
                    "paths": [
                        "/home/linuxbrew/.linuxbrew/",
                        "/home/linuxbrew/.linuxbrew/Cellar/",
                        "/opt/homebrew/",
                        "/opt/homebrew/Caskroom/",
                        "/opt/homebrew/Cellar/",
                        "/opt/homebrew/bin/",
                        "/usr/local/",
                        "/usr/local/Cellar/"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "crosscutting.hook_scripts",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/claude/hooks/",
                        "<project>/claude/settings.json",
                        "<project>/claude/settings.local.json",
                        "<project>/clinerules/hooks/",
                        "~/.claude/settings.json",
                        "~/Documents/Cline/Hooks/"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "crosscutting.instructions_agents_md",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/**/AGENTS.md",
                        "<project>/AGENTS.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "crosscutting.instructions_claude_md",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/**/CLAUDE.md",
                        "<project>/CLAUDE.local.md",
                        "<project>/CLAUDE.md",
                        "<project>/claude/CLAUDE.md",
                        "~/.claude/CLAUDE.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "crosscutting.instructions_clinerules",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/claude/skills/",
                        "<project>/cline/remote-config/",
                        "<project>/cline/skills/",
                        "<project>/clineignore",
                        "<project>/clinerules",
                        "<project>/clinerules/",
                        "<project>/clinerules/*.md",
                        "<project>/clinerules/skills/",
                        "<project>/clinerules/workflows/",
                        "~/Documents/Cline/Rules/",
                        "~/Documents/Cline/Workflows/"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "crosscutting.instructions_copilot_instructions",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$HOME/.copilot/copilot-instructions.md",
                        "$HOME/.copilot/instructions/**/*.instructions.md",
                        "<project>/github/agents/*.md",
                        "<project>/github/copilot-instructions.md",
                        "<project>/github/copilot/settings.json",
                        "<project>/github/copilot/settings.local.json",
                        "<project>/github/instructions/**/*.instructions.md",
                        "<project>/github/prompts/*.prompt.md",
                        "<project>/github/skills/"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "crosscutting.instructions_cursor_rules",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/**/.cursor/rules/",
                        "<project>/AGENTS.md",
                        "<project>/cursor/rules/",
                        "<project>/cursor/rules/*.mdc",
                        "<project>/cursor/rules/*/RULE.md",
                        "<project>/cursorrules"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "crosscutting.instructions_gemini_md",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/**/GEMINI.md",
                        "<project>/GEMINI.md",
                        "<project>/gemini/settings.json",
                        "~/.gemini/GEMINI.md",
                        "~/.gemini/settings.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "crosscutting.instructions_junie_guidelines",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/junie/",
                        "<project>/junie/guidelines.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "crosscutting.instructions_kiro_steering",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/kiro/specs/",
                        "<project>/kiro/steering/",
                        "<project>/kiro/steering/*.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "crosscutting.instructions_windsurf_rules",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/windsurf/rules/",
                        "<project>/windsurf/rules/*.md",
                        "<project>/windsurfrules"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "mcp_config",
                    "collect_priority": "normal",
                    "id": "crosscutting.mcp_config_files",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$HOME/.copilot/mcp-config.json",
                        "%APPDATA%\\Claude\\claude_desktop_config.json",
                        "%USERPROFILE%\\.mcp.json",
                        "<project>/cursor/mcp.json",
                        "<project>/gemini/settings.json",
                        "<project>/mcp.json",
                        "<project>/vscode/mcp.json",
                        "~/.claude.json",
                        "~/.config/Claude/claude_desktop_config.json",
                        "~/.cursor/mcp.json",
                        "~/.gemini/settings.json",
                        "~/.vscode/mcp.json",
                        "~/Library/Application Support/Claude/claude_desktop_config.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "first",
                    "id": "crosscutting.npm_debug_logs",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%LOCALAPPDATA%\\npm-cache\\_logs\\*-debug-*.log",
                        "~/.npm/_logs/*-debug-*.log"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "first",
                    "id": "crosscutting.npm_global_install_dirs",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%APPDATA%\\npm\\",
                        "%APPDATA%\\npm\\node_modules\\",
                        "/opt/homebrew/lib/node_modules/",
                        "/usr/local/bin/",
                        "/usr/local/lib/node_modules/",
                        "~/.nvm/versions/node/*/lib/node_modules/"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "durable",
                    "id": "crosscutting.npm_npx_cache",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%LOCALAPPDATA%\\npm-cache\\_npx\\*\\package.json",
                        "~/.npm/_npx/*/node_modules/",
                        "~/.npm/_npx/*/package.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "crosscutting.pipx_home_and_bin",
                    "os": [
                        "linux",
                        "macos",
                        "windows"
                    ],
                    "paths": [
                        "%LOCALAPPDATA%\\pipx\\pipx\\venvs\\*\\",
                        "/opt/pipx/",
                        "~/.local/bin/",
                        "~/.local/pipx/",
                        "~/.local/share/pipx/venvs/*/",
                        "~/Library/Application Support/pipx/venvs/*/"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "shell_history",
                    "collect_priority": "normal",
                    "id": "crosscutting.shell_bash_history",
                    "os": [
                        "macos",
                        "linux"
                    ],
                    "paths": [
                        "$HISTFILE",
                        "~/.bash_history"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "shell_history",
                    "collect_priority": "normal",
                    "id": "crosscutting.shell_fish_history",
                    "os": [
                        "macos",
                        "linux"
                    ],
                    "paths": [
                        "$XDG_DATA_HOME/fish/${fish_history}_history",
                        "$XDG_DATA_HOME/fish/fish_history",
                        "~/.local/share/fish/fish_history"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "shell_history",
                    "collect_priority": "normal",
                    "id": "crosscutting.shell_psreadline_history",
                    "os": [
                        "windows",
                        "macos",
                        "linux"
                    ],
                    "paths": [
                        "$XDG_DATA_HOME/powershell/PSReadLine/*_history.txt",
                        "%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\*_history.txt",
                        "%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
                        "~/.local/share/powershell/PSReadLine/ConsoleHost_history.txt"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "shell_history",
                    "collect_priority": "normal",
                    "id": "crosscutting.shell_zsh_history",
                    "os": [
                        "macos",
                        "linux"
                    ],
                    "paths": [
                        "$HISTFILE",
                        "~/.zhistory",
                        "~/.zsh_history"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "crosscutting.uv_tool_dir",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$XDG_DATA_HOME/uv/tools/*/",
                        "%APPDATA%\\uv\\data\\tools\\*\\",
                        "%LOCALAPPDATA%\\uv\\cache\\",
                        "~/.cache/uv/",
                        "~/.local/bin/",
                        "~/.local/share/uv/python/",
                        "~/.local/share/uv/tools/*/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "crosscutting.windows_appdata_program_dirs",
                    "os": [
                        "windows"
                    ],
                    "paths": [
                        "%APPDATA%\\",
                        "%LOCALAPPDATA%\\Ollama\\",
                        "%LOCALAPPDATA%\\Packages\\",
                        "%LOCALAPPDATA%\\Programs\\",
                        "%LOCALAPPDATA%\\Programs\\Ollama\\"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "crosscutting.windows_execution_evidence_files",
                    "os": [
                        "windows"
                    ],
                    "paths": [
                        "%SystemRoot%\\AppCompat\\Programs\\Amcache.hve",
                        "%SystemRoot%\\AppCompat\\Programs\\Amcache.hve.LOG1",
                        "%SystemRoot%\\AppCompat\\Programs\\Amcache.hve.LOG2",
                        "%SystemRoot%\\Prefetch\\*.pf",
                        "%SystemRoot%\\System32\\Tasks\\",
                        "%SystemRoot%\\System32\\sru\\SRUDB.dat"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "crosscutting.windows_execution_evidence_registry",
                    "os": [
                        "windows"
                    ],
                    "paths": [
                        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks",
                        "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
                        "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\AppCompatibility",
                        "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\*",
                        "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\bam\\UserSettings\\*",
                        "HKEY_USERS\\<sid>\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\*\\Count",
                        "HKEY_USERS\\<sid>\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "HKEY_USERS\\<sid>\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
                    ],
                    "root": "registry",
                    "sensitivity": "normal",
                    "status": "unverified"
                }
            ]
        },
        {
            "agent": "cursor",
            "artifacts": [
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "cursor.acp_session_store",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.cursor/acp-sessions/<session-uuid>/meta.json",
                        "~/.cursor/acp-sessions/<session-uuid>/store.db",
                        "~/.cursor/acp-sessions/<session-uuid>/store.db-shm",
                        "~/.cursor/acp-sessions/<session-uuid>/store.db-wal"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "cursor.agent_cli_state",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.cursor/commands/*.md",
                        "~/.cursor/agent-cli-state.json",
                        "~/.cursor/agents/",
                        "~/.cursor/browser-logs/",
                        "~/.cursor/hooks.json",
                        "~/.cursor/plugins/",
                        "~/.cursor/sandbox-policies/",
                        "~/.cursor/skills-cursor/",
                        "~/.cursor/skills/",
                        "~/.cursor/snapshots/",
                        "~/.cursor/worktrees/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "cursor.agent_transcripts_jsonl",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.cursor\\projects\\<escaped-abs-cwd>\\agent-transcripts\\...",
                        "~/.cursor/projects/<escaped-abs-cwd>/agent-tools/*.txt",
                        "~/.cursor/projects/<escaped-abs-cwd>/agent-transcripts/<composer-id>.txt",
                        "~/.cursor/projects/<escaped-abs-cwd>/agent-transcripts/<session-uuid>.jsonl",
                        "~/.cursor/projects/<escaped-abs-cwd>/agent-transcripts/<session-uuid>/<session-uuid>.jsonl",
                        "~/.cursor/projects/<escaped-abs-cwd>/agent-transcripts/<session-uuid>/transcript.jsonl"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "cursor.ai_code_tracking_db",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.cursor/ai-tracking/*.db",
                        "~/.cursor/ai-tracking/ai-code-tracking.db"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "cursor.auth_credentials",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$XDG_CONFIG_HOME/cursor/auth.json",
                        "%APPDATA%\\Cursor\\auth.json",
                        "~/.config/cursor/auth.json",
                        "~/.cursor/auth.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "cursor.chat_session_meta_json",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.cursor/chats/<md5-hex-of-abs-workspace-path>/<session-uuid>/meta.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "prompt_history",
                    "collect_priority": "normal",
                    "id": "cursor.chat_session_prompt_history",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.cursor/chats/<md5-hex-of-abs-workspace-path>/<session-uuid>/prompt_history.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "cursor.chat_store_db",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$XDG_CONFIG_HOME/cursor/chats/<md5>/<session-uuid>/store.db",
                        "%USERPROFILE%\\.cursor\\chats\\<md5>\\<session-uuid>\\store.db",
                        "~/.cursor/chats/<md5-hex-of-abs-workspace-path>/<session-uuid>/store.db",
                        "~/.cursor/chats/<md5-hex-of-abs-workspace-path>/<session-uuid>/store.db-shm",
                        "~/.cursor/chats/<md5-hex-of-abs-workspace-path>/<session-uuid>/store.db-wal"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "normal",
                    "id": "cursor.cli_config",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$XDG_CONFIG_HOME/cursor/cli-config.json",
                        "%USERPROFILE%\\.cursor\\cli-config.json",
                        "<project>/.cursor/cli.json",
                        "~/.cursor/cli-config.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "file_snapshot",
                    "collect_priority": "normal",
                    "id": "cursor.commit_checkpoints",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Cursor\\User\\globalStorage\\anysphere.cursor-commits\\checkpoints\\",
                        "~/.config/Cursor/User/globalStorage/anysphere.cursor-commits/checkpoints/",
                        "~/Library/Application Support/Cursor/User/globalStorage/anysphere.cursor-commits/checkpoints/<id>/diffs/<uuid>",
                        "~/Library/Application Support/Cursor/User/globalStorage/anysphere.cursor-commits/checkpoints/<id>/files/<uuid>",
                        "~/Library/Application Support/Cursor/User/globalStorage/anysphere.cursor-commits/checkpoints/<id>/metadata.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "cursor.conversation_search_db",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Cursor\\User\\globalStorage\\conversation-search.db",
                        "~/.config/Cursor/User/globalStorage/conversation-search.db",
                        "~/Library/Application Support/Cursor/User/globalStorage/conversation-search.db"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "cursor.extensions",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.cursor\\extensions\\extensions.json",
                        "~/.cursor-server/extensions/",
                        "~/.cursor/extensions/",
                        "~/.cursor/extensions/extensions.json",
                        "~/Library/Application Support/Cursor/extensions/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "prompt_history",
                    "collect_priority": "normal",
                    "id": "cursor.global_prompt_history",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$HOME/.cursor/prompt_history.json",
                        "%USERPROFILE%\\.cursor\\prompt_history.json",
                        "~/.cursor/prompt_history.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "cursor.global_state_vscdb",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Cursor\\User\\globalStorage\\state.vscdb",
                        "~/.config/Cursor/User/globalStorage/state.vscdb",
                        "~/Library/Application Support/Cursor/User/globalStorage/state.vscdb",
                        "~/Library/Application Support/Cursor/User/globalStorage/state.vscdb-shm",
                        "~/Library/Application Support/Cursor/User/globalStorage/state.vscdb-wal",
                        "~/Library/Application Support/Cursor/User/globalStorage/state.vscdb.backup"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "cursor.install_and_machine_identity",
                    "os": [
                        "windows"
                    ],
                    "paths": [
                        "%LOCALAPPDATA%\\Programs\\cursor\\",
                        "%LOCALAPPDATA%\\cursor-updater\\",
                        "HKCU\\Software\\Classes\\cursor\\shell\\open\\command",
                        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "~/Library/Application Support/Cursor/User/globalStorage/statsig-cache.json",
                        "~/Library/Application Support/Cursor/User/globalStorage/storage.json",
                        "~/Library/Application Support/Cursor/machineid",
                        "~/Library/Preferences/com.todesktop.230313mzl4w4u92.plist"
                    ],
                    "root": "registry",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "file_snapshot",
                    "collect_priority": "normal",
                    "id": "cursor.local_file_history",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Cursor\\User\\History\\",
                        "~/.config/Cursor/User/History/",
                        "~/Library/Application Support/Cursor/User/History/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "cursor.logs",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Cursor\\logs\\",
                        "~/.config/Cursor/logs/",
                        "~/Library/Application Support/Cursor/User/process-monitor/",
                        "~/Library/Application Support/Cursor/logs/*/window*/workbench.mcp.*.log",
                        "~/Library/Application Support/Cursor/logs/<launch-timestamp>/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "mcp_config",
                    "collect_priority": "normal",
                    "id": "cursor.mcp_config",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.cursor\\mcp.json",
                        "<project>/.cursor/mcp.json",
                        "<project>/.mcp.json",
                        "~/.cursor/mcp.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "cursor.pasted_text",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.cursor/chats/<md5>/<session-uuid>/pasted_text.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "cursor.project_instructions",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.cursor/agents/",
                        "<project>/.cursor/commands/*.md",
                        "<project>/.cursor/plans/",
                        "<project>/.cursor/rules/*.mdc",
                        "<project>/.cursor/skills/",
                        "<project>/.cursorrules",
                        "<project>/AGENTS.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "cursor.project_metadata",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.cursor/projects-metadata.json",
                        "~/.cursor/projects/<escaped-abs-cwd>/mcp-approvals.json",
                        "~/.cursor/projects/<escaped-abs-cwd>/repo.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "cache",
                    "collect_priority": "first",
                    "id": "cursor.retrieval_index",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/Library/Application Support/Cursor/CachedData/",
                        "~/Library/Application Support/Cursor/User/workspaceStorage/<workspace-hash>/anysphere.cursor-retrieval/embeddable_files.txt",
                        "~/Library/Application Support/Cursor/User/workspaceStorage/<workspace-hash>/anysphere.cursor-retrieval/high_level_folder_description.txt",
                        "~/Library/Caches/cursor-compile-cache/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "cursor.workspace_state_vscdb",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Cursor\\User\\workspaceStorage\\<workspace-hash>\\state.vscdb",
                        "~/.config/Cursor/User/workspaceStorage/<workspace-hash>/state.vscdb",
                        "~/Library/Application Support/Cursor/User/workspaceStorage/<workspace-hash>/state.vscdb",
                        "~/Library/Application Support/Cursor/User/workspaceStorage/<workspace-hash>/workspace.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                }
            ]
        },
        {
            "agent": "devin",
            "artifacts": [
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "devin.acp_events",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Devin\\User\\acp-events\\",
                        "~/.config/Devin/User/acp-events/",
                        "~/.config/Devin/logs/<launch>/window*/exthost/output_logging_*/1-Devin Desktop.log",
                        "~/Library/Application Support/Devin/User/acp-events/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "devin.sessions_db",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.local\\share\\devin\\cli\\sessions.db",
                        "~/.local/share/devin/cli/sessions.db",
                        "~/.local/share/devin/cli/transcripts/<session-id>.json",
                        "~/Library/Application Support/devin/cli/sessions.db",
                        "~/Library/Application Support/devin/cli/transcripts/<session-id>.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                }
            ]
        },
        {
            "agent": "factory_droid",
            "artifacts": [
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "factory_droid.auth",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.factory/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "factory_droid.config",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/.factory/settings.json",
                        "<project>/.factory/settings.local.json",
                        "~/.factory/config.json",
                        "~/.factory/settings.json",
                        "~/.factory/settings.local.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "factory_droid.logs",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.factory/bug-reports/",
                        "~/.factory/logs/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "mcp_config",
                    "collect_priority": "normal",
                    "id": "factory_droid.mcp_and_hooks",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/.factory/mcp.json",
                        "~/.factory/hooks.json",
                        "~/.factory/mcp.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "factory_droid.sessions",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/.factory/sessions/",
                        "~/.factory/sessions/**/settings.json",
                        "~/.factory/sessions/*/*.jsonl",
                        "~/.factory/sessions/<uuid>.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "factory_droid.skills_and_droids",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/AGENTS.md",
                        "~/.factory/commands/",
                        "~/.factory/droids/",
                        "~/.factory/skills/"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "unverified"
                }
            ]
        },
        {
            "agent": "goose",
            "artifacts": [
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "goose.cli_logs",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%APPDATA%\\Block\\goose\\data\\logs\\cli\\",
                        "~/.local/state/goose/logs/cli/",
                        "~/.local/state/goose/logs/cli/YYYY-MM-DD/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "goose.config",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%APPDATA%\\Block\\goose\\config\\config.yaml",
                        "~/.config/goose/config.yaml"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "goose.desktop_log",
                    "os": [
                        "macos",
                        "windows"
                    ],
                    "paths": [
                        "%APPDATA%\\Block\\goose\\logs\\main.log",
                        "~/Library/Application Support/Goose/logs/main.log"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "goose.hints",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/.goosehints",
                        "<project>/AGENTS.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "memory",
                    "collect_priority": "normal",
                    "id": "goose.memory",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/.goose/memory/",
                        "~/.config/goose/memory/"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "normal",
                    "id": "goose.permissions",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%APPDATA%\\Block\\goose\\config\\permission.yaml",
                        "%APPDATA%\\Block\\goose\\config\\permissions\\tool_permissions.json",
                        "~/.config/goose/permission.yaml",
                        "~/.config/goose/permissions/tool_permissions.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "goose.prompts",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%APPDATA%\\Block\\goose\\config\\prompts\\",
                        "~/.config/goose/prompts/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "goose.recipes",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/*.yaml"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "goose.secrets",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%APPDATA%\\Block\\goose\\config\\secrets.yaml",
                        "~/.config/goose/secrets.yaml"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "goose.server_logs",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%APPDATA%\\Block\\goose\\data\\logs\\server\\",
                        "~/.local/state/goose/logs/server/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "goose.sessions_db",
                    "os": [
                        "macos",
                        "linux"
                    ],
                    "paths": [
                        "~/.local/share/goose/sessions/sessions.db",
                        "~/.local/share/goose/sessions/sessions.db-shm",
                        "~/.local/share/goose/sessions/sessions.db-wal",
                        "~/Library/Application Support/Block/goose/data/sessions/sessions.db"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "goose.sessions_db_windows",
                    "os": [
                        "windows"
                    ],
                    "paths": [
                        "%APPDATA%\\Block\\goose\\data\\sessions\\sessions.db"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "goose.sessions_jsonl_legacy",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%APPDATA%\\Block\\goose\\data\\sessions\\*.jsonl",
                        "~/.local/share/goose/sessions/*.jsonl"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                }
            ]
        },
        {
            "agent": "hermes",
            "artifacts": [
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "hermes.auth",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$HERMES_HOME/auth.json",
                        "~/.hermes/auth.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "hermes.config",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$HERMES_HOME/config.yaml",
                        "~/.hermes/config.yaml"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "hermes.cron",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$HERMES_HOME/cron/",
                        "~/.hermes/cron/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "hermes.env",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$HERMES_HOME/.env",
                        "~/.hermes/.env"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "hermes.logs",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$HERMES_HOME/logs/",
                        "~/.hermes/logs/errors.log",
                        "~/.hermes/logs/gateway.log"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "memory",
                    "collect_priority": "normal",
                    "id": "hermes.memories",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$HERMES_HOME/memories/",
                        "~/.hermes/memories/MEMORY.md",
                        "~/.hermes/memories/USER.md"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "hermes.profiles",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.hermes/profiles/<name>/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "file_snapshot",
                    "collect_priority": "normal",
                    "id": "hermes.sandboxes",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$HERMES_HOME/sandboxes/",
                        "~/.hermes/sandboxes/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "hermes.sessions_dir",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$HERMES_HOME/sessions/",
                        "~/.hermes/sessions/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "hermes.skills",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$HERMES_HOME/skills/",
                        "~/.hermes/skills/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "hermes.soul",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$HERMES_HOME/SOUL.md",
                        "~/.hermes/SOUL.md"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "hermes.state_db",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$HERMES_HOME/state.db",
                        "~/.hermes/state.db",
                        "~/.hermes/state.db-shm",
                        "~/.hermes/state.db-wal"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                }
            ]
        },
        {
            "agent": "jetbrains_ai",
            "artifacts": [
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "jetbrains_ai.aia_task_history",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\JetBrains\\<Product><Version>\\aia-task-history\\",
                        "~/.config/JetBrains/<Product><Version>/aia-task-history/",
                        "~/Library/Application Support/JetBrains/<Product><Version>/aia-task-history/<session-id>.agentsession",
                        "~/Library/Application Support/JetBrains/<Product><Version>/aia-task-history/<session-id>.checkpoints",
                        "~/Library/Application Support/JetBrains/<Product><Version>/aia-task-history/<session-id>.events",
                        "~/Library/Application Support/JetBrains/<Product><Version>/aia-task-history/<session-id>.lastid"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "jetbrains_ai.base_directories",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\JetBrains\\<Product><Version>\\",
                        "%APPDATA%\\JetBrains\\<Product><Version>\\plugins\\",
                        "%LOCALAPPDATA%\\JetBrains\\<Product><Version>\\",
                        "%LOCALAPPDATA%\\JetBrains\\<Product><Version>\\log\\",
                        "~/.cache/JetBrains/<Product><Version>/",
                        "~/.cache/JetBrains/<Product><Version>/log/",
                        "~/.config/JetBrains/<Product><Version>/",
                        "~/.local/share/JetBrains/<Product><Version>/",
                        "~/Library/Application Support/JetBrains/<Product><Version>/",
                        "~/Library/Application Support/JetBrains/<Product><Version>/plugins/",
                        "~/Library/Caches/JetBrains/<Product><Version>/",
                        "~/Library/Logs/JetBrains/<Product><Version>/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "jetbrains_ai.ide_logs",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%LOCALAPPDATA%\\JetBrains\\<Product><Version>\\log\\idea.log",
                        "~/.cache/JetBrains/<Product><Version>/log/idea.log",
                        "~/Library/Logs/JetBrains/<Product><Version>/acp.log",
                        "~/Library/Logs/JetBrains/<Product><Version>/idea.log",
                        "~/Library/Logs/JetBrains/<Product><Version>/idea.log.*"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "jetbrains_ai.log_data",
                    "os": [
                        "windows",
                        "macos",
                        "linux"
                    ],
                    "paths": [
                        "%LOCALAPPDATA%\\JetBrains\\<Product><Version>\\ai-assistant-log-data\\",
                        "~/.cache/JetBrains/<Product><Version>/ai-assistant-log-data/",
                        "~/Library/Caches/JetBrains/<Product><Version>/ai-assistant-log-data/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "mcp_config",
                    "collect_priority": "normal",
                    "id": "jetbrains_ai.mcp_config",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$XDG_CONFIG_HOME/JetBrains/Air/mcp.json",
                        "%APPDATA%\\JetBrains\\Air\\mcp.json",
                        "<project>/.air/mcp.json",
                        "~/.config/JetBrains/Air/mcp.json",
                        "~/Library/Application Support/JetBrains/Air/mcp.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "jetbrains_ai.password_safe",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\JetBrains\\<Product><Version>\\c.kdbx",
                        "%APPDATA%\\JetBrains\\<Product><Version>\\c.pwd",
                        "~/.config/JetBrains/<Product><Version>/c.kdbx",
                        "~/.config/JetBrains/<Product><Version>/c.pwd",
                        "~/Library/Application Support/JetBrains/<Product><Version>/c.kdbx",
                        "~/Library/Application Support/JetBrains/<Product><Version>/c.pwd",
                        "~/Library/Application Support/JetBrains/<Product><Version>/options/security.xml"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                }
            ]
        },
        {
            "agent": "junie",
            "artifacts": [
                {
                    "category": "permissions",
                    "collect_priority": "normal",
                    "id": "junie.allowlist",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.junie\\allowlist.json",
                        "~/.junie/allowlist.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "junie.cli_sessions",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.junie\\sessions\\<session-id>\\",
                        "~/.junie/sessions/<session-id>/events.jsonl",
                        "~/.junie/sessions/<session-id>/subagents/",
                        "~/.junie/sessions/<session-id>/transcript.md"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "junie.home_config",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.junie\\AGENTS.md",
                        "%USERPROFILE%\\.junie\\config.json",
                        "~/.junie/AGENTS.md",
                        "~/.junie/config.json",
                        "~/.junie/settings.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "junie.jcp_outbox",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%LOCALAPPDATA%\\JetBrains\\<Product><Version>\\junie-jcp-outbox\\",
                        "~/.cache/JetBrains/<Product><Version>/junie-jcp-outbox/",
                        "~/Library/Caches/JetBrains/<Product><Version>/junie-jcp-outbox/event-logs/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "junie.matterhorn_project_logs",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%LOCALAPPDATA%\\JetBrains\\<Product><Version>\\projects\\<ProjectName>\\matterhorn\\.matterhorn\\",
                        "~/.cache/JetBrains/<Product><Version>/projects/<ProjectName>/matterhorn/.matterhorn/",
                        "~/Library/Caches/JetBrains/<Product><Version>/projects/<ProjectName>/matterhorn/.matterhorn/events/<issueId> <taskId>-events.jsonl",
                        "~/Library/Caches/JetBrains/<Product><Version>/projects/<ProjectName>/matterhorn/.matterhorn/issues/chain-<issueId>.json",
                        "~/Library/Caches/JetBrains/<Product><Version>/projects/<ProjectName>/matterhorn/.matterhorn/issues/chain-<issueId>/task-<index>.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "mcp_config",
                    "collect_priority": "normal",
                    "id": "junie.mcp_config",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.junie\\mcp\\mcp.json",
                        "<project>/.junie/mcp/mcp.json",
                        "~/.junie/mcp/mcp.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "junie.plugin_install_evidence",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\JetBrains\\<Product><Version>\\plugins\\ml-llm\\",
                        "~/.local/share/JetBrains/<Product><Version>/ml-llm/",
                        "~/Library/Application Support/JetBrains/<Product><Version>/options/InstallJunieHubActionManager.xml",
                        "~/Library/Application Support/JetBrains/<Product><Version>/plugins/ml-llm/lib/modules/intellij.ml.llm.junie.*.jar"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "junie.project_dir",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.aiignore",
                        "<project>/.junie/AGENTS.md",
                        "<project>/.junie/config.json",
                        "<project>/.junie/guidelines.md",
                        "<project>/.junie/guidelines/",
                        "<project>/.junie/playbook.md",
                        "<project>/.junie/rules/*.md",
                        "<project>/AGENTS.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "junie.trust_and_auth_key",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.junie\\trust\\",
                        "~/.junie/trust/",
                        "~/.junie/trust/authentication-key"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "unverified"
                }
            ]
        },
        {
            "agent": "kilo_code",
            "artifacts": [
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "kilo_code.cli_db",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.local\\share\\kilo\\kilo.db",
                        "~/.local/share/kilo/kilo.db",
                        "~/.local/share/kilo/kilo.db-shm",
                        "~/.local/share/kilo/kilo.db-wal"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "kilo_code.extension_id_legacy_tree",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Code\\User\\globalStorage\\kilocode.kilo-code\\tasks\\",
                        "~/.config/Code/User/globalStorage/kilocode.kilo-code/tasks/",
                        "~/.vscode-server/data/User/globalStorage/kilocode.kilo-code/tasks/",
                        "~/Library/Application Support/Code/User/globalStorage/kilocode.kilo-code/tasks/<taskId>/api_conversation_history.json",
                        "~/Library/Application Support/Code/User/globalStorage/kilocode.kilo-code/tasks/<taskId>/task_metadata.json",
                        "~/Library/Application Support/Code/User/globalStorage/kilocode.kilo-code/tasks/<taskId>/ui_messages.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "kilo_code.home_dir",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.kilocodemodes",
                        "~/.kilocode/cli/global/settings/custom_modes.yaml"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "kilo_code.settings",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Code\\User\\globalStorage\\kilocode.kilo-code\\settings\\custom_modes.yaml",
                        "~/.config/Code/User/globalStorage/kilocode.kilo-code/settings/custom_modes.yaml",
                        "~/Library/Application Support/Code/User/globalStorage/kilocode.kilo-code/settings/custom_modes.yaml"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                }
            ]
        },
        {
            "agent": "lmstudio",
            "artifacts": [
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "lmstudio.cli_and_server",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.lmstudio\\bin\\lms.exe",
                        "~/.lmstudio/bin/lms"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "lmstudio.conversations",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.lmstudio\\conversations\\",
                        "~/.lmstudio/conversations/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "lmstudio.macos_app_support_and_logs",
                    "os": [
                        "macos"
                    ],
                    "paths": [
                        "~/Library/Application Support/LM Studio/",
                        "~/Library/Caches/ai.elementlabs.lmstudio/",
                        "~/Library/HTTPStorages/ai.elementlabs.lmstudio/",
                        "~/Library/Logs/LM Studio/",
                        "~/Library/Preferences/ai.elementlabs.lmstudio.plist",
                        "~/Library/Saved Application State/ai.elementlabs.lmstudio.savedState/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "mcp_config",
                    "collect_priority": "normal",
                    "id": "lmstudio.mcp_config",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.lmstudio\\mcp.json",
                        "~/.lmstudio/mcp.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "lmstudio.models",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.lmstudio\\models\\*\\*\\*",
                        "~/.lmstudio/models/*/*/*"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "lmstudio.presets_and_hub",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.lmstudio\\config-presets\\",
                        "%USERPROFILE%\\.lmstudio\\hub\\",
                        "~/.lmstudio/config-presets/",
                        "~/.lmstudio/hub/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                }
            ]
        },
        {
            "agent": "ollama",
            "artifacts": [
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "ollama.app_chat_database",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%LOCALAPPDATA%\\Ollama\\db.sqlite",
                        "%LOCALAPPDATA%\\Ollama\\db.sqlite-wal",
                        "~/.ollama/db.sqlite",
                        "~/Library/Application Support/Ollama/db.sqlite",
                        "~/Library/Application Support/Ollama/db.sqlite-shm",
                        "~/Library/Application Support/Ollama/db.sqlite-wal"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "ollama.app_config",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%LOCALAPPDATA%\\Ollama\\config.json",
                        "~/.ollama/config.json",
                        "~/Library/Application Support/Ollama/config.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "file_snapshot",
                    "collect_priority": "normal",
                    "id": "ollama.backup_dir",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.ollama/backup/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "ollama.cli_config",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.ollama/config.json",
                        "~/.ollama/config/config.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "prompt_history",
                    "collect_priority": "first",
                    "id": "ollama.cli_prompt_history",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.ollama\\history",
                        "~/.ollama/history"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "ollama.env_overrides",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "/etc/systemd/system/ollama.service",
                        "/etc/systemd/system/ollama.service.d/override.conf",
                        "~/.bashrc",
                        "~/.zshrc"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "ollama.env_overrides_registry",
                    "os": [
                        "windows"
                    ],
                    "paths": [
                        "HKEY_CURRENT_USER\\Environment"
                    ],
                    "root": "registry",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "ollama.logs",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%LOCALAPPDATA%\\Ollama\\app.log",
                        "%LOCALAPPDATA%\\Ollama\\server-*.log",
                        "%LOCALAPPDATA%\\Ollama\\server.log",
                        "%LOCALAPPDATA%\\Ollama\\upgrade.log",
                        "~/.ollama/logs/app.log",
                        "~/.ollama/logs/server.log"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "ollama.macos_app_container",
                    "os": [
                        "macos"
                    ],
                    "paths": [
                        "~/Library/Application Support/Ollama/",
                        "~/Library/Caches/com.electron.ollama/",
                        "~/Library/Preferences/com.electron.ollama.plist",
                        "~/Library/Saved Application State/com.electron.ollama.savedState/",
                        "~/Library/Webkit/com.electron.ollama/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "cache",
                    "collect_priority": "normal",
                    "id": "ollama.model_blobs",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$OLLAMA_MODELS/blobs/sha256-*",
                        "%USERPROFILE%\\.ollama\\models\\blobs\\sha256-*",
                        "/usr/share/ollama/.ollama/models/blobs/sha256-*",
                        "~/.ollama/models/blobs/sha256-*"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "ollama.model_manifests",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$OLLAMA_MODELS/manifests/*/*/*/*",
                        "%USERPROFILE%\\.ollama\\models\\manifests\\*\\*\\*\\*",
                        "/usr/share/ollama/.ollama/models/manifests/*/*/*/*",
                        "~/.ollama/models/manifests/*/*/*/*"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "ollama.private_key",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.ollama/id_ed25519",
                        "~/.ollama/id_ed25519.pub"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                }
            ]
        },
        {
            "agent": "opencode",
            "artifacts": [
                {
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "opencode.agents_commands",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/.opencode/agents/",
                        "<project>/.opencode/commands/",
                        "<project>/AGENTS.md",
                        "~/.config/opencode/agents/",
                        "~/.config/opencode/commands/"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "opencode.auth",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$XDG_DATA_HOME/opencode/auth.json",
                        "%LOCALAPPDATA%\\opencode\\auth.json",
                        "~/.local/share/opencode/auth.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "unverified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "opencode.config",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$XDG_CONFIG_HOME/opencode/opencode.json",
                        "<project>/.opencode/",
                        "<project>/opencode.json",
                        "<project>/opencode.jsonc",
                        "~/.config/opencode/opencode.json",
                        "~/.config/opencode/opencode.jsonc"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "opencode.db",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$XDG_DATA_HOME/opencode/opencode.db",
                        "%LOCALAPPDATA%\\opencode\\opencode.db",
                        "~/.local/share/opencode/opencode-*.db",
                        "~/.local/share/opencode/opencode.db",
                        "~/.local/share/opencode/opencode.db-shm",
                        "~/.local/share/opencode/opencode.db-wal"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "opencode.legacy_json_storage",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.local/share/opencode/storage/message/*/*.json",
                        "~/.local/share/opencode/storage/part/*/*.json",
                        "~/.local/share/opencode/storage/session/*/ses_*.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "opencode.log",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$XDG_DATA_HOME/opencode/log/",
                        "%LOCALAPPDATA%\\opencode\\log\\",
                        "~/.local/share/opencode/log/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "opencode.managed_config",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%ProgramData%\\opencode",
                        "/Library/Application Support/opencode/",
                        "/etc/opencode/"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "opencode.mcp_auth",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$XDG_DATA_HOME/opencode/mcp-auth.json",
                        "~/.local/share/opencode/mcp-auth.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "file_snapshot",
                    "collect_priority": "normal",
                    "id": "opencode.repos_cache",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$XDG_DATA_HOME/opencode/repos/",
                        "~/.local/share/opencode/repos/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "opencode.tui_config",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/tui.json",
                        "~/.config/opencode/tui.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                }
            ]
        },
        {
            "agent": "pi",
            "artifacts": [
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "pi.auth",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.pi/agent/auth.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "pi.bin",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.pi/agent/bin/",
                        "~/.pi/agent/themes/",
                        "~/.pi/server/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "pi.debug_log",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.pi/agent/pi-debug.log"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "pi.extensions",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.pi/agent/extensions/*.ts",
                        "~/.pi/agent/tools/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "pi.models",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.pi/agent/models.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "pi.prompts",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.pi/agent/prompts/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "pi.sessions",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$PI_CODING_AGENT_SESSION_DIR/**/*.jsonl",
                        "~/.pi/agent/sessions/--<encoded-cwd>--/<iso-timestamp>_<session-id>.jsonl"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "pi.settings",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/.pi/",
                        "~/.pi/agent/settings.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                }
            ]
        },
        {
            "agent": "roo_code",
            "artifacts": [
                {
                    "category": "file_snapshot",
                    "collect_priority": "durable",
                    "id": "roo_code.checkpoints",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<vscode-user>/globalStorage/rooveterinaryinc.roo-cline/checkpoints/<workspaceHash>/.git/",
                        "<vscode-user>/globalStorage/rooveterinaryinc.roo-cline/checkpoints/<workspaceHash>/.git/info/exclude",
                        "<vscode-user>/globalStorage/rooveterinaryinc.roo-cline/tasks/<taskId>/checkpoints/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "roo_code.custom_storage_path",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.vscode/settings.json",
                        "<vscode-user>/settings.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "roo_code.extension_id",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<vscode-user>/globalStorage/rooveterinaryinc.roo-cline/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "roo_code.global_dirs",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.roo\\",
                        "~/.agents/",
                        "~/.roo/",
                        "~/.roo/rules-<mode>/",
                        "~/.roo/rules/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "roo_code.rules",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.clinerules",
                        "<project>/.clinerules-<mode>",
                        "<project>/.roo/rules-<mode>/",
                        "<project>/.roo/rules/",
                        "<project>/.rooignore",
                        "<project>/.roorules",
                        "<project>/.roorules-<mode>",
                        "<project>/AGENT.md",
                        "<project>/AGENTS.local.md",
                        "<project>/AGENTS.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "mcp_config",
                    "collect_priority": "normal",
                    "id": "roo_code.settings",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<vscode-user>/globalStorage/rooveterinaryinc.roo-cline/cache/",
                        "<vscode-user>/globalStorage/rooveterinaryinc.roo-cline/settings/custom_modes.yaml",
                        "<vscode-user>/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "roo_code.tasks",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<vscode-user>/globalStorage/rooveterinaryinc.roo-cline/tasks/**/_index.json",
                        "<vscode-user>/globalStorage/rooveterinaryinc.roo-cline/tasks/<taskId>/api_conversation_history.json",
                        "<vscode-user>/globalStorage/rooveterinaryinc.roo-cline/tasks/<taskId>/history_item.json",
                        "<vscode-user>/globalStorage/rooveterinaryinc.roo-cline/tasks/<taskId>/task_metadata.json",
                        "<vscode-user>/globalStorage/rooveterinaryinc.roo-cline/tasks/<taskId>/ui_messages.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                }
            ]
        },
        {
            "agent": "vscode",
            "artifacts": [
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "vscode.extension_dirs",
                    "os": [
                        "windows",
                        "macos",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.vscode\\extensions\\",
                        "~/.cursor/extensions/",
                        "~/.vscode-insiders/extensions/",
                        "~/.vscode-server/extensions/",
                        "~/.vscode/extensions/",
                        "~/.windsurf/extensions/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "vscode.extension_install_evidence",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.vscode\\extensions\\",
                        "~/.vscode-server/extensions/",
                        "~/.vscode/extensions/extensions.json",
                        "~/.vscode/extensions/kilocode.kilo-code-*/",
                        "~/.vscode/extensions/rooveterinaryinc.roo-cline-*/",
                        "~/.vscode/extensions/saoudrizwan.claude-dev-*/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "vscode.state_vscdb",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Code\\User\\globalStorage\\state.vscdb",
                        "~/.config/Code/User/globalStorage/state.vscdb",
                        "~/Library/Application Support/Code/User/globalStorage/state.vscdb",
                        "~/Library/Application Support/Code/User/globalStorage/state.vscdb.backup"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "durable",
                    "id": "vscode.user_data_roots",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Code\\User\\globalStorage\\",
                        "~/.config/Code/User/globalStorage/",
                        "~/.config/VSCodium/User/globalStorage/",
                        "~/.vscode-server/data/User/globalStorage/",
                        "~/Library/Application Support/Code - Insiders/User/globalStorage/",
                        "~/Library/Application Support/Code/User/globalStorage/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                }
            ]
        },
        {
            "agent": "warp",
            "artifacts": [
                {
                    "category": "prompt_history",
                    "collect_priority": "normal",
                    "id": "warp.sqlite",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "${XDG_STATE_HOME:-~/.local/state}/warp-terminal/warp.sqlite",
                        "%LOCALAPPDATA%\\warp\\Warp\\data\\warp.sqlite",
                        "~/Library/Group Containers/2BBY89MBSN.dev.warp/Library/Application Support/dev.warp.Warp-Stable/warp.sqlite",
                        "~/Library/Group Containers/2BBY89MBSN.dev.warp/Library/Application Support/dev.warp.Warp-Stable/warp.sqlite-shm",
                        "~/Library/Group Containers/2BBY89MBSN.dev.warp/Library/Application Support/dev.warp.Warp-Stable/warp.sqlite-wal"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                }
            ]
        },
        {
            "agent": "windsurf",
            "artifacts": [
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "windsurf.auth_credentials",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.cache/nvim/codeium/config.json",
                        "~/.codeium/config.json",
                        "~/.local/share/devin/credentials.toml",
                        "~/AppData/Local/devin/credentials.toml"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "windsurf.cascade_trajectories",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$WINDSURF_CONFIG_DIR/cascade/<cascade-id>.pb",
                        "%USERPROFILE%\\.codeium\\windsurf\\cascade\\<cascade-id>.pb",
                        "~/.codeium/windsurf/cascade/<cascade-id-uuid>.pb",
                        "~/.codeium/windsurf/cascade/<cascade-id-uuid>.pb.archived"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "windsurf.code_tracker_and_settings",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.codeium/windsurf/code_tracker/",
                        "~/.codeium/windsurf/installation_id",
                        "~/.codeium/windsurf/user_settings.pb"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "cache",
                    "collect_priority": "normal",
                    "id": "windsurf.embedding_database",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.codeium\\windsurf\\database\\<hash>\\",
                        "~/.codeium/windsurf/database/<hash>/embedding_database.sqlite",
                        "~/.codeium/windsurf/database/<md5-of-workspace-id>/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "normal",
                    "id": "windsurf.enterprise_policy",
                    "os": [
                        "windows"
                    ],
                    "paths": [
                        "/Applications/Devin.app/Contents/Resources/app/policies",
                        "/etc/windsurf/policies/policy.json",
                        "C:\\Windows\\PolicyDefinitions\\en-US\\windsurf.adml",
                        "C:\\Windows\\PolicyDefinitions\\windsurf.admx",
                        "HKCU\\Software\\Policies\\Windsurf\\<ProductName>",
                        "HKLM\\Software\\Policies\\Windsurf\\<ProductName>"
                    ],
                    "root": "registry",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "first",
                    "id": "windsurf.global_rules",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Codeium\\windsurf\\global_rules.md",
                        "%USERPROFILE%\\.codeium\\windsurf\\memories\\global_rules.md",
                        "~/.codeium/windsurf/global_rules.md",
                        "~/.codeium/windsurf/memories/global_rules.md"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "windsurf.hooks",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.codeium\\windsurf\\hooks.json",
                        "<project>/.windsurf/hooks.json",
                        "~/.codeium/windsurf/hooks.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "windsurf.ide_global_state_vscdb",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Devin\\User\\globalStorage\\state.vscdb",
                        "%APPDATA%\\Windsurf - Next\\User\\globalStorage\\state.vscdb",
                        "%APPDATA%\\Windsurf Insiders\\User\\globalStorage\\state.vscdb",
                        "%APPDATA%\\Windsurf\\User\\globalStorage\\state.vscdb",
                        "~/.config/Devin/User/globalStorage/state.vscdb",
                        "~/.config/Windsurf/User/globalStorage/state.vscdb",
                        "~/Library/Application Support/Devin/User/globalStorage/state.vscdb",
                        "~/Library/Application Support/Windsurf - Next/User/globalStorage/state.vscdb",
                        "~/Library/Application Support/Windsurf/User/globalStorage/state.vscdb",
                        "~/Library/Application Support/Windsurf/User/globalStorage/storage.json",
                        "~/Library/Application Support/Windsurf/machineId"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "windsurf.ide_workspace_state_vscdb",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Windsurf\\User\\workspaceStorage\\<hash>\\state.vscdb",
                        "~/.config/Windsurf/User/settings.json",
                        "~/.config/Windsurf/User/workspaceStorage/<hash>/state.vscdb",
                        "~/Library/Application Support/Windsurf/User/workspaceStorage/<hash>/state.vscdb"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "windsurf.implicit_trajectories",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.codeium\\windsurf\\implicit\\*.pb",
                        "~/.codeium/windsurf/implicit/*.pb"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "windsurf.language_server_binaries_and_logs",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%LOCALAPPDATA%\\Programs\\Windsurf\\",
                        "/Applications/Devin.app",
                        "/usr/share/windsurf/resources/app/extensions/windsurf/bin/language_server_linux_x64",
                        "C:\\Program Files\\Windsurf\\",
                        "~/.codeium/<version>/language_server_linux_x64",
                        "~/.codeium/<version>/language_server_macos_arm",
                        "~/.codeium/<version>/language_server_windows_x64.exe",
                        "~/.windsurf-server/data/logs/<timestamp>/1-windsurf.log"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "mcp_config",
                    "collect_priority": "normal",
                    "id": "windsurf.mcp_config",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.codeium\\windsurf\\mcp_config.json",
                        "<project>/.windsurf/mcp_config.json",
                        "~/.codeium/windsurf/mcp_config.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "memory",
                    "collect_priority": "durable",
                    "id": "windsurf.memories",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.codeium\\windsurf\\memories\\*.pb",
                        "~/.codeium/windsurf/memories/*.pb"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "windsurf.project_instructions",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.windsurf/rules/*.md",
                        "<project>/.windsurf/settings.json",
                        "<project>/.windsurfrules",
                        "<project>/AGENTS.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "windsurf.workflows_and_skills",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.windsurf/skills/",
                        "<project>/.windsurf/workflows/*.md",
                        "~/.codeium/windsurf/global_workflows/*.md",
                        "~/.codeium/windsurf/skills/"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                }
            ]
        },
        {
            "agent": "zed",
            "artifacts": [
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "zed.extensions",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$ZED_DATA_DIR/debug_adapters/",
                        "$ZED_DATA_DIR/extensions/",
                        "$ZED_DATA_DIR/external_agents/",
                        "$ZED_DATA_DIR/prompt_overrides/",
                        "~/.config/zed/prompts/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "zed.flatpak_legacy_threads",
                    "os": [
                        "linux"
                    ],
                    "paths": [
                        "~/.var/app/dev.zed.Zed/data/zed/threads/threads-db.1.mdb/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "zed.logs",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$XDG_DATA_HOME/zed/logs/",
                        "%LOCALAPPDATA%\\Zed\\logs\\",
                        "~/Library/Logs/Zed/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "mcp_config",
                    "collect_priority": "normal",
                    "id": "zed.settings",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$XDG_CONFIG_HOME/zed/settings.json",
                        "%APPDATA%\\Zed\\settings.json",
                        "<project>/.zed/settings.json",
                        "~/.config/zed/settings.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "zed.sidebar_threads",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$XDG_DATA_HOME/zed/db/0-<release_channel>/db.sqlite",
                        "%LOCALAPPDATA%\\Zed\\db\\0-<release_channel>\\db.sqlite",
                        "~/Library/Application Support/Zed/db/0-stable/db.sqlite"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "live_only",
                    "id": "zed.threads_db",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$XDG_DATA_HOME/zed/threads/threads.db",
                        "%LOCALAPPDATA%\\Zed\\threads\\threads.db",
                        "~/.local/share/zed/threads/threads.db",
                        "~/Library/Application Support/Zed/threads/threads.db"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                }
            ]
        }
    ],
    "sha256": "ab6057d1481144a027fc692b2574336bc7a589be2e24b103ccb833267442d896"
}
'@
$script:EmbeddedCatalogue = $EmbeddedCatalogueJson | ConvertFrom-Json
# --- END EMBEDDED CATALOGUE ---


# ============================================================================ utilities

function Write-Utf8NoBom {
    <#
    .SYNOPSIS
        Write text as UTF-8 without a byte order mark.
    .DESCRIPTION
        Set-Content and Out-File default to UTF-16LE on PowerShell 5.1, and even the UTF8
        option there emits a byte order mark. Either would make this collector's output
        differ from collect.py's for the same input, which is exactly what the differential
        test exists to catch.
    #>
    param([string] $Path, [string] $Text)
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $encoding)
}

function Get-UtcString {
    <#
    .SYNOPSIS
        Format a time as the bundle's one timestamp format, or $null.
    .DESCRIPTION
        Microseconds are always present and the zone is always UTC, because a manifest
        that sometimes carries them and sometimes not cannot be compared byte for byte.
        InvariantCulture because the format is culture dependent otherwise, and a machine
        set to a different locale would produce a different manifest for the same tree.

        A time the platform cannot supply is $null, never zero and never the epoch: the
        epoch is a real instant and would read as a genuine 1970 timestamp in a timeline.
    #>
    param([Nullable[DateTime]] $Value)
    if ($null -eq $Value) { return $null }
    $utc = ([DateTime]$Value).ToUniversalTime()
    # Python writes exactly six fractional digits. .NET's "ffffff" matches that.
    return $utc.ToString('yyyy-MM-ddTHH:mm:ss.ffffff', [System.Globalization.CultureInfo]::InvariantCulture) + 'Z'
}

function Get-Sha256OfFile {
    param([string] $Path)
    $stream = $null
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $bytes = $sha.ComputeHash($stream)
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        $sha.Dispose()
    }
    return ([System.BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
}

function Get-Sha256OfString {
    param([string] $Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
    } finally {
        $sha.Dispose()
    }
    return ([System.BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
}

function ConvertTo-CanonicalJson {
    <#
    .SYNOPSIS
        Serialize to the exact bytes Python's json.dumps(sort_keys=True, indent=2,
        ensure_ascii=False) produces.
    .DESCRIPTION
        The reason this exists rather than ConvertTo-Json: the two implementations of this
        format have to produce manifests that can be diffed byte for byte, and
        ConvertTo-Json differs from Python in key order, in indentation, in how it escapes
        non-ASCII and in how it renders numbers. It also defaults to -Depth 2 on 5.1, which
        silently flattens anything deeper into type names.

        Writing a serializer by hand is unusual and is the right call here: the output
        format is part of the specification, and a specification that says "whatever this
        version of this cmdlet happens to emit" is not one.

        Arrays must be passed as a generic List, not as a PowerShell array. PowerShell
        unwraps an array of one element and turns an empty one into $null when either
        crosses a function boundary, which would serialize a one-file manifest as an object
        instead of an array and a no-file manifest as null. Every array-valued field in
        this collector is therefore a List[object] built in place.
    #>
    param(
        [Parameter(Mandatory = $true)] [AllowNull()] $Value,
        [int] $Indent = 0
    )

    $pad = ' ' * $Indent
    $padInner = ' ' * ($Indent + 2)

    if ($null -eq $Value) { return 'null' }

    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }

    if ($Value -is [string]) { return (ConvertTo-JsonString $Value) }

    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte]) {
        return $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    }

    if ($Value -is [double] -or $Value -is [decimal] -or $Value -is [float]) {
        # Nothing in the manifest is a float. Emitting one would be a bug worth seeing
        # rather than a rounding difference worth hiding.
        throw ("ConvertTo-CanonicalJson: refusing to serialize the floating point value " +
               "$Value. The manifest format has no float fields; see docs/BUNDLE_FORMAT.md.")
    }

    if ($Value -is [System.Collections.IDictionary]) {
        if ($Value.Count -eq 0) { return '{}' }
        $parts = [System.Collections.Generic.List[string]]::new()
        # Entries are enumerated rather than looked up by key. An OrderedDictionary exposes
        # both an [object] and an [int] indexer, and Sort-Object hands keys back wrapped in
        # PSObject, so $Value[$key] cannot resolve the overload and throws "Argument types
        # do not match" at runtime. Enumerating sidesteps the indexer entirely.
        #
        # -CaseSensitive gives an ordinal sort, matching Python's sort by code point. A
        # culture-aware sort would order keys differently on a machine with another locale,
        # and the manifest would stop being comparable between two collections.
        $entries = @($Value.GetEnumerator()) | Sort-Object -Property Key -CaseSensitive
        foreach ($entry in $entries) {
            $rendered = ConvertTo-CanonicalJson -Value $entry.Value -Indent ($Indent + 2)
            $parts.Add($padInner + (ConvertTo-JsonString ([string]$entry.Key)) + ': ' + [string]$rendered)
        }
        return "{`n" + [string]::Join(",`n", $parts) + "`n" + $pad + '}'
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        # Enumerated with foreach rather than collected with @($Value), and the difference
        # is not style. @() on a List[object] built by New-Object throws "Argument types
        # do not match": it copies through ICollection.CopyTo and the overload cannot be
        # resolved for that particular combination, while the identical type built with
        # ::new() copies fine and a List[string] copies fine either way. The failure is in
        # the collection step, not in this function, so it would move around as calling
        # code changed. foreach uses the enumerator and has none of that.
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($item in $Value) {
            $parts.Add($padInner + [string](ConvertTo-CanonicalJson -Value $item -Indent ($Indent + 2)))
        }
        if ($parts.Count -eq 0) { return '[]' }
        return "[`n" + [string]::Join(",`n", $parts) + "`n" + $pad + ']'
    }

    throw "ConvertTo-CanonicalJson: unsupported type $($Value.GetType().FullName)"
}

function ConvertTo-JsonString {
    <#
    .SYNOPSIS
        Escape a string the way Python's json module does with ensure_ascii=False.
    .DESCRIPTION
        Only the characters the JSON grammar requires are escaped, plus the short forms
        Python uses. Everything else, including every non-ASCII character, is written
        through as UTF-8. Escaping non-ASCII as \uXXXX would also be valid JSON and would
        not match collect.py byte for byte.
    #>
    param([string] $Text)
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    foreach ($char in $Text.ToCharArray()) {
        $code = [int]$char
        switch ($char) {
            '"'  { [void]$builder.Append('\"'); continue }
            '\'  { [void]$builder.Append('\\'); continue }
            "`n" { [void]$builder.Append('\n'); continue }
            "`r" { [void]$builder.Append('\r'); continue }
            "`t" { [void]$builder.Append('\t'); continue }
            "`b" { [void]$builder.Append('\b'); continue }
            "`f" { [void]$builder.Append('\f'); continue }
            default {
                if ($code -lt 0x20) {
                    [void]$builder.Append(('\u{0:x4}' -f $code))
                } else {
                    [void]$builder.Append($char)
                }
            }
        }
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}


# ======================================================================== path mapping

# Characters that cannot appear in a path component on at least one supported platform,
# plus the separator itself. See docs/BUNDLE_FORMAT.md, "Path mapping".
$script:ReservedChars = [System.Collections.Generic.HashSet[char]]::new(
    [char[]]('<', '>', ':', '"', '|', '?', '*', '\', '/'))

$script:ReservedNames = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@('CON', 'PRN', 'AUX', 'NUL',
        'COM0', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
        'LPT0', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'),
    [System.StringComparer]::OrdinalIgnoreCase)

function Get-PercentEncoded {
    <#
    .SYNOPSIS
        Percent-encode one character as its UTF-8 bytes, upper-case hex.
    .DESCRIPTION
        Matches collect.py's _pct. A .NET string is UTF-16, so a character outside the
        basic multilingual plane arrives as a surrogate pair and is encoded by the caller
        as a unit; a lone surrogate encodes to the replacement character's bytes, which is
        lossy in the bundle path and is exactly why original_path is mandatory.
    #>
    param([string] $Character)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Character)
    $builder = [System.Text.StringBuilder]::new()
    foreach ($byte in $bytes) { [void]$builder.Append(('%{0:X2}' -f $byte)) }
    return $builder.ToString()
}

function ConvertTo-EncodedSegment {
    <#
    .SYNOPSIS
        Make one path component safe on every supported filesystem, reversibly.
    .DESCRIPTION
        Mirrors collect.py's encode_segment step for step, and the order of the steps is
        part of the format: '%' is encoded first, or nothing below it could be decoded
        unambiguously. Steps five and six are not reversible, which docs/BUNDLE_FORMAT.md
        states and which is why every manifest entry carries original_path.
    #>
    param([string] $Segment)

    $builder = [System.Text.StringBuilder]::new()
    foreach ($char in $Segment.ToCharArray()) {
        $code = [int]$char
        if ($char -eq '%') {
            [void]$builder.Append('%25')
        } elseif ($script:ReservedChars.Contains($char) -or $code -lt 0x20 -or
                  ($code -ge 0xD800 -and $code -le 0xDFFF)) {
            [void]$builder.Append((Get-PercentEncoded ([string]$char)))
        } else {
            [void]$builder.Append($char)
        }
    }
    $encoded = $builder.ToString()

    # Windows silently strips a trailing dot or space from a file name, which would change
    # the name and could collide with a sibling that differs only by it.
    if ($encoded.Length -gt 0) {
        $last = $encoded[$encoded.Length - 1]
        if ($last -eq '.' -or $last -eq ' ') {
            $encoded = $encoded.Substring(0, $encoded.Length - 1) + (Get-PercentEncoded ([string]$last))
        }
    }

    # A reserved device name cannot be a file name on Windows at all, whatever extension
    # follows it, so the first character is encoded and CON.txt becomes %43ON.txt.
    if ($encoded.Length -gt 0) {
        $stem = $encoded.Split('.')[0]
        if ($script:ReservedNames.Contains($stem)) {
            $encoded = (Get-PercentEncoded ([string]$encoded[0])) + $encoded.Substring(1)
        }
    }

    # Over-long components, measured in bytes rather than characters because that is what
    # the filesystem limits.
    $raw = [System.Text.Encoding]::UTF8.GetBytes($encoded)
    if ($raw.Length -gt 200) {
        $cut = 190
        # Do not split a multi-byte character: back up off any continuation byte.
        while ($cut -gt 0 -and (($raw[$cut] -band 0xC0) -eq 0x80)) { $cut -= 1 }
        $head = [System.Text.Encoding]::UTF8.GetString($raw, 0, $cut)
        $tag = (Get-Sha256OfString $Segment).Substring(0, 10)
        $encoded = $head + '~' + $tag
    }
    return $encoded
}

function Get-NormalizedPath {
    <#
    .SYNOPSIS
        Collapse a path the way Python's os.path.normpath does, without touching the disk.
    .DESCRIPTION
        Not [System.IO.Path]::GetFullPath, for two reasons: it resolves against the current
        directory, which a forensic tool must never let influence where it looks, and on
        Linux it would mangle a Windows-shaped path such as C:/Users/alice while collecting
        a mounted image.
    #>
    param([string] $Path)
    $isAbsolute = $Path.StartsWith('/')
    $drive = ''
    $rest = $Path
    $driveMatch = [regex]::Match($Path, '^([A-Za-z]:)/')
    if ($driveMatch.Success) {
        $drive = $driveMatch.Groups[1].Value
        $rest = $Path.Substring($drive.Length + 1)
    }
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($segment in $rest.Split('/')) {
        if ($segment -ceq '' -or $segment -ceq '.') { continue }
        if ($segment -ceq '..') {
            if ($out.Count -gt 0 -and $out[$out.Count - 1] -cne '..') {
                $out.RemoveAt($out.Count - 1)
                continue
            }
            if ($isAbsolute -or $drive) { continue }
        }
        $out.Add($segment)
    }
    $joined = [string]::Join('/', $out)
    if ($drive) { return $drive + '/' + $joined }
    if ($isAbsolute) { return '/' + $joined }
    if ($joined -ceq '') { return '.' }
    return $joined
}

function ConvertTo-BundlePath {
    <#
    .SYNOPSIS
        Map an original absolute path to its path inside the bundle.
    .DESCRIPTION
        $Used maps a case-folded bundle path to the original it came from. Without that
        check, a case-sensitive source written to a case-insensitive destination silently
        loses one of two files whose names differ only in case, and the bundle would be
        internally consistent while missing evidence.
    #>
    param(
        [string] $Original,
        [System.Collections.IDictionary] $Used,
        [string] $TargetOs
    )

    $segments = [System.Collections.Generic.List[string]]::new()
    if ($TargetOs -eq 'windows') {
        $norm = $Original.Replace('\', '/')
        if ($norm.StartsWith('//')) {
            # A UNC path. The share is evidence of where the file came from, so it is kept
            # as path segments rather than flattened away.
            $segments.Add('UNC')
            foreach ($part in $norm.Substring(2).Split('/')) {
                if ($part) { $segments.Add($part) }
            }
        } elseif ($norm -match '^[A-Za-z]:/') {
            $segments.Add($norm.Substring(0, 1).ToUpperInvariant())
            foreach ($part in $norm.Substring(3).Split('/')) {
                if ($part) { $segments.Add($part) }
            }
        } else {
            foreach ($part in $norm.Split('/')) {
                if ($part) { $segments.Add($part) }
            }
        }
    } else {
        foreach ($part in $Original.Split('/')) {
            if ($part) { $segments.Add($part) }
        }
    }

    $encoded = [System.Collections.Generic.List[string]]::new()
    foreach ($segment in $segments) { $encoded.Add((ConvertTo-EncodedSegment $segment)) }

    $candidate = [string]::Join('/', $encoded)
    $folded = $candidate.ToLowerInvariant()
    # -cne, not -ne. PowerShell's string comparison operators are case-insensitive by
    # default, which in the one check whose whole purpose is detecting a case collision
    # made the two paths compare equal and the suffix was never appended: Settings.json
    # and settings.json then mapped to the same bundle path and one overwrote the other.
    if ($Used.Contains($folded) -and [string]$Used[$folded] -cne $Original) {
        $suffix = '~' + (Get-Sha256OfString $Original).Substring(0, 10)
        $encoded[$encoded.Count - 1] = $encoded[$encoded.Count - 1] + $suffix
        $candidate = [string]::Join('/', $encoded)
        $folded = $candidate.ToLowerInvariant()
    }
    $Used[$folded] = $Original
    return $candidate
}


# ============================================================== placeholder expansion

# Windows placeholders expanded relative to the profile being collected.
$script:WinPlaceholders = [ordered]@{
    '%USERPROFILE%'   = ''
    '%APPDATA%'       = 'AppData/Roaming'
    '%LOCALAPPDATA%'  = 'AppData/Local'
}

# Windows placeholders that are machine-wide rather than relative to a profile, kept
# apart from the table above because they must not be joined to a user's home directory.
# The drive is assumed to be C: for the reason collect.py gives: a mounted image has no
# environment to read, and these are the paths that prove a binary executed at all.
$script:WinSystemPlaceholders = [ordered]@{
    '%SYSTEMROOT%'        = 'C:/Windows'
    '%WINDIR%'            = 'C:/Windows'
    '%SYSTEMDRIVE%'       = 'C:'
    '%PROGRAMFILES(X86)%' = 'C:/Program Files (x86)'
    '%PROGRAMFILES%'      = 'C:/Program Files'
    '%PROGRAMDATA%'       = 'C:/ProgramData'
    '%ALLUSERSPROFILE%'   = 'C:/ProgramData'
    '%PUBLIC%'            = 'C:/Users/Public'
}

$script:XdgDefaults = [ordered]@{
    'XDG_DATA_HOME'   = '.local/share'
    'XDG_CONFIG_HOME' = '.config'
    'XDG_CACHE_HOME'  = '.cache'
    'XDG_STATE_HOME'  = '.local/state'
}

# The user directory of VS Code and of the forks that inherit its storage layout. A dozen
# agentic extensions keep their conversations under it, so <vscode-user> expands to all of
# these rather than to a wildcard: a wildcard matches one directory level and finds
# nothing, which is how an extension's entire history goes missing with nobody told.
#
# Kept in step with the same table in collect.py by the conformance suite.
$script:VsCodeProducts = @('Code', 'Code - Insiders', 'VSCodium', 'Cursor', 'Windsurf',
    'Kiro', 'Trae', 'Positron')

$script:VsCodeUserTemplates = [ordered]@{
    'macos'   = 'Library/Application Support/{0}/User'
    'linux'   = '.config/{0}/User'
    'windows' = 'AppData/Roaming/{0}/User'
}

# Patterns this run refused to search, with the reason. Script state rather than a return
# value so every call site stays a plain list of patterns, and surfaced in the manifest
# because a pattern the collector declined to follow is a hole in the evidence and has to
# be visible as one. See docs/BUNDLE_FORMAT.md.
$script:PatternRefusals = [System.Collections.Generic.List[object]]::new()

function Add-PatternRefusal {
    <#
    .SYNOPSIS
        Record a refusal once and return nothing, which is what the caller expects.
    #>
    param([string] $Pattern, [string] $Expanded, [string] $Reason)
    foreach ($existingItem in $script:PatternRefusals) {
        [System.Collections.IDictionary] $existing = $existingItem
        if ([string]$existing['pattern'] -ceq $Pattern -and
            [string]$existing['reason'] -ceq $Reason) { return }
    }
    $record = [ordered]@{}
    $record['expanded'] = $Expanded
    $record['pattern'] = $Pattern
    $record['reason'] = $Reason
    [void]$script:PatternRefusals.Add($record)
}

function Resolve-EnvPrefix {
    <#
    .SYNOPSIS
        Resolve a leading environment variable in a catalogue path.
    .DESCRIPTION
        Mirrors collect.py's resolve_env_prefix, including which of the three outcomes is
        worth reporting. Agents relocate their whole data tree with a variable of their own
        (CLAUDE_CONFIG_DIR, CODEX_HOME, HERMES_HOME and a dozen more) and the catalogue
        carries those spellings so a relocated tree is still found.

        Returns an ordered dictionary with 'text' and 'outcome'. 'ok' means rewritten,
        'unset' means the variable is not set here so the pattern does not apply and its
        default-location sibling covers it, and anything else is a reason to report:
        collecting a mounted image, the endpoint's environment cannot be read from the
        analyst's workstation and guessing would be worse than saying so.
    #>
    param([string] $Text, [string] $ProfileHome, [string] $Root)

    $result = [ordered]@{}

    # ${VAR:-default} is shell syntax and appears where vendor documentation used it. The
    # default half is the path the agent uses when the variable is unset, so it is real.
    $braced = [regex]::Match($Text, '^\$\{([A-Za-z_][A-Za-z0-9_]*):-([^}]*)\}(.*)$')
    if ($braced.Success) {
        $name = $braced.Groups[1].Value
        $fallback = $braced.Groups[2].Value
        $tail = $braced.Groups[3].Value
        $value = $null
        if (-not $Root) { $value = [System.Environment]::GetEnvironmentVariable($name) }
        $base = $fallback
        if ($value) { $base = $value }
        if ($base.StartsWith('~')) { $base = $ProfileHome + $base.Substring(1) }
        $result['text'] = $base.TrimEnd('/') + $tail
        $result['outcome'] = 'ok'
        return $result
    }

    $plain = [regex]::Match($Text, '^\$([A-Za-z_][A-Za-z0-9_]*)(.*)$')
    if (-not $plain.Success) {
        $result['text'] = $Text
        $result['outcome'] = 'malformed_variable'
        return $result
    }
    $name = $plain.Groups[1].Value
    $tail = $plain.Groups[2].Value

    if ($name -ceq 'HOME') {
        $result['text'] = $ProfileHome.TrimEnd('/') + $tail
        $result['outcome'] = 'ok'
        return $result
    }
    if ($script:XdgDefaults.Contains($name)) {
        $value = $null
        if (-not $Root) { $value = [System.Environment]::GetEnvironmentVariable($name) }
        if (-not $value) {
            $value = $ProfileHome.TrimEnd('/') + '/' + [string]$script:XdgDefaults[$name]
        }
        $result['text'] = $value.TrimEnd('/') + $tail
        $result['outcome'] = 'ok'
        return $result
    }

    if ($Root) {
        $result['text'] = $Text
        $result['outcome'] = 'environment_unreadable_offline'
        return $result
    }
    $value = [System.Environment]::GetEnvironmentVariable($name)
    if (-not $value) {
        $result['text'] = $Text
        $result['outcome'] = 'unset'
        return $result
    }
    $result['text'] = $value.TrimEnd('/') + $tail
    $result['outcome'] = 'ok'
    return $result
}

function Expand-VsCodeUser {
    <#
    .SYNOPSIS
        Turn one <vscode-user> pattern into one pattern per known product.
    #>
    param([string] $Pattern, [string] $ProfileHome, [string] $TargetOs)
    $out = [System.Collections.Generic.List[string]]::new()
    if (-not $script:VsCodeUserTemplates.Contains($TargetOs)) { return $out }
    $template = [string]$script:VsCodeUserTemplates[$TargetOs]
    $tail = $Pattern.Substring('<vscode-user>'.Length).TrimStart('\', '/')
    foreach ($product in $script:VsCodeProducts) {
        $base = [string]::Format($template, $product)
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($piece in @($ProfileHome.TrimEnd('/'), $base, $tail)) {
            if ($piece) { $parts.Add($piece) }
        }
        $out.Add([string]::Join('/', $parts))
    }
    return ,$out
}

function Expand-CataloguePath {
    <#
    .SYNOPSIS
        Turn one catalogue path pattern into concrete glob patterns on this filesystem.
    .DESCRIPTION
        Mirrors collect.py's expand_paths. An angle-bracket segment is a human-readable
        placeholder and becomes a single-level wildcard, which is safe: a false match costs
        a skipped manifest entry, while treating it literally would collect nothing.

        Anything this function declines to search is recorded in $script:PatternRefusals,
        never dropped. A collector that quietly searches nothing produces a clean bundle
        from a host it never looked at, which is the one failure this tool must not have.
    #>
    param([string] $Pattern, [string] $ProfileHome, [string] $TargetOs, [string] $Root)

    $results = [System.Collections.Generic.List[string]]::new()
    $text = $Pattern

    if ($text.StartsWith('<vscode-user>')) {
        foreach ($expanded in (Expand-VsCodeUser -Pattern $text -ProfileHome $ProfileHome -TargetOs $TargetOs)) {
            foreach ($final in (Expand-CataloguePath -Pattern $expanded -ProfileHome $ProfileHome -TargetOs $TargetOs -Root $Root)) {
                $results.Add($final)
            }
        }
        return ,$results
    }

    # A catalogue entry lists every operating system's spelling of the same artifact in one
    # paths list, so on any given host most of them do not apply. That is expected and is
    # not a refusal. What must never be quiet is a pattern that applies here and still
    # cannot be resolved, which is what the refusals at the end are for.
    if ($TargetOs -eq 'windows') {
        if ($text.StartsWith('$')) { return $results }  # freedesktop variable
        $upper = $text.ToUpperInvariant()
        $matched = $false
        foreach ($key in $script:WinPlaceholders.Keys) {
            if ($upper.StartsWith($key)) {
                $tail = $text.Substring(([string]$key).Length).TrimStart('\', '/')
                $parts = [System.Collections.Generic.List[string]]::new()
                foreach ($piece in @($ProfileHome, [string]$script:WinPlaceholders[$key], $tail)) {
                    if ($piece) { $parts.Add($piece) }
                }
                $text = [string]::Join('/', $parts)
                $matched = $true
                break
            }
        }
        if (-not $matched) {
            foreach ($key in $script:WinSystemPlaceholders.Keys) {
                if ($upper.StartsWith($key)) {
                    $text = [string]$script:WinSystemPlaceholders[$key] + $text.Substring(([string]$key).Length)
                    $matched = $true
                    break
                }
            }
            if (-not $matched -and $text.StartsWith('~')) {
                # ~ is the catalogue's ordinary spelling for the user profile and many
                # entries give no other. Leaving it unexpanded meant the pattern was
                # searched relative to the working directory, so on Windows those
                # artifacts were never found and the manifest reported a clean profile.
                $text = $ProfileHome.TrimEnd('/') + $text.Substring(1)
            }
        }
        $text = $text.Replace('\', '/')
    } else {
        if ($text -match '^%[A-Za-z_]+%' -or $text -match '^[A-Za-z]:\\' -or $text.StartsWith('HKEY_')) {
            return $results  # a Windows spelling or a registry key, meaningless here
        }
        if ($text.StartsWith('$')) {
            $resolved = Resolve-EnvPrefix -Text $text -ProfileHome $ProfileHome -Root $Root
            $outcome = [string]$resolved['outcome']
            if ($outcome -ceq 'unset') { return $results }
            if ($outcome -cne 'ok') {
                Add-PatternRefusal -Pattern $Pattern -Expanded $text -Reason $outcome
                return ,$results
            }
            $text = [string]$resolved['text']
        }
        if ($text.StartsWith('~')) { $text = $ProfileHome + $text.Substring(1) }
    }

    $text = [regex]::Replace($text, '<[^>]+>', '*')

    if ($Root -and -not $text.StartsWith($Root.TrimEnd('/') + '/') -and $text -cne $Root.TrimEnd('/')) {
        # Re-anchor under the mounted root, but only when it is not already anchored there.
        # A profile-relative path already carries the root because $ProfileHome was discovered
        # inside it; an absolute system path and a project root read out of an agent's own
        # state do not. Re-anchoring unconditionally double-prefixed the first kind, and
        # every profile artifact then silently failed to match.
        $relative = [regex]::Replace($text, '^[A-Za-z]:/', '').TrimStart('/')
        $text = $Root.TrimEnd('/') + '/' + $relative
    }

    # A pattern that reduces to a bare wildcard near the top of the tree would collect the
    # whole filesystem under one artifact id. That is not hypothetical: a catalogue entry
    # once carried prose in angle brackets, expansion turned it into a wildcard, and one
    # artifact swallowed a home directory. The schema rejects such an entry now, and this
    # is the second line of defence, because a collector in the field fails closed.
    $stripped = $text.TrimEnd('/')
    if ($stripped.EndsWith('/*') -and (($stripped.ToCharArray() | Where-Object { $_ -eq '/' }).Count -le 1)) {
        Add-PatternRefusal -Pattern $Pattern -Expanded $text -Reason 'wildcard_too_broad'
        return ,$results
    }
    if ([regex]::Replace($stripped, '[*?/]', '') -ceq '') {
        Add-PatternRefusal -Pattern $Pattern -Expanded $text -Reason 'wildcard_only'
        return ,$results
    }

    # A relative pattern would be searched against the process working directory, which on
    # an analyst workstation is somewhere in the case folder and on an endpoint is wherever
    # the responder happened to be. Both find the wrong thing or nothing, and neither says
    # so.
    if (-not ($text.StartsWith('/') -or $text -match '^[A-Za-z]:/')) {
        Add-PatternRefusal -Pattern $Pattern -Expanded $text -Reason 'not_absolute'
        return ,$results
    }

    # A literal path is normalized, a glob is not. This mirrors collect.py, which ends with
    # os.path.normpath for a pattern with no wildcard: without it a catalogue entry written
    # with a trailing slash produces a different manifest path in each collector for the
    # same file, and the differential test between the two would fail on 769 entries that
    # are in fact identical.
    if ($text.Contains('*') -or $text.Contains('?')) {
        $results.Add($text)
    } else {
        $results.Add((Get-NormalizedPath $text))
    }
    return ,$results
}


# ========================================================================== discovery

function Test-PathExists {
    <#
    .SYNOPSIS
        Does this path exist, without following a symbolic link.
    .DESCRIPTION
        Test-Path -Path follows links, so a dangling link reads as absent and the fact that
        an agent left a link behind would be lost. Existence is therefore asked of the
        filesystem entry itself.
    #>
    param([string] $Path)
    try {
        $info = [System.IO.FileInfo]::new($Path)
        if ($info.Exists) { return $true }
        return [System.IO.Directory]::Exists($Path)
    } catch {
        return $false
    }
}

function Test-IsSymlink {
    param([string] $Path)
    try {
        $attrs = [System.IO.File]::GetAttributes($Path)
        return (($attrs -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
    } catch {
        return $false
    }
}

function Get-GlobMatches {
    <#
    .SYNOPSIS
        Expand a glob without descending into symlinked directories.
    .DESCRIPTION
        Mirrors collect.py's iter_matches, walk for walk, rather than using
        Get-ChildItem -Recurse: the two implementations have to agree on what a pattern
        matches, and a cmdlet's own interpretation of ** and of link following is not
        something this format can depend on.

        -clike rather than -like, because PowerShell's wildcard operators are
        case-insensitive by default and Python's fnmatch on a POSIX host is not. The
        difference is invisible on Windows, where the filesystem is case-insensitive
        anyway, and it is what lets the differential test run both collectors over one
        tree and compare.
    #>
    param([string] $Pattern, [int] $Limit = 100000)

    if (-not ($Pattern.Contains('*') -or $Pattern.Contains('?'))) {
        $out = [System.Collections.Generic.List[string]]::new()
        if (Test-PathExists $Pattern) { $out.Add($Pattern) }
        return ,$out
    }

    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($piece in $Pattern.Split('/')) { $parts.Add($piece) }

    $bases = [System.Collections.Generic.List[string]]::new()
    if ($Pattern.StartsWith('/')) {
        $bases.Add('/')
        $parts.RemoveAt(0)
    } elseif ($parts.Count -gt 0 -and $parts[0] -match '^[A-Za-z]:$') {
        $bases.Add($parts[0] + '/')
        $parts.RemoveAt(0)
    } else {
        $bases.Add('.')
    }

    for ($index = 0; $index -lt $parts.Count; $index++) {
        $part = $parts[$index]
        $next = [System.Collections.Generic.List[string]]::new()

        if ($part -ceq '**') {
            foreach ($base in $bases) {
                foreach ($dir in (Get-DirectoryTree $base $Limit)) { $next.Add($dir) }
            }
        } elseif ($part.Contains('*') -or $part.Contains('?')) {
            foreach ($base in $bases) {
                $names = [System.Collections.Generic.List[string]]::new()
                try {
                    foreach ($child in [System.IO.Directory]::GetFileSystemEntries($base)) {
                        $names.Add([System.IO.Path]::GetFileName($child))
                    }
                } catch {
                    continue
                }
                foreach ($name in (Sort-Ordinal $names)) {
                    if ($name -clike $part) { $next.Add((Join-BundlePath $base $name)) }
                }
            }
        } else {
            foreach ($base in $bases) {
                $candidate = Join-BundlePath $base $part
                if (Test-PathExists $candidate) { $next.Add($candidate) }
            }
        }

        $bases = $next
        if ($bases.Count -eq 0) { return ,$bases }
        if ($index -lt ($parts.Count - 1)) {
            $kept = [System.Collections.Generic.List[string]]::new()
            foreach ($base in $bases) {
                if ([System.IO.Directory]::Exists($base)) { $kept.Add($base) }
            }
            $bases = $kept
            if ($bases.Count -eq 0) { return ,$bases }
        }
    }

    $unique = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($base in $bases) { [void]$unique.Add($base) }
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($item in $unique) { $out.Add($item) }
    return ,$out
}

function Join-BundlePath {
    <#
    .SYNOPSIS
        Join two path pieces with a forward slash, exactly once.
    .DESCRIPTION
        Join-Path would use the platform separator and would produce backslashes on
        Windows, and every path inside this collector is held with forward slashes so that
        the two implementations produce the same manifest for the same tree.
    #>
    param([string] $Base, [string] $Leaf)
    if ($Base -ceq '/') { return '/' + $Leaf }
    return $Base.TrimEnd('/') + '/' + $Leaf
}

function Get-DirectoryTree {
    <#
    .SYNOPSIS
        Every directory at or under a base, without following symbolic links.
    #>
    param([string] $Base, [int] $Limit = 100000)
    $found = [System.Collections.Generic.List[string]]::new()
    if (-not [System.IO.Directory]::Exists($Base)) { return $found }
    $stack = [System.Collections.Generic.Stack[string]]::new()
    $stack.Push($Base)
    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        $found.Add($current)
        if ($found.Count -ge $Limit) { return $found }
        $children = [System.Collections.Generic.List[string]]::new()
        try {
            foreach ($dir in [System.IO.Directory]::GetDirectories($current)) { $children.Add($dir) }
        } catch {
            continue
        }
        foreach ($dir in ($children | Sort-Object -CaseSensitive -Descending)) {
            $normalized = ([string]$dir).Replace('\', '/')
            # A link out of the profile would take the collection with it.
            if (-not (Test-IsSymlink $normalized)) { $stack.Push($normalized) }
        }
    }
    return ,$found
}

function Get-RegularFilesUnder {
    <#
    .SYNOPSIS
        List regular files under a directory, without following symlinked directories.
    .DESCRIPTION
        Returns an ordered dictionary with 'files' and 'truncated'. Hitting the cap is
        recorded as an error rather than passing silently, because a truncated artifact
        looks exactly like a small one in the manifest.
    #>
    param([string] $Base, [int] $Limit)
    $files = [System.Collections.Generic.List[string]]::new()
    $truncated = $false
    foreach ($dir in (Get-DirectoryTree $Base)) {
        $names = [System.Collections.Generic.List[string]]::new()
        try {
            foreach ($file in [System.IO.Directory]::GetFiles($dir)) { $names.Add(([string]$file).Replace('\', '/')) }
        } catch {
            continue
        }
        foreach ($name in (Sort-Ordinal $names)) {
            $files.Add([string]$name)
            if ($files.Count -ge $Limit) { $truncated = $true; break }
        }
        if ($truncated) { break }
    }
    $result = [ordered]@{}
    $result['files'] = $files
    $result['truncated'] = $truncated
    return $result
}

function Get-ProfilesToScan {
    <#
    .SYNOPSIS
        The user profiles to scan, as a list of ordered dictionaries with name and home.
    #>
    param([string] $Root, [bool] $AllUsers, [string[]] $Named)

    $found = [System.Collections.Generic.List[object]]::new()

    if ($Root) {
        # A mounted image or an exported profile. Look for the usual profile parents, and
        # fall back to treating the root itself as one profile, because an exported single
        # profile is a common shape and finding nothing in it would read as a clean host.
        foreach ($parent in @('Users', 'home', 'root')) {
            $base = Join-BundlePath $Root $parent
            if (-not [System.IO.Directory]::Exists($base)) { continue }
            if ($parent -ceq 'root') {
                $entry = [ordered]@{}; $entry['home'] = $base; $entry['name'] = 'root'
                [void]$found.Add($entry)
                continue
            }
            $names = [System.Collections.Generic.List[string]]::new()
            try {
                foreach ($dir in [System.IO.Directory]::GetDirectories($base)) {
                    $names.Add([System.IO.Path]::GetFileName(([string]$dir).TrimEnd('/', '\')))
                }
            } catch {
                continue
            }
            foreach ($name in ($names | Sort-Object -CaseSensitive)) {
                $entry = [ordered]@{}
                $entry['home'] = (Join-BundlePath $base $name)
                $entry['name'] = $name
                [void]$found.Add($entry)
            }
        }
        if ($found.Count -eq 0) {
            $leaf = [System.IO.Path]::GetFileName($Root.TrimEnd('/', '\'))
            if (-not $leaf) { $leaf = 'root' }
            $entry = [ordered]@{}; $entry['home'] = $Root; $entry['name'] = $leaf
            [void]$found.Add($entry)
        }
    } elseif ($AllUsers) {
        foreach ($parent in @('C:/Users', '/Users', '/home')) {
            if (-not [System.IO.Directory]::Exists($parent)) { continue }
            $names = [System.Collections.Generic.List[string]]::new()
            try {
                foreach ($dir in [System.IO.Directory]::GetDirectories($parent)) {
                    $names.Add([System.IO.Path]::GetFileName(([string]$dir).TrimEnd('/', '\')))
                }
            } catch {
                continue
            }
            foreach ($name in ($names | Sort-Object -CaseSensitive)) {
                # $profilePath, because $home is the automatic $HOME. Assigning it inside a
                # function is legal and creates a local, which makes it a trap rather than
                # an error for whoever edits this next.
                $profilePath = Join-BundlePath $parent $name
                if (Test-IsSymlink $profilePath) { continue }
                $entry = [ordered]@{}; $entry['home'] = $profilePath; $entry['name'] = $name
                [void]$found.Add($entry)
            }
        }
    } else {
        $profilePath = [System.Environment]::GetEnvironmentVariable('USERPROFILE')
        if (-not $profilePath) { $profilePath = [System.Environment]::GetEnvironmentVariable('HOME') }
        if (-not $profilePath) { $profilePath = $HOME }
        $entry = [ordered]@{}
        $entry['home'] = ([string]$profilePath).Replace('\', '/')
        $entry['name'] = (Get-CollectorUser)
        [void]$found.Add($entry)
    }

    if ($Named -and $Named.Count -gt 0) {
        $kept = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $found) {
            if ($Named -ccontains [string]$entry['name']) { [void]$kept.Add($entry) }
        }
        return ,$kept
    }
    return ,$found
}

function Get-CollectorUser {
    try {
        $name = [System.Environment]::UserName
        if ($name) { return $name }
    } catch {
        # Fall through: a user name is context, not evidence, and must not stop a run.
    }
    $fallback = [System.Environment]::GetEnvironmentVariable('USERNAME')
    if (-not $fallback) { $fallback = [System.Environment]::GetEnvironmentVariable('USER') }
    if (-not $fallback) { $fallback = 'unknown' }
    return $fallback
}


# ========================================================================= collection

function Get-ProjectRoots {
    <#
    .SYNOPSIS
        The working copies whose project-anchored artifacts should be collected.
    .DESCRIPTION
        Project instruction files (CLAUDE.md, AGENTS.md, .cursorrules and the rest) live
        inside a user's repositories rather than under the profile, and they are the
        prompt-injection surface. They cannot be found by expanding a profile, so the
        agent's own state is read for the list: the projects key of ~/.claude.json is
        authoritative, and the encoded directory names under projects/ are a fallback.

        The encoding replaces every non-alphanumeric character with a dash and is not
        reversible, so a decoded name is used only when it happens to name a real
        directory. Mirrors collect.py's discover_project_roots.
    #>
    param([string] $ProfileHome)

    $roots = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

    function Add-Root {
        param([string] $Path, [string] $Source)
        $normalized = ([string]$Path).Replace('\', '/').TrimEnd('/')
        if (-not $normalized) { return }
        if (-not $seen.Add($normalized)) { return }
        if (-not [System.IO.Directory]::Exists($normalized)) { return }
        $entry = [ordered]@{}
        $entry['path'] = $normalized
        $entry['source'] = $Source
        [void]$roots.Add($entry)
    }

    $configPath = Join-BundlePath $ProfileHome '.claude.json'
    if (Test-PathExists $configPath) {
        try {
            $raw = [System.IO.File]::ReadAllText($configPath)
            $parsed = $raw | ConvertFrom-Json
            if ($parsed.PSObject.Properties.Name -ccontains 'projects') {
                foreach ($property in $parsed.projects.PSObject.Properties) {
                    Add-Root -Path $property.Name -Source 'claude_code.global_config'
                }
            }
        } catch {
            # A config we cannot parse is not a reason to collect nothing. The projects
            # directory below is a second, independent source for the same list.
        }
    }

    $projectsDir = Join-BundlePath $ProfileHome '.claude/projects'
    if ([System.IO.Directory]::Exists($projectsDir)) {
        $names = [System.Collections.Generic.List[string]]::new()
        try {
            foreach ($dir in [System.IO.Directory]::GetDirectories($projectsDir)) {
                $names.Add([System.IO.Path]::GetFileName(([string]$dir).TrimEnd('/', '\')))
            }
        } catch {
            $names.Clear()
        }
        foreach ($name in ($names | Sort-Object -CaseSensitive)) {
            $candidate = '/' + ([string]$name).TrimStart('-').Replace('-', '/')
            Add-Root -Path $candidate -Source 'claude_code.projects_dir_name'
        }
    }

    return ,$roots
}

function Get-FileTimes {
    <#
    .SYNOPSIS
        Every timestamp the platform offers, as the bundle's timestamp format or null.
    .DESCRIPTION
        On Windows CreationTime is a real creation time, which is what birthtime_utc means
        on macOS, so it is reported there rather than left null. ctime_utc carries
        CreationTime as well, because docs/BUNDLE_FORMAT.md documents that this field means
        inode change time on Unix and creation time on Windows rather than pretending the
        two are the same thing.
    #>
    param([System.IO.FileSystemInfo] $Info)
    $times = [ordered]@{}
    $times['atime_utc'] = (Get-UtcString $Info.LastAccessTimeUtc)
    $times['birthtime_utc'] = (Get-UtcString $Info.CreationTimeUtc)
    $times['ctime_utc'] = (Get-UtcString $Info.CreationTimeUtc)
    $times['mtime_utc'] = (Get-UtcString $Info.LastWriteTimeUtc)
    return $times
}

function Copy-ArtifactFile {
    <#
    .SYNOPSIS
        Collect one file and return its manifest entry.
    .DESCRIPTION
        Every path out of this function produces an entry. A file that could not be read is
        still described, with a reason, because a collection that silently omits what it
        could not open leaves an analyst unable to tell absent from unreadable.

        $Withhold is decided by the caller across every artifact claiming this path, so a
        credential file caught by a broad directory glob is withheld too. See ADR 0014.
    #>
    param(
        $Artifact,
        [string] $Original,
        [string] $ProfileHome,
        [string] $UserName,
        [string] $FilesDir,
        [System.Collections.IDictionary] $Used,
        [string] $TargetOs,
        [bool] $Withhold,
        [bool] $IncludeSecrets,
        [long] $MaxFileSize,
        [bool] $DryRun
    )

    $entry = [ordered]@{}
    $entry['agent'] = ([string]$Artifact.id).Split('.')[0]
    $entry['artifact_id'] = [string]$Artifact.id
    $entry['atime_utc'] = $null
    $entry['birthtime_utc'] = $null
    $entry['bundle_path'] = $null
    $entry['category'] = [string]$Artifact.category
    $entry['changed_while_reading'] = $false
    $entry['collected'] = $false
    $entry['ctime_utc'] = $null
    $entry['mtime_utc'] = $null
    $entry['original_path'] = $Original
    $entry['reason'] = $null
    $entry['reparse_point'] = $false
    $entry['sha256'] = $null
    $entry['size'] = $null
    $entry['status'] = [string]$Artifact.status
    $entry['symlink'] = $null
    $entry['user'] = $UserName

    # What gets read, as opposed to what gets reported. They differ for a symbolic link
    # inside the profile: the bytes come from the target, and original_path plus the bundle
    # path stay on the link, because that is how the file was found.
    $readPath = $Original

    $isDirectory = $false
    try {
        $isDirectory = [System.IO.Directory]::Exists($Original)
        if (-not $isDirectory -and -not [System.IO.File]::Exists($Original)) {
            # Neither, which on a live host usually means a link whose target is gone or a
            # path we are not allowed to stat. Either way it is recorded, never dropped.
            if (Test-PathExists $Original) {
                $entry['reason'] = 'not_a_file'
            } else {
                $entry['reason'] = 'unreadable'
            }
            return $entry
        }
    } catch [System.UnauthorizedAccessException] {
        $entry['reason'] = 'permission_denied'
        return $entry
    } catch {
        $entry['reason'] = 'unreadable'
        return $entry
    }

    if (Test-IsSymlink $Original) {
        $entry['reparse_point'] = $true
        $target = $null
        try {
            $info = [System.IO.FileInfo]::new($Original)
            if ($info.PSObject.Properties.Name -ccontains 'LinkTarget') { $target = $info.LinkTarget }
        } catch {
            $target = $null
        }
        $entry['symlink'] = $target
        $resolved = $null
        try {
            $resolved = ([string]([System.IO.Path]::GetFullPath($Original))).Replace('\', '/')
            if ($target) {
                if ($target -match '^([A-Za-z]:|/)') {
                    $resolved = ([string]$target).Replace('\', '/')
                } else {
                    $parent = [System.IO.Path]::GetDirectoryName($Original)
                    $resolved = (Get-NormalizedPath ((([string]$parent).Replace('\', '/')).TrimEnd('/') + '/' + ([string]$target).Replace('\', '/')))
                }
            }
        } catch {
            $resolved = $null
        }
        $homeNormalized = (Get-NormalizedPath $ProfileHome)
        # A link out of the profile would take the collection somewhere it was never
        # authorized to read. Recorded, not followed.
        if (-not $resolved -or -not $resolved.StartsWith($homeNormalized.TrimEnd('/') + '/')) {
            $entry['reason'] = 'skipped_symlink'
            return $entry
        }
        # Inside the profile, so the link is followed and the rest of this function
        # describes the target: its size, its hash and its timestamps are what the bundle
        # will hold. original_path still records the link, which is how it was found.
        if ([System.IO.File]::Exists($resolved)) {
            $readPath = $resolved
        } elseif ([System.IO.Directory]::Exists($resolved)) {
            $entry['reason'] = 'not_a_file'
            return $entry
        } else {
            $entry['reason'] = 'unreadable'
            return $entry
        }
    }

    if ($isDirectory) {
        $entry['reason'] = 'not_a_file'
        return $entry
    }

    $info = $null
    try {
        $info = [System.IO.FileInfo]::new($readPath)
        $times = Get-FileTimes $info
        foreach ($key in $times.Keys) { $entry[[string]$key] = $times[[string]$key] }
        $entry['size'] = [long]$info.Length
    } catch [System.UnauthorizedAccessException] {
        $entry['reason'] = 'permission_denied'
        return $entry
    } catch {
        $entry['reason'] = 'unreadable'
        return $entry
    }

    if ([long]$entry['size'] -gt $MaxFileSize) {
        $entry['reason'] = 'too_large'
        return $entry
    }

    if ($DryRun) {
        # No read at all: hashing would touch access times and cost the time a dry run
        # exists to save. The entry says what would have happened.
        $entry['reason'] = 'dry_run'
        return $entry
    }

    $secret = ($Withhold -and -not $IncludeSecrets)

    try {
        $entry['sha256'] = Get-Sha256OfFile $readPath
    } catch [System.UnauthorizedAccessException] {
        $entry['reason'] = 'permission_denied'
        return $entry
    } catch {
        $entry['reason'] = 'unreadable'
        return $entry
    }

    try {
        $after = [System.IO.FileInfo]::new($readPath)
        if ($after.Length -ne [long]$entry['size'] -or
            (Get-UtcString $after.LastWriteTimeUtc) -cne [string]$entry['mtime_utc']) {
            $entry['changed_while_reading'] = $true
        }
    } catch {
        # A file that vanished between the hash and the re-stat is still described by the
        # entry we already built, which is the point of building it first.
    }

    if ($secret) {
        # Presence, identity and timestamps are recorded; the bytes are not copied. See
        # SECURITY.md: the tool locates credential material, and copying it by default
        # would make every bundle a liability of its own.
        $entry['reason'] = 'secret_policy'
        return $entry
    }

    if (-not $FilesDir) {
        $entry['collected'] = $true
        return $entry
    }

    $relative = ConvertTo-BundlePath -Original $Original -Used $Used -TargetOs $TargetOs
    $destination = (Join-BundlePath $FilesDir $relative)
    try {
        $parent = [System.IO.Path]::GetDirectoryName($destination)
        if ($parent) { [void][System.IO.Directory]::CreateDirectory($parent) }
        [System.IO.File]::Copy($readPath, $destination, $true)
        # Carry the original timestamps onto the copy, so a bundle extracted on another
        # machine still shows when the evidence was last written.
        [System.IO.File]::SetLastWriteTimeUtc($destination, $info.LastWriteTimeUtc)
        [System.IO.File]::SetLastAccessTimeUtc($destination, $info.LastAccessTimeUtc)
    } catch [System.UnauthorizedAccessException] {
        $entry['reason'] = 'permission_denied'
        return $entry
    } catch {
        $entry['reason'] = 'unreadable'
        return $entry
    }

    $entry['bundle_path'] = 'files/' + $relative
    $entry['collected'] = $true
    return $entry
}


# ===================================================================== the collection

function Sort-Ordinal {
    <#
    .SYNOPSIS
        Sort strings by code point, the way Python's sorted() does.
    .DESCRIPTION
        Sort-Object -CaseSensitive is culture-aware and orders "mixed.md" before "Mixed.md";
        an ordinal sort orders them the other way, which is what Python does. The order
        decides which of two files whose names differ only in case keeps the plain bundle
        path and which gets the collision suffix, so the two collectors disagreeing here
        makes their manifests differ over a pair of files that are both collected.
    #>
    param([System.Collections.Generic.List[string]] $Items)
    $array = [string[]]$Items.ToArray()
    [System.Array]::Sort($array, [System.StringComparer]::Ordinal)
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($item in $array) { $out.Add($item) }
    return ,$out
}

function Sort-DictionaryList {
    <#
    .SYNOPSIS
        Sort a list of ordered dictionaries by one or more string fields, ordinally.
    .DESCRIPTION
        Not Sort-Object, and the reason is a real failure rather than a preference.
        Sort-Object hands each item back wrapped in a PSObject, and an OrderedDictionary
        exposes both an [object] and an [int] indexer, so $entry['collected'] on a wrapped
        dictionary cannot resolve the overload: PowerShell picks the [int] one and the run
        dies with "Cannot convert value collected to type System.Int32". Sorting the keys
        and keeping the dictionaries untouched avoids the wrapper entirely.

        Ordinal comparison, because Python sorts by code point and a culture-aware sort
        would order two manifests differently on two machines for the same tree.
    #>
    param(
        [System.Collections.Generic.List[object]] $Items,
        [string[]] $Fields
    )
    $keys = [System.Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt $Items.Count; $index++) {
        $dictionary = [System.Collections.IDictionary]$Items[$index]
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($field in $Fields) {
            $value = ''
            if ($dictionary.Contains($field)) { $value = [string]$dictionary[$field] }
            $parts.Add($value)
        }
        # The index is the last component, so the sort is stable and two records with equal
        # fields keep the order they were collected in.
        $parts.Add($index.ToString('D8', [System.Globalization.CultureInfo]::InvariantCulture))
        # [char]0x0001 rather than the `u{0001} escape, which is PowerShell 6 syntax and
        # a parse error on 5.1. A parse error means this file does not load at all on the
        # platform it exists for.
        $keys.Add([string]::Join([string][char]0x0001, $parts))
    }
    $sortedKeys = [string[]]$keys.ToArray()
    [System.Array]::Sort($sortedKeys, [System.StringComparer]::Ordinal)

    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($key in $sortedKeys) {
        $pieces = $key.Split([char]0x0001)
        $index = [int]::Parse($pieces[$pieces.Length - 1], [System.Globalization.CultureInfo]::InvariantCulture)
        [void]$out.Add($Items[$index])
    }
    return ,$out
}

function Invoke-Collection {
    <#
    .SYNOPSIS
        Collect everything the catalogue describes for this platform, and return the
        manifest as an ordered dictionary ready to serialize.
    #>
    param(
        [string] $Out,
        [string] $Root,
        [string] $TargetOs,
        [string[]] $Agents,
        [string[]] $User,
        [bool] $AllUsers,
        [bool] $IncludeSecrets,
        [long] $MaxFileSize,
        [int] $MaxFilesPerArtifact,
        [bool] $DryRun,
        [string[]] $Argv
    )

    $started = [DateTime]::UtcNow

    $artifacts = [System.Collections.Generic.List[object]]::new()
    foreach ($agent in $script:EmbeddedCatalogue.agents) {
        if ($Agents -and $Agents.Count -gt 0 -and -not ($Agents -ccontains [string]$agent.agent)) { continue }
        foreach ($artifact in $agent.artifacts) {
            if ($artifact.os -ccontains $TargetOs) { [void]$artifacts.Add($artifact) }
        }
    }
    # Most volatile first, then by id so two runs queue the same work in the same order.
    $ordered = $artifacts | Sort-Object -Property `
        @{ Expression = { $script:PriorityOrder.IndexOf([string]$_.collect_priority) } }, `
        @{ Expression = { [string]$_.id }; Descending = $false }

    $users = Get-ProfilesToScan -Root $Root -AllUsers $AllUsers -Named $User

    $filesDir = $null
    if (-not $DryRun) {
        $filesDir = (Join-BundlePath $Out 'files')
        [void][System.IO.Directory]::CreateDirectory($filesDir)
    }

    $entries = [System.Collections.Generic.List[object]]::new()
    $errors = [System.Collections.Generic.List[object]]::new()
    $projectRoots = [System.Collections.Generic.List[object]]::new()
    $projectRootPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    # Ordinal, not [ordered]@{}. A PowerShell ordered dictionary compares keys
    # case-insensitively, so Mixed.md and mixed.md were one entry and one of two real files
    # was silently dropped: exactly the case collision the bundle path mapping exists to
    # preserve.
    $used = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
    # Paths already decided, so a second user's glob cannot re-collect a shared file.
    $seenPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

    # Typed, not just named. A variable whose static type is object cannot be indexed by
    # key on an OrderedDictionary: PowerShell resolves the [int] indexer and assigning
    # $user['collected'] fails with "Cannot convert value collected to type System.Int32".
    # Items coming out of a List[object] are object-typed, so every dictionary taken from
    # one is declared before it is used.
    foreach ($userItem in $users) {
        [System.Collections.IDictionary] $scanned = $userItem
        $profileHome = [string]$scanned['home']
        if (-not [System.IO.Directory]::Exists($profileHome)) {
            $scanned['collected'] = $false
            $scanned['reason'] = 'unreadable'
            continue
        }
        $scanned['collected'] = $true

        # Named $discoveredRoot, not $root. PowerShell variable names are case-insensitive,
        # so a loop variable called $root IS the $Root parameter: it replaced the mounted
        # root path with a dictionary, every later pattern expanded against nothing, and the
        # collection reported 0 hits and 917 unresolvable patterns on a tree full of
        # evidence. Nothing warned, because assigning to a parameter is legal.
        $roots = Get-ProjectRoots -ProfileHome $profileHome
        foreach ($rootItem in $roots) {
            [System.Collections.IDictionary] $discoveredRoot = $rootItem
            if ($projectRootPaths.Add([string]$discoveredRoot['path'])) {
                [void]$projectRoots.Add($discoveredRoot)
            }
        }

        # Two passes, not one. A single file is often claimed by more than one artifact: a
        # broad directory glob and a specific entry for one file inside it. Deciding as
        # each match is found lets iteration order decide whether credential bytes get
        # copied, which was a real protective failure and not a theoretical one. Resolving
        # every claim on a path before deciding makes "secret wins" a property of the file.
        # See ADR 0014.
        $matches = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
        foreach ($artifact in $ordered) {
            $anchors = [System.Collections.Generic.List[string]]::new()
            if (@('project', 'repo_root', 'plugin') -ccontains [string]$artifact.root) {
                foreach ($anchorItem in $projectRoots) {
                    $anchors.Add([string]([System.Collections.IDictionary]$anchorItem)['path'])
                }
                if ($anchors.Count -eq 0) { continue }
            } else {
                $anchors.Add($profileHome)
            }
            foreach ($anchor in $anchors) {
                foreach ($pattern in $artifact.paths) {
                    $concrete = [string]$pattern
                    if (@('project', 'repo_root', 'plugin') -ccontains [string]$artifact.root) {
                        $concrete = [regex]::Replace($concrete, '^<[^>]+>', $anchor.TrimEnd('/'))
                    }
                    foreach ($expanded in (Expand-CataloguePath -Pattern $concrete -ProfileHome $profileHome -TargetOs $TargetOs -Root $Root)) {
                        foreach ($match in (Get-GlobMatches $expanded)) {
                            $targets = [System.Collections.Generic.List[string]]::new()
                            if ([System.IO.Directory]::Exists($match) -and -not (Test-IsSymlink $match)) {
                                $walked = Get-RegularFilesUnder -Base $match -Limit $MaxFilesPerArtifact
                                foreach ($file in $walked['files']) { $targets.Add([string]$file) }
                                if ([bool]$walked['truncated']) {
                                    $problem = [ordered]@{}
                                    $problem['detail'] = ('stopped after {0} files; raise -MaxFilesPerArtifact' -f $MaxFilesPerArtifact)
                                    $problem['error'] = 'too_many_files'
                                    $problem['path'] = $match
                                    [void]$errors.Add($problem)
                                }
                            } else {
                                $targets.Add($match)
                            }
                            foreach ($target in $targets) {
                                if (-not $matches.Contains($target)) {
                                    $matches[$target] = [System.Collections.Generic.List[object]]::new()
                                }
                                [void]([System.Collections.Generic.List[object]]$matches[$target]).Add($artifact)
                            }
                        }
                    }
                }
            }
        }

        $targetsSorted = [System.Collections.Generic.List[string]]::new()
        foreach ($key in $matches.Keys) { $targetsSorted.Add([string]$key) }
        foreach ($target in (Sort-Ordinal $targetsSorted)) {
            if (-not $seenPaths.Add([string]$target)) { continue }
            $claimants = [System.Collections.Generic.List[object]]$matches[[string]$target]

            # Attributed to the most specific claim, the artifact with the fewest path
            # patterns, so a file is reported under the entry that names it rather than
            # under a directory glob that happened to include it.
            $primary = ($claimants | Sort-Object -Property `
                @{ Expression = { @($_.paths).Count } }, `
                @{ Expression = { [string]$_.id } })[0]

            $withhold = $false
            $claimantIds = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($claimant in $claimants) {
                if ([string]$claimant.sensitivity -ceq 'secret') { $withhold = $true }
                [void]$claimantIds.Add([string]$claimant.id)
            }

            $entry = Copy-ArtifactFile -Artifact $primary -Original ([string]$target) `
                -ProfileHome $profileHome -UserName ([string]$scanned['name']) -FilesDir $filesDir `
                -Used $used -TargetOs $TargetOs -Withhold $withhold `
                -IncludeSecrets $IncludeSecrets -MaxFileSize $MaxFileSize -DryRun $DryRun

            # One artifact can claim the same path through two of its own patterns, which
            # is not a second claim and must not produce a one-element list.
            if ($claimantIds.Count -gt 1) {
                $ids = [System.Collections.Generic.List[object]]::new()
                foreach ($id in $claimantIds) { [void]$ids.Add($id) }
                $entry['artifact_ids'] = $ids
            }
            [void]$entries.Add($entry)

            if (@('permission_denied', 'unreadable') -ccontains [string]$entry['reason']) {
                $problem = [ordered]@{}
                $problem['detail'] = [string]$entry['artifact_id']
                $problem['error'] = [string]$entry['reason']
                $problem['path'] = [string]$target
                [void]$errors.Add($problem)
            }
        }
    }

    $sortedEntries = Sort-DictionaryList -Items $entries -Fields @('artifact_id', 'original_path')

    $collected = 0
    foreach ($entryItem in $sortedEntries) {
        [System.Collections.IDictionary] $entry = $entryItem
        if ([bool]$entry['collected']) { $collected += 1 }
    }

    $sortedErrors = Sort-DictionaryList -Items $errors -Fields @('path', 'error')

    $sortedRefusals = Sort-DictionaryList -Items $script:PatternRefusals -Fields @('pattern', 'reason')

    $sortedRoots = Sort-DictionaryList -Items $projectRoots -Fields @('path')

    $userList = [System.Collections.Generic.List[object]]::new()
    foreach ($userItem in $users) { [void]$userList.Add($userItem) }

    $agentsFilter = $null
    if ($Agents -and $Agents.Count -gt 0) {
        $agentsFilter = [System.Collections.Generic.List[object]]::new()
        foreach ($name in ($Agents | Sort-Object -CaseSensitive)) { [void]$agentsFilter.Add([string]$name) }
    }

    $argvList = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Argv) { [void]$argvList.Add([string]$item) }

    $offset = [DateTimeOffset]::Now.Offset
    $offsetText = ('{0}{1:00}:{2:00}' -f $(if ($offset.Ticks -lt 0) { '-' } else { '+' }),
        [Math]::Abs($offset.Hours), [Math]::Abs($offset.Minutes))

    $counts = [ordered]@{}
    $counts['collected'] = $collected
    $counts['errors'] = $sortedErrors.Count
    $counts['hit'] = $sortedEntries.Count
    $counts['refused_patterns'] = $sortedRefusals.Count
    $counts['skipped'] = $sortedEntries.Count - $collected

    $collection = [ordered]@{}
    $collection['agents_filter'] = $agentsFilter
    $collection['architecture'] = (Get-Architecture)
    $collection['argv'] = $argvList
    $collection['collector_user'] = (Get-CollectorUser)
    $collection['elevated'] = (Test-Elevated)
    $collection['finished_utc'] = (Get-UtcString ([DateTime]::UtcNow))
    $collection['hostname'] = [System.Net.Dns]::GetHostName()
    $collection['include_secrets'] = [bool]$IncludeSecrets
    $collection['local_timezone'] = $offsetText
    $collection['local_timezone_name'] = [System.TimeZoneInfo]::Local.StandardName
    $collection['max_file_size'] = [long]$MaxFileSize
    $collection['os'] = $TargetOs
    $collection['os_version'] = [string][System.Environment]::OSVersion.Version
    $collection['root'] = $(if ($Root) { $Root } else { $null })
    $collection['started_utc'] = (Get-UtcString $started)
    $collection['uuid'] = [string]([Guid]::NewGuid())

    $tool = [ordered]@{}
    $tool['catalogue_version'] = [string]$script:EmbeddedCatalogue.sha256
    $tool['name'] = $script:ToolName
    $tool['sha256'] = (Get-ToolSha256)
    $tool['version'] = $script:ToolVersion

    $manifest = [ordered]@{}
    $manifest['collection'] = $collection
    $manifest['counts'] = $counts
    $manifest['errors'] = $sortedErrors
    $manifest['files'] = $sortedEntries
    $manifest['format_version'] = $script:FormatVersion
    $manifest['project_roots'] = $sortedRoots
    # A pattern the collector declined to search is a hole in the coverage, so it is
    # reported next to the errors rather than left implicit in an absent file entry.
    $manifest['refused_patterns'] = $sortedRefusals
    $manifest['tool'] = $tool
    $manifest['users'] = $userList
    return $manifest
}

function Get-Architecture {
    <#
    .SYNOPSIS
        The machine architecture, without depending on a recent .NET.
    .DESCRIPTION
        RuntimeInformation.OSArchitecture arrived in .NET Framework 4.7.1, and an endpoint
        still on an older 4.x is exactly the kind of machine this collector is pushed to.
        PROCESSOR_ARCHITECTURE has been there since forever and is what the manifest needs:
        context for reading the rest, not a precise runtime fact.
    #>
    try {
        return [string][System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    } catch {
        $value = [System.Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITEW6432')
        if (-not $value) { $value = [System.Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE') }
        if (-not $value) { $value = 'unknown' }
        return [string]$value
    }
}

function Resolve-RelativePath {
    <#
    .SYNOPSIS
        Make a path absolute against PowerShell's location, not .NET's.
    .DESCRIPTION
        The two differ whenever the session has changed directory, because Set-Location does
        not touch [System.Environment]::CurrentDirectory. Every write in this file uses
        System.IO, so without this a relative -Out lands somewhere the operator did not
        choose, and on a live-response console that is somebody else's directory.
    #>
    param([string] $Path)
    if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }
    $location = (Get-Location).ProviderPath
    return (Join-BundlePath ([string]$location).Replace('\', '/') $Path)
}

function Test-Elevated {
    <#
    .SYNOPSIS
        Is this process running with administrative rights.
    .DESCRIPTION
        Recorded in the manifest because it decides what the collection could see: a
        non-elevated run cannot read another user's profile, and an empty result from one
        is not the same finding as an empty result from an elevated run.
    #>
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        # Not Windows, or an identity the platform will not describe. Reported as false
        # rather than null, because the manifest field means "known to be elevated".
        return $false
    }
}

function Get-ToolSha256 {
    <#
    .SYNOPSIS
        Hash this file as it ran, so a bundle can be tied to the exact collector build.
    #>
    try {
        return (Get-Sha256OfFile $PSCommandPath)
    } catch {
        return ''
    }
}


# ==================================================================== bundle writing

function New-CustodyRecord {
    <#
    .SYNOPSIS
        Build one hash-chained custody record.
    .DESCRIPTION
        Each record commits to the previous one, so removing or editing a single record
        breaks the chain at a detectable point. Tamper-evident, not tamper-proof: anyone
        who can write the file can rewrite the whole chain. See docs/BUNDLE_FORMAT.md.
    #>
    param([int] $Seq, [string] $EventName, [string] $ManifestSha, [string] $PrevSha)
    $record = [ordered]@{}
    $record['actor'] = (Get-CollectorUser)
    $record['event'] = $EventName
    $record['host'] = [System.Net.Dns]::GetHostName()
    $record['manifest_sha256'] = $ManifestSha
    $record['prev_sha256'] = $(if ($PrevSha) { $PrevSha } else { $null })
    $record['seq'] = $Seq
    $record['time_utc'] = (Get-UtcString ([DateTime]::UtcNow))
    $record['tool'] = ('{0} {1}' -f $script:ToolName, $script:ToolVersion)
    # The chain hash covers the record without its own hash field, serialized with the
    # compact separators collect.py uses, so the two implementations chain identically.
    $record['sha256'] = (Get-Sha256OfString (ConvertTo-CompactJson $record))
    return $record
}

function ConvertTo-CompactJson {
    <#
    .SYNOPSIS
        Serialize with no whitespace, matching Python's separators=(',', ':').
    .DESCRIPTION
        Used only for the custody chain hash, where the bytes being hashed have to be
        identical in both collectors or the chains cannot be compared. The pretty form is
        what gets written to disk.
    #>
    param([Parameter(Mandatory = $true)] [AllowNull()] $Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [string]) { return (ConvertTo-JsonString $Value) }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte]) {
        return $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($entry in (@($Value.GetEnumerator()) | Sort-Object -Property Key -CaseSensitive)) {
            $parts.Add((ConvertTo-JsonString ([string]$entry.Key)) + ':' + [string](ConvertTo-CompactJson $entry.Value))
        }
        return '{' + [string]::Join(',', $parts) + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($item in $Value) { $parts.Add([string](ConvertTo-CompactJson $item)) }
        return '[' + [string]::Join(',', $parts) + ']'
    }
    throw "ConvertTo-CompactJson: unsupported type $($Value.GetType().FullName)"
}

function Write-Bundle {
    <#
    .SYNOPSIS
        Write manifest.json and the first custody record, and return the manifest hash.
    #>
    param([string] $Out, [System.Collections.IDictionary] $Manifest)
    $text = ConvertTo-CanonicalJson -Value $Manifest -Indent 0
    $sha = Get-Sha256OfString $text
    Write-Utf8NoBom -Path (Join-BundlePath $Out 'manifest.json') -Text $text
    $record = New-CustodyRecord -Seq 0 -EventName 'collected' -ManifestSha $sha -PrevSha $null
    # One record per line, because the file is JSONL and a pretty-printed record would
    # make it unparseable line by line, which is how the verifier reads the chain.
    Write-Utf8NoBom -Path (Join-BundlePath $Out 'chain_of_custody.jsonl') `
        -Text ((ConvertTo-LineJson $record) + "`n")
    return $sha
}

function ConvertTo-LineJson {
    <#
    .SYNOPSIS
        Serialize onto one line, matching Python's json.dumps(sort_keys=True) defaults.
    .DESCRIPTION
        A third form, and each of the three has one caller. The pretty form is manifest
        .json, the compact form is what the custody hash covers, and this one is what a
        line of chain_of_custody.jsonl looks like. Python's default separators are ', '
        and ': ', with the spaces, so they are here too: the file is compared between the
        two collectors byte for byte.
    #>
    param([Parameter(Mandatory = $true)] [AllowNull()] $Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [string]) { return (ConvertTo-JsonString $Value) }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte]) {
        return $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($entry in (@($Value.GetEnumerator()) | Sort-Object -Property Key -CaseSensitive)) {
            $parts.Add((ConvertTo-JsonString ([string]$entry.Key)) + ': ' + [string](ConvertTo-LineJson $entry.Value))
        }
        return '{' + [string]::Join(', ', $parts) + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($item in $Value) { $parts.Add([string](ConvertTo-LineJson $item)) }
        return '[' + [string]::Join(', ', $parts) + ']'
    }
    throw "ConvertTo-LineJson: unsupported type $($Value.GetType().FullName)"
}

function Write-BundleZip {
    <#
    .SYNOPSIS
        Pack the bundle in manifest order and write a .sha256 sidecar beside it.
    .DESCRIPTION
        Entries are added in manifest order rather than in directory order so that two
        collections of an unchanged tree produce the same archive. The two metadata files
        get a fixed 1980 timestamp, which is the earliest the zip format can store and
        avoids the collection time making otherwise identical archives differ.
    #>
    param([string] $Out, [System.Collections.IDictionary] $Manifest)

    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    $archive = $Out.TrimEnd('/', '\') + '.zip'
    $base = [System.IO.Path]::GetFileName($Out.TrimEnd('/', '\'))
    $metadataTime = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)

    if ([System.IO.File]::Exists($archive)) { [System.IO.File]::Delete($archive) }
    $stream = [System.IO.File]::Open($archive, [System.IO.FileMode]::CreateNew)
    $zip = $null
    try {
        $zip = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Create)

        foreach ($name in @('manifest.json', 'chain_of_custody.jsonl')) {
            $source = Join-BundlePath $Out $name
            $item = $zip.CreateEntry($base + '/' + $name, [System.IO.Compression.CompressionLevel]::Optimal)
            $item.LastWriteTime = $metadataTime
            $writer = $item.Open()
            try {
                $bytes = [System.IO.File]::ReadAllBytes($source)
                $writer.Write($bytes, 0, $bytes.Length)
            } finally {
                $writer.Dispose()
            }
        }

        foreach ($entryItem in $Manifest['files']) {
            [System.Collections.IDictionary] $entry = $entryItem
            $bundlePath = [string]$entry['bundle_path']
            if (-not $bundlePath) { continue }
            $source = Join-BundlePath $Out $bundlePath
            if (-not [System.IO.File]::Exists($source)) { continue }
            $item = $zip.CreateEntry($base + '/' + $bundlePath, [System.IO.Compression.CompressionLevel]::Optimal)
            $item.LastWriteTime = [DateTimeOffset]::new([System.IO.File]::GetLastWriteTime($source))
            $writer = $item.Open()
            try {
                $bytes = [System.IO.File]::ReadAllBytes($source)
                $writer.Write($bytes, 0, $bytes.Length)
            } finally {
                $writer.Dispose()
            }
        }
    } finally {
        if ($null -ne $zip) { $zip.Dispose() }
        $stream.Dispose()
    }

    $digest = Get-Sha256OfFile $archive
    Write-Utf8NoBom -Path ($archive + '.sha256') `
        -Text ('{0}  {1}{2}' -f $digest, [System.IO.Path]::GetFileName($archive), "`n")
    return $archive
}


# ========================================================================== self test

function Invoke-SelfTest {
    <#
    .SYNOPSIS
        Serialize a fixed set of structures and print them, for comparison with Python.
    .DESCRIPTION
        The parity between this file's serializer and Python's json.dumps is part of the
        bundle format, so the check belongs in the repository rather than in somebody's
        scratch directory. tests/conformance runs this and compares each block against
        json.dumps(sort_keys=True, indent=2, ensure_ascii=False).

        The cases are the ones that have actually gone wrong: an empty array and a
        one-element array, because PowerShell unwraps those across a function boundary; a
        string with a backslash, because catalogue paths are full of them; non-ASCII,
        because ensure_ascii=False must be matched rather than escaped; and control
        characters, because Python uses short escapes for some and \uXXXX for the rest.
    #>
    $cases = [ordered]@{}

    $mixed = [ordered]@{}
    $mixed['b'] = 1
    $mixed['a'] = 'two'
    $mixed['c'] = $true
    $mixed['d'] = $null
    $cases['dict_mixed'] = $mixed

    $cases['empty_dict'] = [ordered]@{}
    $cases['empty_list'] = [System.Collections.Generic.List[object]]::new()

    $one = [System.Collections.Generic.List[object]]::new()
    [void]$one.Add('only')
    $cases['one_element_list'] = $one

    $innerNumbers = [System.Collections.Generic.List[object]]::new()
    [void]$innerNumbers.Add(1)
    [void]$innerNumbers.Add(2)
    $innerStrings = [System.Collections.Generic.List[object]]::new()
    [void]$innerStrings.Add('x')
    $innerDict = [ordered]@{}
    $innerDict['k'] = $innerStrings
    $nested = [System.Collections.Generic.List[object]]::new()
    [void]$nested.Add($innerNumbers)
    [void]$nested.Add($innerDict)
    $cases['nested'] = $nested

    $cases['unicode'] = 'Grüezi ünd ãçcents 日本語 emoji'
    $cases['control'] = "tab`there`nnewline`r`bback`fform"
    $cases['quotes'] = 'he said "hi" and C:\path\to'

    $numbers = [System.Collections.Generic.List[object]]::new()
    foreach ($n in @(0, 1, -1, 268435456)) { [void]$numbers.Add([int]$n) }
    [void]$numbers.Add([long]9007199254740991)
    $cases['numbers'] = $numbers

    $bools = [System.Collections.Generic.List[object]]::new()
    [void]$bools.Add($true)
    [void]$bools.Add($false)
    $cases['bools'] = $bools

    $nulls = [System.Collections.Generic.List[object]]::new()
    [void]$nulls.Add($null)
    [void]$nulls.Add('x')
    [void]$nulls.Add($null)
    $cases['nulls_in_list'] = $nulls

    # Written to the console rather than to the output stream. A function that both emits
    # with Write-Output and returns a value returns all of it as one collection, and the
    # caller then passes that array to exit, which printed nothing and exited 0.
    foreach ($entry in $cases.GetEnumerator()) {
        [Console]::Out.Write('===' + [string]$entry.Key + "`n")
        [Console]::Out.Write([string](ConvertTo-CanonicalJson -Value $entry.Value -Indent 0) + "`n")
    }
    return $script:ExitOk
}


# =============================================================================== main

function Invoke-Main {
    if ($Version) {
        [Console]::Out.Write(('{0} {1}{2}' -f $script:ToolName, $script:ToolVersion, "`n"))
        return $script:ExitOk
    }

    if ($SelfTest) { return (Invoke-SelfTest) }

    if ($script:EmbeddedCatalogue.agents.Count -eq 0) {
        # A collector with no catalogue would report a clean host for every machine it ran
        # on, which is the worst possible failure, so it refuses to run at all.
        [Console]::Error.Write(("{0}: the embedded catalogue is empty or failed to parse. " -f $script:ToolName) +
            "Rebuild with scripts/build_collectors.py.`n")
        return $script:ExitUsage
    }

    $targetOs = $TargetOs
    if (-not $targetOs) {
        $targetOs = 'windows'
        if ([System.Environment]::OSVersion.Platform -ceq 'Unix') {
            # Running this file on a POSIX host happens in the differential test and
            # nowhere else, but guessing 'windows' there would search paths that cannot
            # exist and report a clean host.
            $targetOs = 'linux'
            if ([System.IO.Directory]::Exists('/System/Library')) { $targetOs = 'macos' }
        }
    }

    if (-not $DryRun) {
        if (-not $Out) {
            [Console]::Error.Write(("{0}: -Out is required unless -DryRun is given.`n" -f $script:ToolName))
            return $script:ExitUsage
        }
        if ([System.IO.Directory]::Exists($Out)) {
            $existing = @([System.IO.Directory]::GetFileSystemEntries($Out))
            if ($existing.Count -gt 0) {
                # Never write into a directory that already holds something. Merging two
                # collections into one bundle would produce a manifest that describes
                # neither, and the hashes would still verify.
                [Console]::Error.Write(("{0}: {1} is not empty. Give an empty or new " -f $script:ToolName, $Out) +
                    "directory so one bundle is one collection.`n")
                return $script:ExitUsage
            }
        } else {
            [void][System.IO.Directory]::CreateDirectory($Out)
        }
    }

    # Resolved to absolute before anything is written. PowerShell's current location and
    # .NET's current directory are two different things, and every write in this file goes
    # through System.IO, so a relative -Out would put the manifest in one place and the
    # collected files in another.
    $normalizedOut = ''
    if ($Out) {
        $normalizedOut = ([string]([System.IO.Path]::GetFullPath((Resolve-RelativePath $Out)))).Replace('\', '/').TrimEnd('/')
    }
    $normalizedRoot = ''
    if ($Root) {
        $normalizedRoot = ([string]([System.IO.Path]::GetFullPath((Resolve-RelativePath $Root)))).Replace('\', '/').TrimEnd('/')
    }

    $argv = [System.Collections.Generic.List[string]]::new()
    $argv.Add($script:ToolName)
    foreach ($arg in $script:RawArguments) { $argv.Add([string]$arg) }

    $manifest = Invoke-Collection -Out $normalizedOut -Root $normalizedRoot -TargetOs $targetOs `
        -Agents $Agents -User $User -AllUsers ([bool]$AllUsers) `
        -IncludeSecrets ([bool]$IncludeSecrets) -MaxFileSize $MaxFileSize `
        -MaxFilesPerArtifact $MaxFilesPerArtifact -DryRun ([bool]$DryRun) -Argv $argv

    $archive = $null
    if (-not $DryRun) {
        [void](Write-Bundle -Out $normalizedOut -Manifest $manifest)
        if ($Zip) { $archive = Write-BundleZip -Out $normalizedOut -Manifest $manifest }
    }

    $counts = $manifest['counts']

    # The same summary collect.py prints, field for field, because a fleet sweep that
    # pipes -Json into something else must not have to know which collector ran.
    $priorities = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
    foreach ($agent in $script:EmbeddedCatalogue.agents) {
        foreach ($artifact in $agent.artifacts) {
            $priorities[[string]$artifact.id] = [string]$artifact.collect_priority
        }
    }
    $byPriority = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
    foreach ($entryItem in $manifest['files']) {
        [System.Collections.IDictionary] $entry = $entryItem
        $key = 'normal'
        if ($priorities.Contains([string]$entry['artifact_id'])) {
            $key = [string]$priorities[[string]$entry['artifact_id']]
        }
        if (-not $byPriority.Contains($key)) {
            $bucket = [ordered]@{}
            $bucket['collected'] = 0
            $bucket['hit'] = 0
            $byPriority[$key] = $bucket
        }
        [System.Collections.IDictionary] $bucket = $byPriority[$key]
        $bucket['hit'] = [int]$bucket['hit'] + 1
        if ([bool]$entry['collected']) { $bucket['collected'] = [int]$bucket['collected'] + 1 }
    }

    $userNames = [System.Collections.Generic.List[object]]::new()
    foreach ($entryItem in $manifest['users']) {
        [void]$userNames.Add([string]([System.Collections.IDictionary]$entryItem)['name'])
    }
    $rootPaths = [System.Collections.Generic.List[object]]::new()
    foreach ($entryItem in $manifest['project_roots']) {
        [void]$rootPaths.Add([string]([System.Collections.IDictionary]$entryItem)['path'])
    }

    if ($Json) {
        $summary = [ordered]@{}
        $summary['bundle'] = $(if ($DryRun) { $null } else { $normalizedOut })
        $summary['by_priority'] = $byPriority
        $summary['counts'] = $counts
        $summary['dry_run'] = [bool]$DryRun
        $summary['project_roots'] = $rootPaths
        $summary['users'] = $userNames
        [Console]::Out.Write((ConvertTo-CanonicalJson -Value $summary -Indent 0) + "`n")
    } else {
        [Console]::Error.Write(('{0}: {1} hit, {2} collected, {3} skipped, {4} error(s){5}' -f
            $script:ToolName, $counts['hit'], $counts['collected'], $counts['skipped'],
            $counts['errors'], "`n"))
        # Said on the terminal, not only in the manifest. An analyst who reads the summary
        # line and nothing else would otherwise take a clean run as full coverage.
        foreach ($priority in $script:PriorityOrder) {
            if (-not $byPriority.Contains($priority)) { continue }
            [System.Collections.IDictionary] $bucket = $byPriority[$priority]
            [Console]::Error.Write(('  {0,-10} {1}/{2}{3}' -f $priority,
                $bucket['collected'], $bucket['hit'], "`n"))
        }
        if ([int]$counts['refused_patterns'] -gt 0) {
            [Console]::Error.Write(('  {0} pattern(s) not searched, see refused_patterns in the manifest{1}' -f
                $counts['refused_patterns'], "`n"))
        }
        if (-not $DryRun) {
            [Console]::Error.Write(('  bundle: {0}{1}' -f $normalizedOut, "`n"))
        }
    }

    if ([int]$counts['hit'] -eq 0) {
        # Distinct from failure on purpose: a host with no agent artifacts is a valid and
        # useful result, and a fleet sweep that cannot tell the two apart draws a wrong
        # picture of where agents are in use.
        return $script:ExitNothingFound
    }
    if ([int]$counts['errors'] -gt 0) { return $script:ExitErrors }
    return $script:ExitOk
}

# Dot-sourcing this file defines its functions without running a collection, which is what
# the differential test and the parity check do. $PSCommandPath is set either way, so the
# guard is on the invocation name instead.
if ($MyInvocation.InvocationName -cne '.' -and -not $script:Sourced) {
    exit (Invoke-Main)
}
