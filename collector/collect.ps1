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
      * A script file with no byte order mark is read as the machine's ANSI code page, not
        as UTF-8, so a non-ASCII character in this file would be parsed as two. This file
        therefore contains no byte above 127 at all, and a test enforces that.
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
            "agent": "amazonq",
            "artifacts": [
                {
                    "category": "permissions",
                    "collect_priority": "first",
                    "id": "amazonq.cli_agents",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.aws\\amazonq\\cli-agents\\*.json",
                        "<project>/.amazonq/cli-agents/*.json",
                        "~/.aws/amazonq/cli-agents/*.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "file_snapshot",
                    "collect_priority": "durable",
                    "id": "amazonq.cli_checkpoints",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.aws\\amazonq\\cli-checkouts\\<conversation-id>\\**",
                        "~/.aws/amazonq/cli-checkouts/<conversation-id>/**"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "live_only",
                    "id": "amazonq.cli_logs",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$TMPDIR/qlog/chat.log",
                        "$TMPDIR/qlog/mcp.log",
                        "$TMPDIR/qlog/qchat.log",
                        "$TMPDIR/qlog/translate.log",
                        "$XDG_RUNTIME_DIR/qlog/*.log",
                        "%TEMP%\\amazon-q\\logs\\*.log",
                        "%TEMP%\\qlog\\*.log",
                        "/tmp/qlog/*.log"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "mcp_config",
                    "collect_priority": "first",
                    "id": "amazonq.cli_mcp_config",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.aws\\amazonq\\mcp.json",
                        "<project>/.amazonq/mcp.json",
                        "~/.aws/amazonq/mcp.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "prompt_history",
                    "collect_priority": "first",
                    "id": "amazonq.cli_prompt_history",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.aws\\amazonq\\.cli_bash_history",
                        "~/.aws/amazonq/.cli_bash_history"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "amazonq.cli_settings",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$Q_CLI_DATA_DIR/settings.json",
                        "$XDG_DATA_HOME/amazon-q/settings.json",
                        "%LOCALAPPDATA%\\amazon-q\\settings.json",
                        "~/.local/share/amazon-q/settings.json",
                        "~/Library/Application Support/amazon-q/settings.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "amazonq.cli_state_database",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$Q_CLI_DATA_DIR/data.sqlite3",
                        "$XDG_DATA_HOME/amazon-q/data.sqlite3",
                        "%LOCALAPPDATA%\\amazon-q\\data.sqlite3",
                        "~/.local/share/amazon-q/data.sqlite3",
                        "~/Library/Application Support/amazon-q/data.sqlite3"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "first",
                    "id": "amazonq.cli_subagent_executions",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.amazonq/.subagents/**"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "amazonq.cli_todo_lists",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.amazonq/cli-todo-lists/*.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "amazonq.cli_user_rules",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.aws\\amazonq\\rules\\*",
                        "~/.aws/amazonq/rules/*"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "mcp_config",
                    "collect_priority": "first",
                    "id": "amazonq.ide_agent_config",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.aws\\amazonq\\default.json",
                        "<project>/.amazonq/default.json",
                        "~/.aws/amazonq/agents/default.json",
                        "~/.aws/amazonq/default.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "normal",
                    "id": "amazonq.ide_chat_export",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/q-dev-chat-*.html",
                        "<project>/q-dev-chat-*.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "amazonq.ide_chat_history",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.aws\\amazonq\\history\\*.json",
                        "~/.aws/amazonq/history/*.json",
                        "~/.aws/amazonq/history/chat-history-<hash>.json",
                        "~/.aws/amazonq/history/chat-history-no-workspace.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "amazonq.ide_extension_install",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.vscode\\extensions\\amazonwebservices.amazon-q-vscode-*\\**",
                        "~/.vscode/extensions/amazonwebservices.amazon-q-vscode-*/**",
                        "~/.vscode/extensions/amazonwebservices.aws-toolkit-vscode-*/**",
                        "~/.vscode/extensions/extensions.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "cache",
                    "collect_priority": "durable",
                    "id": "amazonq.knowledge_bases",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.aws\\amazonq\\knowledge_bases\\**",
                        "~/.aws/amazonq/knowledge_bases/*/*/bm25_data.json",
                        "~/.aws/amazonq/knowledge_bases/*/*/data.json",
                        "~/.aws/amazonq/knowledge_bases/*/contexts.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "durable",
                    "id": "amazonq.legacy_profiles_and_context",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.aws\\amazonq\\global_context.json",
                        "%USERPROFILE%\\.aws\\amazonq\\profiles\\**",
                        "~/.aws/amazonq/global_context.json",
                        "~/.aws/amazonq/profiles/**"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "memory",
                    "collect_priority": "normal",
                    "id": "amazonq.memory_bank",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.amazonq/rules/memory-bank/guidelines.md",
                        "<project>/.amazonq/rules/memory-bank/product.md",
                        "<project>/.amazonq/rules/memory-bank/structure.md",
                        "<project>/.amazonq/rules/memory-bank/tech.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "amazonq.project_rules",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.amazonq/rules/**/*.md",
                        "<project>/AGENTS.md",
                        "<project>/AmazonQ.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "amazonq.prompt_library",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.aws\\amazonq\\prompts\\*.md",
                        "<project>/.amazonq/prompts/*",
                        "~/.aws/amazonq/prompts/*.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "first",
                    "id": "amazonq.sso_token_cache",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.aws\\sso\\cache\\*.json",
                        "~/.aws/sso/cache/<hash>.json",
                        "~/.aws/sso/cache/aws-toolkit-vscode-client-id-*.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
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
                        "$XDG_CONFIG_HOME/amp/settings.jsonc",
                        "/Library/Application Support/ampcode/managed-settings.json",
                        "/etc/ampcode/managed-settings.json",
                        "%PROGRAMDATA%\\ampcode\\managed-settings.json",
                        "%USERPROFILE%\\.config\\amp\\settings.json",
                        "%USERPROFILE%\\.config\\amp\\settings.jsonc",
                        "<project>/.amp/settings.json",
                        "<project>/.amp/settings.jsonc",
                        "~/.config/amp/settings.json",
                        "~/.config/amp/settings.jsonc"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "amp.skills",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/.agents/skills/",
                        "<project>/.claude/skills/",
                        "~/.agents/skills/",
                        "~/.claude/plugins/cache/",
                        "~/.claude/skills/",
                        "~/.config/agents/skills/",
                        "~/.config/amp/skills/"
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
                        "$CLAUDE_CODE_DEBUG_LOGS_DIR",
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
                        "<project>/.claude/hooks/**/*",
                        "~/.claude/hooks/*",
                        "~/.claude/hooks/**/*"
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
            "agent": "claude_desktop",
            "artifacts": [
                {
                    "category": "log",
                    "collect_priority": "first",
                    "id": "claude_desktop.app_logs",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Claude\\logs\\main.log",
                        "%LOCALAPPDATA%\\Claude-3p\\logs\\main.log",
                        "%LOCALAPPDATA%\\Claude\\Logs\\main.log",
                        "%LOCALAPPDATA%\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\logs\\",
                        "%LOCALAPPDATA%\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\logs\\main.log",
                        "~/.config/Claude-3p/logs/main.log",
                        "~/.config/Claude/logs/main.log",
                        "~/Library/Logs/Claude-3p/main.log",
                        "~/Library/Logs/Claude/claude.ai-web.log",
                        "~/Library/Logs/Claude/cowork_vm_node.log",
                        "~/Library/Logs/Claude/main.log",
                        "~/Library/Logs/Claude/mcp-server-<name>.log",
                        "~/Library/Logs/Claude/mcp.log"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "claude_desktop.code_launch_config",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.claude/launch.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "claude_desktop.code_session_index",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Claude\\claude-code-sessions\\<uuid>\\<uuid>\\local_<session-id>.json",
                        "%LOCALAPPDATA%\\Claude-3p\\claude-code-sessions\\",
                        "%LOCALAPPDATA%\\Claude\\claude-code-sessions\\<uuid>\\<uuid>\\local_<session-id>.json",
                        "%LOCALAPPDATA%\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\claude-code-sessions\\<uuid>\\<uuid>\\local_<session-id>.json",
                        "~/Library/Application Support/Claude-3p/claude-code-sessions/",
                        "~/Library/Application Support/Claude/claude-code-sessions/<uuid>/<uuid>/local_<session-id>.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "claude_desktop.cowork_account_settings",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Claude\\local-agent-mode-sessions\\*\\*\\cowork_account_settings.json",
                        "%LOCALAPPDATA%\\Claude-3p\\local-agent-mode-sessions\\*\\*\\cowork_account_settings.json",
                        "%LOCALAPPDATA%\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\local-agent-mode-sessions\\*\\*\\cowork_account_settings.json",
                        "~/Library/Application Support/Claude-3p/local-agent-mode-sessions/*/*/cowork_account_settings.json",
                        "~/Library/Application Support/Claude/local-agent-mode-sessions/*/*/cowork_account_settings.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "live_only",
                    "id": "claude_desktop.cowork_audit_key",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Claude\\local-agent-mode-sessions\\<uuid>\\<uuid>\\<session-id>\\.audit-key",
                        "%LOCALAPPDATA%\\Claude-3p\\local-agent-mode-sessions\\<uuid>\\<uuid>\\<session-id>\\.audit-key",
                        "%LOCALAPPDATA%\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\local-agent-mode-sessions\\<uuid>\\<uuid>\\<session-id>\\.audit-key",
                        "~/Library/Application Support/Claude-3p/local-agent-mode-sessions/<uuid>/<uuid>/<session-id>/.audit-key",
                        "~/Library/Application Support/Claude/local-agent-mode-sessions/<uuid>/<uuid>/<session-id>/.audit-key"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "first",
                    "id": "claude_desktop.cowork_audit_log",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Claude\\local-agent-mode-sessions\\<uuid>\\<uuid>\\<session-id>\\audit.jsonl",
                        "%LOCALAPPDATA%\\Claude-3p\\local-agent-mode-sessions\\<uuid>\\<uuid>\\<session-id>\\audit.jsonl",
                        "%LOCALAPPDATA%\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\local-agent-mode-sessions\\<uuid>\\<uuid>\\<session-id>\\audit.jsonl",
                        "~/Library/Application Support/Claude-3p/local-agent-mode-sessions/<uuid>/<uuid>/<session-id>/audit.jsonl",
                        "~/Library/Application Support/Claude/local-agent-mode-sessions/<uuid>/<uuid>/<session-id>/audit.jsonl"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "memory",
                    "collect_priority": "first",
                    "id": "claude_desktop.cowork_memory",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Claude\\local-agent-mode-sessions\\*\\*\\memory\\memory\\*.md",
                        "%LOCALAPPDATA%\\Claude-3p\\local-agent-mode-sessions\\*\\*\\memory\\memory\\*.md",
                        "%LOCALAPPDATA%\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\local-agent-mode-sessions\\*\\*\\memory\\memory\\*.md",
                        "~/Library/Application Support/Claude-3p/local-agent-mode-sessions/*/*/memory/memory/*.md",
                        "~/Library/Application Support/Claude/local-agent-mode-sessions/*/*/memory/CLAUDE.md",
                        "~/Library/Application Support/Claude/local-agent-mode-sessions/*/*/memory/memory/*.md",
                        "~/Library/Application Support/Claude/local-agent-mode-sessions/*/*/spaces/<uuid>/memory/*.md"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "file_snapshot",
                    "collect_priority": "first",
                    "id": "claude_desktop.cowork_session_files",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Claude\\local-agent-mode-sessions\\<uuid>\\<uuid>\\local_<uuid>\\outputs\\",
                        "%APPDATA%\\Claude\\local-agent-mode-sessions\\<uuid>\\<uuid>\\local_<uuid>\\uploads\\",
                        "%LOCALAPPDATA%\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\local-agent-mode-sessions\\<uuid>\\<uuid>\\local_<uuid>\\outputs\\",
                        "%LOCALAPPDATA%\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\local-agent-mode-sessions\\<uuid>\\<uuid>\\local_<uuid>\\uploads\\",
                        "~/Library/Application Support/Claude-3p/local-agent-mode-sessions/<uuid>/<uuid>/local_<uuid>/outputs/",
                        "~/Library/Application Support/Claude/local-agent-mode-sessions/<uuid>/<uuid>/local_<uuid>/outputs/",
                        "~/Library/Application Support/Claude/local-agent-mode-sessions/<uuid>/<uuid>/local_<uuid>/uploads/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "claude_desktop.cowork_session_store",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Claude\\local-agent-mode-sessions\\<uuid>\\<uuid>\\local_<uuid>\\",
                        "%LOCALAPPDATA%\\Claude-3p\\local-agent-mode-sessions\\<uuid>\\<uuid>\\local_<uuid>\\",
                        "%LOCALAPPDATA%\\Claude\\local-agent-mode-sessions\\<uuid>\\<uuid>\\local_<uuid>\\",
                        "%LOCALAPPDATA%\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\local-agent-mode-sessions\\<uuid>\\<uuid>\\local_<uuid>\\",
                        "~/.config/Claude-3p/local-agent-mode-sessions/<uuid>/<uuid>/local_<uuid>/",
                        "~/.config/Claude/local-agent-mode-sessions/<uuid>/<uuid>/local_<uuid>/",
                        "~/Library/Application Support/Claude-3p/local-agent-mode-sessions/<uuid>/<uuid>/local_<uuid>/",
                        "~/Library/Application Support/Claude/local-agent-mode-sessions/<uuid>/<uuid>/local_<uuid>.json",
                        "~/Library/Application Support/Claude/local-agent-mode-sessions/<uuid>/<uuid>/local_<uuid>/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "file_snapshot",
                    "collect_priority": "durable",
                    "id": "claude_desktop.cowork_vm_bundle",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Claude\\vm_bundles\\claudevm.bundle\\",
                        "%LOCALAPPDATA%\\Claude-3p\\vm_bundles\\",
                        "%LOCALAPPDATA%\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\vm_bundles\\claudevm.bundle\\",
                        "%LOCALAPPDATA%\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\vm_bundles\\claudevm.bundle\\sessiondata.vhdx",
                        "~/Library/Application Support/Claude-3p/vm_bundles/",
                        "~/Library/Application Support/Claude/vm_bundles/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "first",
                    "id": "claude_desktop.coworkd_service_log",
                    "os": [
                        "macos",
                        "windows"
                    ],
                    "paths": [
                        "C:\\ProgramData\\Claude\\Logs\\coworkd\\user-<sid>.log",
                        "~/Library/Logs/Claude/coworkd.log"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "claude_desktop.device_identifier",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%LOCALAPPDATA%\\Claude-3p\\ant-did",
                        "~/.config/Claude-3p/ant-did",
                        "~/Library/Application Support/Claude-3p/ant-did"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "claude_desktop.embedded_claude_code",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Claude\\claude-code\\<version>\\claude.exe",
                        "%LOCALAPPDATA%\\Claude-3p\\claude-code\\<version>\\",
                        "%LOCALAPPDATA%\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\claude-code\\<version>\\claude.exe",
                        "~/Library/Application Support/Claude-3p/claude-code/<version>/claude.app/Contents/MacOS/claude",
                        "~/Library/Application Support/Claude/claude-code-vm/",
                        "~/Library/Application Support/Claude/claude-code/<version>/claude.app/Contents/MacOS/claude"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "claude_desktop.install_evidence_linux",
                    "os": [
                        "linux"
                    ],
                    "paths": [
                        "/etc/apt/sources.list.d/claude-desktop.list",
                        "/etc/default/claude-desktop",
                        "/usr/share/keyrings/claude-desktop-archive-keyring.asc",
                        "/var/lib/dpkg/info/claude-desktop.*"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "claude_desktop.install_evidence_macos",
                    "os": [
                        "macos"
                    ],
                    "paths": [
                        "/Applications/Claude.app",
                        "~/Applications/Claude.app"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "claude_desktop.install_evidence_windows",
                    "os": [
                        "windows"
                    ],
                    "paths": [
                        "%LOCALAPPDATA%\\Packages\\Claude_pzs8sxrjxfjjc\\",
                        "C:\\Program Files\\WindowsApps\\Claude_<version>_<arch>__pzs8sxrjxfjjc\\"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "claude_desktop.local_config_library",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%LOCALAPPDATA%\\Claude-3p\\configLibrary\\",
                        "~/.config/Claude-3p/configLibrary/",
                        "~/Library/Application Support/Claude-3p/configLibrary/<id>.json",
                        "~/Library/Application Support/Claude-3p/configLibrary/_meta.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "normal",
                    "id": "claude_desktop.managed_policy_linux",
                    "os": [
                        "linux"
                    ],
                    "paths": [
                        "/etc/claude-desktop/managed-settings.json"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "normal",
                    "id": "claude_desktop.managed_policy_macos",
                    "os": [
                        "macos"
                    ],
                    "paths": [
                        "/Library/Managed Preferences/<user>/com.anthropic.claudefordesktop.plist",
                        "/Library/Managed Preferences/com.anthropic.claudefordesktop.plist",
                        "~/Library/Preferences/com.anthropic.claudefordesktop.plist"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "normal",
                    "id": "claude_desktop.managed_policy_windows",
                    "os": [
                        "windows"
                    ],
                    "paths": [
                        "HKCU\\SOFTWARE\\Policies\\Claude",
                        "HKLM\\SOFTWARE\\Policies\\Claude"
                    ],
                    "root": "registry",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "mcp_config",
                    "collect_priority": "first",
                    "id": "claude_desktop.mcp_config",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Claude\\claude_desktop_config.json",
                        "%LOCALAPPDATA%\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\claude_desktop_config.json",
                        "~/.config/Claude/claude_desktop_config.json",
                        "~/Library/Application Support/Claude/claude_desktop_config.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "live_only",
                    "id": "claude_desktop.oauth_and_signin_tokens",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%LOCALAPPDATA%\\Microsoft\\Credentials\\",
                        "~/Library/Keychains/login.keychain-db"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "unverified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "claude_desktop.org_plugins",
                    "os": [
                        "macos",
                        "windows"
                    ],
                    "paths": [
                        "/Library/Application Support/Claude/org-plugins/",
                        "C:\\Program Files\\Claude\\org-plugins\\"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "cache",
                    "collect_priority": "normal",
                    "id": "claude_desktop.renderer_state",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Claude\\IndexedDB\\",
                        "%APPDATA%\\Claude\\Local Storage\\",
                        "%LOCALAPPDATA%\\Claude-3p\\IndexedDB\\",
                        "%LOCALAPPDATA%\\Claude\\IndexedDB\\",
                        "%LOCALAPPDATA%\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\IndexedDB\\",
                        "%LOCALAPPDATA%\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\Local Storage\\",
                        "~/Library/Application Support/Claude-3p/IndexedDB/",
                        "~/Library/Application Support/Claude/IndexedDB/",
                        "~/Library/Application Support/Claude/Local Storage/",
                        "~/Library/Application Support/Claude/Session Storage/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "first",
                    "id": "claude_desktop.scheduled_tasks",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.claude\\scheduled-tasks\\<task-name>\\SKILL.md",
                        "~/.claude/scheduled-tasks/<task-name>/SKILL.md"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "file_snapshot",
                    "collect_priority": "durable",
                    "id": "claude_desktop.ssh_remote_artifacts",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.claude/remote/ccd-cli/<version>",
                        "~/.claude/remote/plugins/<hash>/",
                        "~/.claude/remote/run/<id>/",
                        "~/.claude/remote/srv/<version>/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "live_only",
                    "id": "claude_desktop.transient_session_credentials",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Claude\\ccd-session-secrets\\<session-id>\\",
                        "%APPDATA%\\Claude\\host-creds-<hash>.json",
                        "%LOCALAPPDATA%\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\ccd-session-secrets\\<session-id>\\",
                        "%LOCALAPPDATA%\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\host-creds-<hash>.json",
                        "~/Library/Application Support/Claude-3p/ccd-session-secrets/<session-id>/",
                        "~/Library/Application Support/Claude-3p/host-creds-<hash>.json",
                        "~/Library/Application Support/Claude/ccd-session-secrets/<session-id>/",
                        "~/Library/Application Support/Claude/host-creds-<hash>.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "file_snapshot",
                    "collect_priority": "first",
                    "id": "claude_desktop.user_output_folder",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\Claude\\",
                        "%USERPROFILE%\\Claude\\Projects\\<name>\\",
                        "~/Claude/",
                        "~/Claude/Projects/<name>/",
                        "~/Documents/Claude/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "first",
                    "id": "claude_desktop.user_plugins",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Claude\\cowork_plugins\\",
                        "%LOCALAPPDATA%\\Claude-3p\\cowork_plugins\\",
                        "%LOCALAPPDATA%\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\cowork_plugins\\",
                        "~/.config/Claude/cowork_plugins/",
                        "~/Library/Application Support/Claude-3p/cowork_plugins/",
                        "~/Library/Application Support/Claude/cowork_plugins/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                }
            ]
        },
        {
            "agent": "cline",
            "artifacts": [
                {
                    "category": "config",
                    "collect_priority": "first",
                    "id": "cline.agent_schedules",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.cline/schedules/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
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
                        "<vscode-user>/globalStorage/saoudrizwan.claude-dev/cache/remote_config_<orgId>.json",
                        "<vscode-user>/globalStorage/saoudrizwan.claude-dev/settings/cline_recommended_models.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "file_snapshot",
                    "collect_priority": "first",
                    "id": "cline.chat_workspace",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.cline/data/workspaces/chat/"
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
                    "category": "transcript",
                    "collect_priority": "durable",
                    "id": "cline.hooks_audit_log",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.cline/data/logs/hooks.jsonl"
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
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "cline.team_data",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "~/.cline/data/teams/"
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
                        "%USERPROFILE%\\.codex\\sessions\\**\\rollout-*.jsonl.*.tmp",
                        "%USERPROFILE%\\.codex\\sessions\\**\\rollout-*.jsonl.zst",
                        "%USERPROFILE%\\.codex\\sessions\\**\\rollout-compress-*.tmp",
                        "~/.codex/sessions/**/rollout-*.jsonl.*.tmp",
                        "~/.codex/sessions/**/rollout-*.jsonl.zst",
                        "~/.codex/sessions/**/rollout-compress-*.tmp"
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
                        "~/.continue/.utils/repo_map.txt",
                        "~/.continue/index/autocompleteCache.sqlite",
                        "~/.continue/index/docs.sqlite",
                        "~/.continue/index/index.sqlite",
                        "~/.continue/index/lancedb/"
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
                    "status": "verified"
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
                        "<project>/.clinerules/hooks/",
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
                        "/Library/Application Support/ClaudeCode/CLAUDE.md",
                        "/etc/claude-code/CLAUDE.md",
                        "<project>/**/CLAUDE.local.md",
                        "<project>/**/CLAUDE.md",
                        "<project>/.claude/CLAUDE.md",
                        "<project>/.claude/rules/**/*.md",
                        "<project>/CLAUDE.local.md",
                        "<project>/CLAUDE.md",
                        "C:\\Program Files\\ClaudeCode\\CLAUDE.md",
                        "~/.claude/CLAUDE.md",
                        "~/.claude/rules/**/*.md"
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
                        "<project>/.claude/skills/",
                        "<project>/.cline/remote-config/",
                        "<project>/.cline/skills/",
                        "<project>/.clineignore",
                        "<project>/.clinerules",
                        "<project>/.clinerules/",
                        "<project>/.clinerules/*.md",
                        "<project>/.clinerules/skills/",
                        "<project>/.clinerules/workflows/",
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
                        "<project>/.github/agents/*.md",
                        "<project>/.github/copilot-instructions.md",
                        "<project>/.github/copilot/settings.json",
                        "<project>/.github/copilot/settings.local.json",
                        "<project>/.github/instructions/**/*.instructions.md",
                        "<project>/.github/prompts/*.prompt.md",
                        "<project>/.github/skills/"
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
                        "<project>/**/AGENTS.md",
                        "<project>/.cursor/rules/",
                        "<project>/.cursor/rules/**/*.md",
                        "<project>/.cursor/rules/**/*.mdc",
                        "<project>/.cursor/rules/*.md",
                        "<project>/.cursor/rules/*.mdc",
                        "<project>/.cursor/rules/*/RULE.md",
                        "<project>/.cursorrules",
                        "<project>/AGENTS.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
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
                        "<project>/.gemini/settings.json",
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
                        "<project>/.junie/",
                        "<project>/.junie/guidelines.md"
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
                        "<project>/.kiro/specs/",
                        "<project>/.kiro/steering/",
                        "<project>/.kiro/steering/*.md"
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
                        "<project>/.windsurf/rules/",
                        "<project>/.windsurf/rules/*.md",
                        "<project>/.windsurfrules"
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
                        "<project>/.mcp.json",
                        "~/.claude.json"
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
                    "status": "unverified"
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
                    "status": "unverified"
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
                        "~/.cursor/browser-logs/",
                        "~/.cursor/hooks.json",
                        "~/.cursor/sandbox-policies/",
                        "~/.cursor/skills-cursor/",
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
                    "status": "unverified"
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
                    "status": "unverified"
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
                    "status": "unverified"
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
                        "%USERPROFILE%\\.cursor\\cli-config.json.bad",
                        "<project>/.cursor/cli.json",
                        "~/.cursor/cli-config.json",
                        "~/.cursor/cli-config.json.bad"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "cursor.commands_and_plans",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.cursor/commands/*.md",
                        "<project>/.cursor/plans/"
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
                    "category": "config",
                    "collect_priority": "first",
                    "id": "cursor.hooks",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "/Library/Application Support/Cursor/hooks.json",
                        "/etc/cursor/hooks.json",
                        "C:\\ProgramData\\Cursor\\hooks.json",
                        "<project>/.cursor/hooks.json",
                        "<project>/.cursor/hooks/",
                        "~/.cursor/hooks.json",
                        "~/.cursor/hooks/"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
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
                    "status": "unverified"
                },
                {
                    "category": "config",
                    "collect_priority": "durable",
                    "id": "cursor.plugins",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.cursor/plugins/",
                        "~/.cursor/plugins/local/"
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
                        "<project>/**/AGENTS.md",
                        "<project>/.cursor/rules/",
                        "<project>/.cursor/rules/**/*.mdc",
                        "<project>/.cursor/rules/*.mdc",
                        "<project>/.cursorrules",
                        "<project>/AGENTS.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
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
                    "category": "instructions",
                    "collect_priority": "durable",
                    "id": "cursor.skills",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/**/.agents/skills/",
                        "<project>/**/.cursor/skills/",
                        "<project>/.agents/skills/",
                        "<project>/.cursor/skills/",
                        "~/.agents/skills/",
                        "~/.cursor/skills/"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "cursor.subagent_output",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "~/.cursor/subagents/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "durable",
                    "id": "cursor.subagents",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.claude/agents/",
                        "<project>/.codex/agents/",
                        "<project>/.cursor/agents/",
                        "~/.claude/agents/",
                        "~/.codex/agents/",
                        "~/.cursor/agents/"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
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
                },
                {
                    "category": "file_snapshot",
                    "collect_priority": "first",
                    "id": "cursor.worktrees",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.cursor\\worktrees\\*",
                        "~/.cursor/worktrees/*"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
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
            "agent": "gemini_cli",
            "artifacts": [
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "gemini_cli.chats",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.gemini\\sessions\\",
                        "%USERPROFILE%\\.gemini\\tmp\\*\\chats\\",
                        "~/.cache/.gemini/tmp/*/chats/",
                        "~/.gemini/sessions/",
                        "~/.gemini/tmp/*/chats/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "gemini_cli.credentials",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.gemini\\oauth_creds.json",
                        "~/.gemini/oauth_creds.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "gemini_cli.google_accounts",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.gemini\\google_accounts.json",
                        "~/.gemini/google_accounts.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "first",
                    "id": "gemini_cli.home_tree",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.gemini\\",
                        "~/.gemini/"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "gemini_cli.project_config",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.gemini/",
                        "<project>/.gemini/.env",
                        "<project>/.gemini/sandbox.Dockerfile",
                        "<project>/.gemini/settings.json",
                        "<project>/GEMINI.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "shell_history",
                    "collect_priority": "first",
                    "id": "gemini_cli.shell_history",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.gemini\\tmp\\<project-hash>\\shell_history",
                        "~/.gemini/tmp/<project-hash>/shell_history"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "normal",
                    "id": "gemini_cli.system_settings",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%PROGRAMDATA%\\gemini-cli\\settings.json",
                        "%PROGRAMDATA%\\gemini-cli\\system-defaults.json",
                        "/Library/Application Support/GeminiCli/settings.json",
                        "/Library/Application Support/GeminiCli/system-defaults.json",
                        "/etc/gemini-cli/settings.json",
                        "/etc/gemini-cli/system-defaults.json"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "normal",
                    "id": "gemini_cli.trusted_folders",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.gemini\\trustedFolders.json",
                        "~/.gemini/trustedFolders.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "gemini_cli.user_settings",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.gemini\\settings.json",
                        "~/.gemini/settings.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
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
            "agent": "kiro",
            "artifacts": [
                {
                    "category": "transcript",
                    "collect_priority": "live_only",
                    "id": "kiro.acp_wire_record",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$KIRO_ACP_RECORD_PATH"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "first",
                    "id": "kiro.agents",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$KIRO_HOME/agents/*",
                        "%USERPROFILE%\\.kiro\\agents\\*",
                        "<project>/.kiro/agents/*",
                        "~/.kiro/agents/*"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "kiro.cli_install",
                    "os": [
                        "linux",
                        "macos"
                    ],
                    "paths": [
                        "~/.local/bin/kiro-cli",
                        "~/.local/bin/kirocli",
                        "~/.local/bin/q"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "log",
                    "collect_priority": "live_only",
                    "id": "kiro.cli_log",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$KIRO_CHAT_LOG_FILE",
                        "$TMPDIR/kiro-log/kiro-chat.log",
                        "$XDG_RUNTIME_DIR/kiro-log/kiro-chat.log",
                        "%TEMP%\\kiro-log\\logs\\kiro-chat.log",
                        "/tmp/kiro-log/*.log"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "kiro.cli_session_database",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$KIRO_HOME/*.sqlite3",
                        "%USERPROFILE%\\.kiro\\*.sqlite3",
                        "~/.kiro/*.sqlite3"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "kiro.cli_session_files",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$KIRO_HOME/sessions/cli/*",
                        "~/.kiro/sessions/cli/*.lock",
                        "~/.kiro/sessions/cli/<session-id>.json",
                        "~/.kiro/sessions/cli/<session-id>.jsonl"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "kiro.cli_settings",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$KIRO_HOME/settings/cli.json",
                        "%USERPROFILE%\\.kiro\\settings\\cli.json",
                        "~/.kiro/settings/cli.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "first",
                    "id": "kiro.hooks",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$KIRO_HOME/hooks/*.json",
                        "%USERPROFILE%\\.kiro\\hooks\\*.json",
                        "<project>/.kiro/hooks/*.json",
                        "<project>/.kiro/hooks/<id>.json",
                        "~/.kiro/hooks/*.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "durable",
                    "id": "kiro.ide_legacy_global_storage",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%APPDATA%\\Kiro\\User\\globalStorage\\kiro.kiroagent\\**",
                        "~/.config/Kiro/User/globalStorage/kiro.kiroagent/**",
                        "~/Library/Application Support/Kiro/User/globalStorage/kiro.kiroagent/**",
                        "~/Library/Application Support/kiro/User/globalStorage/kiro.kiroagent/**"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "kiro.ide_session_files",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$KIRO_HOME/sessions/<workspace-hash>/<session-id>/*",
                        "~/.kiro/sessions/<workspace-hash>/<session-id>/messages.jsonl",
                        "~/.kiro/sessions/<workspace-hash>/<session-id>/session.json",
                        "~/.kiro/sessions/<workspace-hash>/<session-id>/sub-executions/*.jsonl"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "kiro.kiroignore",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/**/.kiroignore",
                        "<project>/.kiroignore"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "first",
                    "id": "kiro.legacy_amazonq_config",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.amazonq/**",
                        "~/.aws/amazonq/**"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "normal",
                    "id": "kiro.managed_settings",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "/Library/Application Support/Kiro/managed-settings.json",
                        "/etc/kiro/managed-settings.json",
                        "C:\\ProgramData\\Kiro\\managed-settings.json"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "mcp_config",
                    "collect_priority": "first",
                    "id": "kiro.mcp_config_project",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.kiro/settings/mcp.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "mcp_config",
                    "collect_priority": "first",
                    "id": "kiro.mcp_config_user",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$KIRO_HOME/settings/mcp.json",
                        "%USERPROFILE%\\.kiro\\settings\\mcp.json",
                        "~/.kiro/settings/mcp.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "first",
                    "id": "kiro.permissions_user",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$KIRO_HOME/settings/permissions.yaml",
                        "%USERPROFILE%\\.kiro\\settings\\permissions.yaml",
                        "~/.kiro/settings/permissions.yaml"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "first",
                    "id": "kiro.permissions_workspace",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$KIRO_HOME/workspace-roots/<hash>/permissions.yaml",
                        "%USERPROFILE%\\.kiro\\workspace-roots\\<hash>\\permissions.yaml",
                        "~/.kiro/workspace-roots/<hash>/permissions.yaml"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "kiro.prompt_library",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$KIRO_HOME/prompts/*",
                        "%USERPROFILE%\\.kiro\\prompts\\*",
                        "<project>/.kiro/prompts/*",
                        "~/.kiro/prompts/*"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "kiro.skills_powers",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$KIRO_HOME/powers/**",
                        "$KIRO_HOME/skills/**",
                        "<project>/.kiro/skills/**",
                        "<project>/.kiro/skills/*/SKILL.md",
                        "~/.kiro/powers/**",
                        "~/.kiro/skills/**",
                        "~/.kiro/skills/*/SKILL.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "kiro.specs",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.kiro/specs/**",
                        "<project>/.kiro/specs/*/bugfix.md",
                        "<project>/.kiro/specs/*/design.md",
                        "<project>/.kiro/specs/*/requirements.md",
                        "<project>/.kiro/specs/*/tasks.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "kiro.steering_project",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/**/AGENTS.md",
                        "<project>/.kiro/steering/*.md",
                        "<project>/AGENTS.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "kiro.steering_user",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$KIRO_HOME/steering/*.md",
                        "%USERPROFILE%\\.kiro\\steering\\*.md",
                        "~/.kiro/steering/*.md",
                        "~/.kiro/steering/AGENTS.md"
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
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "lmstudio.hub_downloads",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.lmstudio\\hub\\",
                        "~/.lmstudio/hub/"
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
                    "category": "instructions",
                    "collect_priority": "normal",
                    "id": "lmstudio.presets",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.lmstudio\\config-presets\\",
                        "~/.lmstudio/config-presets/"
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
                        "%USERPROFILE%\\.local\\share\\opencode\\opencode.db",
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
                        "%USERPROFILE%\\.local\\share\\opencode\\log\\",
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
            "agent": "qwen_code",
            "artifacts": [
                {
                    "category": "memory",
                    "collect_priority": "normal",
                    "id": "qwen_code.auto_memory",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.qwen\\memories\\*",
                        "%USERPROFILE%\\.qwen\\projects\\<sanitized-project-path>\\memory\\*",
                        "<project>/.qwen/memory/*",
                        "~/.qwen/memories/*",
                        "~/.qwen/memories/MEMORY.md",
                        "~/.qwen/projects/<sanitized-project-path>/memory/MEMORY.md",
                        "~/.qwen/projects/<sanitized-project-path>/memory/extract-cursor.json",
                        "~/.qwen/projects/<sanitized-project-path>/memory/meta.json",
                        "~/.qwen/projects/<sanitized-project-path>/memory/pinned/*"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "first",
                    "id": "qwen_code.channels_scheduled_tasks",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.qwen\\channels\\cron.json",
                        "%USERPROFILE%\\.qwen\\channels\\service.pid",
                        "%USERPROFILE%\\.qwen\\channels\\sessions.json",
                        "~/.qwen/channels/cron.json",
                        "~/.qwen/channels/daemon/<hash>/*",
                        "~/.qwen/channels/service.pid",
                        "~/.qwen/channels/sessions.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "qwen_code.conversation_transcript",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.qwen\\projects\\<sanitized-project-path>\\chats\\<session-id>.jsonl",
                        "%USERPROFILE%\\.qwen\\projects\\<sanitized-project-path>\\chats\\archive\\<session-id>.jsonl",
                        "~/.qwen/projects/<sanitized-project-path>/chats/<session-id>.jsonl",
                        "~/.qwen/projects/<sanitized-project-path>/chats/archive/<session-id>.jsonl"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "qwen_code.debug_logs",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.qwen\\debug\\<session-id>.txt",
                        "~/.qwen/debug/<session-id>.txt"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "first",
                    "id": "qwen_code.env_files",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.env",
                        "%USERPROFILE%\\.qwen\\.env",
                        "<project>/.env",
                        "<project>/.qwen/.env",
                        "~/.env",
                        "~/.qwen/.env"
                    ],
                    "root": "project",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "file_snapshot",
                    "collect_priority": "first",
                    "id": "qwen_code.file_history_backups",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.qwen\\file-history\\<session-id>\\<hash>@v<version>",
                        "~/.qwen/file-history/<session-id>/<hash>@v<version>"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "normal",
                    "id": "qwen_code.ignore_files",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.agentignore",
                        "<project>/.aiignore",
                        "<project>/.qwenignore"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "durable",
                    "id": "qwen_code.install_evidence",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.qwen\\bin\\**",
                        "%USERPROFILE%\\.qwen\\installation_id",
                        "%USERPROFILE%\\.qwen\\source.json",
                        "%USERPROFILE%\\.qwen\\updates\\npm\\<launcher-id>\\versions\\<version>\\**",
                        "~/.qwen/bin/**",
                        "~/.qwen/installation_id",
                        "~/.qwen/source.json",
                        "~/.qwen/updates/npm/<launcher-id>/versions/<version>/**"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "first",
                    "id": "qwen_code.mcp_approvals",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.qwen\\mcpApprovals.json",
                        "~/.qwen/mcpApprovals.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "first",
                    "id": "qwen_code.mcp_oauth_tokens",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.qwen\\mcp-oauth-tokens-v2.json",
                        "%USERPROFILE%\\.qwen\\mcp-oauth-tokens.json",
                        "~/.qwen/mcp-oauth-tokens-v2.json",
                        "~/.qwen/mcp-oauth-tokens.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "first",
                    "id": "qwen_code.openai_api_logs",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/logs/openai/openai-<timestamp>-<id>-<suffix>.json",
                        "<project>/logs/openai/openai-<timestamp>-<id>.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "normal",
                    "id": "qwen_code.plan_files",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.qwen\\plans\\<session-id>.md",
                        "~/.qwen/plans/<session-id>.md"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "first",
                    "id": "qwen_code.project_extension_points",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.qwen/agents/<name>.md",
                        "<project>/.qwen/commands/**",
                        "<project>/.qwen/extensions/**",
                        "<project>/.qwen/extensions/qwen-extension.json",
                        "<project>/.qwen/rules/**",
                        "<project>/.qwen/skills/**/SKILL.md",
                        "<project>/.qwen/workflows/<name>.js"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "project_instructions",
                    "collect_priority": "first",
                    "id": "qwen_code.project_instructions",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/**/AGENTS.md",
                        "<project>/**/QWEN.md",
                        "<project>/.qwen/PROJECT_SUMMARY.md",
                        "<project>/.qwen/QWEN.local.md",
                        "<project>/.qwen/team-memory/*",
                        "<project>/.qwen/team-memory/MEMORY.md",
                        "<project>/AGENTS.md",
                        "<project>/QWEN.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "mcp_config",
                    "collect_priority": "first",
                    "id": "qwen_code.project_mcp_config",
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
                    "category": "config",
                    "collect_priority": "first",
                    "id": "qwen_code.project_settings",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.qwen/sandbox-macos-<profile>.sb",
                        "<project>/.qwen/sandbox.Dockerfile",
                        "<project>/.qwen/settings.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "cache",
                    "collect_priority": "live_only",
                    "id": "qwen_code.project_temp_spill",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.qwen\\tmp\\<project-hash>\\background-shells\\<session-id>\\shell-bg_<hex>.output",
                        "%USERPROFILE%\\.qwen\\tmp\\<project-hash>\\checkpoint-<tag>.json",
                        "%USERPROFILE%\\.qwen\\tmp\\<project-hash>\\checkpoints\\*",
                        "%USERPROFILE%\\.qwen\\tmp\\<project-hash>\\tool-results\\*",
                        "~/.qwen/tmp/<project-hash>/<tool-name>_<hex>",
                        "~/.qwen/tmp/<project-hash>/background-shells/<session-id>/shell-bg_<hex>.output",
                        "~/.qwen/tmp/<project-hash>/checkpoint-<tag>.json",
                        "~/.qwen/tmp/<project-hash>/checkpoints/*",
                        "~/.qwen/tmp/<project-hash>/tool-results/*"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "prompt_history",
                    "collect_priority": "first",
                    "id": "qwen_code.prompt_history_log",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.qwen\\tmp\\<project-hash>\\logs.json",
                        "~/.qwen/tmp/<project-hash>/logs.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "prompt_history",
                    "collect_priority": "first",
                    "id": "qwen_code.prompt_terminal_ledger",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.qwen\\projects\\<sanitized-project-path>\\chats\\<session-id>.ledger.jsonl",
                        "~/.qwen/projects/<sanitized-project-path>/chats/<session-id>.ledger.jsonl"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "credentials",
                    "collect_priority": "first",
                    "id": "qwen_code.qwen_oauth_credentials",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.qwen\\oauth_creds.json",
                        "%USERPROFILE%\\.qwen\\oauth_creds.lock",
                        "~/.qwen/oauth_creds.json",
                        "~/.qwen/oauth_creds.lock"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "live_only",
                    "id": "qwen_code.session_registry",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.qwen\\sessions\\<pid>.json",
                        "~/.qwen/sessions/<pid>.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "first",
                    "id": "qwen_code.session_sidecars",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.qwen\\projects\\<sanitized-project-path>\\chats\\<session-id>.pr.json",
                        "%USERPROFILE%\\.qwen\\projects\\<sanitized-project-path>\\chats\\<session-id>.runtime.json",
                        "%USERPROFILE%\\.qwen\\projects\\<sanitized-project-path>\\chats\\<session-id>.worktree.json",
                        "~/.qwen/projects/<sanitized-project-path>/chats/<session-id>.pr.json",
                        "~/.qwen/projects/<sanitized-project-path>/chats/<session-id>.runtime.json",
                        "~/.qwen/projects/<sanitized-project-path>/chats/<session-id>.worktree.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "shell_history",
                    "collect_priority": "first",
                    "id": "qwen_code.shell_history",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.qwen\\tmp\\<project-hash>\\shell_history",
                        "~/.qwen/tmp/<project-hash>/shell_history"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "qwen_code.subagent_transcripts",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.qwen\\projects\\<sanitized-project-path>\\subagents\\<session-id>\\*",
                        "~/.qwen/projects/<sanitized-project-path>/subagents/<session-id>/*"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "qwen_code.system_settings",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "/Library/Application Support/QwenCode/settings.json",
                        "/Library/Application Support/QwenCode/system-defaults.json",
                        "/etc/qwen-code/settings.json",
                        "/etc/qwen-code/system-defaults.json",
                        "C:\\ProgramData\\qwen-code\\settings.json",
                        "C:\\ProgramData\\qwen-code\\system-defaults.json"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "first",
                    "id": "qwen_code.trusted_folders",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.qwen\\trustedFolders.json",
                        "~/.qwen/trustedFolders.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "first",
                    "id": "qwen_code.usage_history",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.qwen\\usage_record.jsonl",
                        "~/.qwen/usage_record.jsonl"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "first",
                    "id": "qwen_code.user_extension_points",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.agents\\skills\\**",
                        "%USERPROFILE%\\.qwen\\agents\\<name>.md",
                        "%USERPROFILE%\\.qwen\\commands\\**",
                        "%USERPROFILE%\\.qwen\\extensions\\**",
                        "%USERPROFILE%\\.qwen\\rules\\**",
                        "%USERPROFILE%\\.qwen\\skills\\**",
                        "%USERPROFILE%\\.qwen\\workflows\\<name>.js",
                        "~/.agents/skills/**",
                        "~/.qwen/agents/<name>.md",
                        "~/.qwen/commands/**",
                        "~/.qwen/extensions/**",
                        "~/.qwen/locales/**",
                        "~/.qwen/rules/**",
                        "~/.qwen/skills/**",
                        "~/.qwen/workflows/<name>.js"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "instructions",
                    "collect_priority": "first",
                    "id": "qwen_code.user_instructions",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.qwen\\AGENTS.md",
                        "%USERPROFILE%\\.qwen\\QWEN.md",
                        "%USERPROFILE%\\.qwen\\memory.md",
                        "~/.qwen/AGENTS.md",
                        "~/.qwen/QWEN.md",
                        "~/.qwen/memory.md"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "first",
                    "id": "qwen_code.user_settings",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.qwen\\settings.json",
                        "~/.qwen/settings.json"
                    ],
                    "root": "user_profile",
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
                    "category": "mcp_config",
                    "collect_priority": "normal",
                    "id": "vscode.mcp_config",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "<project>/.vscode/mcp.json",
                        "<vscode-user>/mcp.json"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
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
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "windsurf.acp_registry",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.windsurf\\acp\\registry.json",
                        "~/.windsurf-next/acp/registry.json",
                        "~/.windsurf/acp/registry.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
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
                        "%USERPROFILE%\\.codeium\\windsurf\\cascade\\*",
                        "~/.codeium/windsurf-insiders/cascade/*",
                        "~/.codeium/windsurf-next/cascade/*",
                        "~/.codeium/windsurf/cascade/*",
                        "~/.codeium/windsurf/cascade/*.pb",
                        "~/.codeium/windsurf/cascade/*.pb.archived"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "windsurf.cascade_transcripts",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.windsurf\\transcripts\\*.jsonl",
                        "~/.devin/transcripts/*.jsonl",
                        "~/.windsurf/transcripts/*.jsonl"
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
                        "%USERPROFILE%\\.codeium\\user_settings.pb",
                        "~/.codeium/user_settings.pb",
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
                        "%USERPROFILE%\\.codeium\\windsurf\\memories\\global_rules.md",
                        "~/.codeium/windsurf-insiders/memories/global_rules.md",
                        "~/.codeium/windsurf-next/memories/global_rules.md",
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
                        "%USERPROFILE%\\.codeium\\hooks.json",
                        "%USERPROFILE%\\.codeium\\windsurf\\hooks.json",
                        "<project>/.windsurf/hooks.json",
                        "~/.codeium/hooks.json",
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
                    "id": "windsurf.ide_user_data",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%APPDATA%\\Devin\\User\\settings.json",
                        "%APPDATA%\\Windsurf\\User\\keybindings.json",
                        "%APPDATA%\\Windsurf\\User\\settings.json",
                        "%APPDATA%\\Windsurf\\argv.json",
                        "~/.config/Windsurf/User/settings.json",
                        "~/Library/Application Support/Devin/User/settings.json",
                        "~/Library/Application Support/Windsurf/User/keybindings.json",
                        "~/Library/Application Support/Windsurf/User/settings.json",
                        "~/Library/Application Support/Windsurf/User/snippets/",
                        "~/Library/Application Support/Windsurf/Workspaces/",
                        "~/Library/Application Support/Windsurf/argv.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
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
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "windsurf.ignore_files",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.codeium\\.codeiumignore",
                        "<project>/.codeiumignore",
                        "<project>/.devinignore",
                        "<project>/.windsurfignore",
                        "~/.codeium/.codeiumignore"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
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
                        "%USERPROFILE%\\.codeium\\windsurf\\memories\\*",
                        "~/.codeium/windsurf-insiders/memories/*",
                        "~/.codeium/windsurf-next/memories/*",
                        "~/.codeium/windsurf/memories/*",
                        "~/.codeium/windsurf/memories/*.pb"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "windsurf.plans",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.windsurf\\plans\\",
                        "<project>/.devin/plans/",
                        "<project>/.windsurf/plans/",
                        "~/.devin/plans/plan-*.md",
                        "~/.devin/plans/",
                        "~/.windsurf/plans/"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "first",
                    "id": "windsurf.plugin_log",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.codeium\\codeium.log",
                        "~/.codeium/codeium.log"
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
                        "<project>/.windsurf/global_rules.md",
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
                    "id": "windsurf.system_config",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "/Library/Application Support/Windsurf/hooks.json",
                        "/Library/Application Support/Windsurf/rules/*.md",
                        "/Library/Application Support/Windsurf/skills/",
                        "/Library/Application Support/Windsurf/workflows/",
                        "/etc/windsurf/hooks.json",
                        "/etc/windsurf/rules/*.md",
                        "/etc/windsurf/skills/",
                        "/etc/windsurf/workflows/",
                        "C:\\ProgramData\\Windsurf\\hooks.json",
                        "C:\\ProgramData\\Windsurf\\rules\\*.md",
                        "C:\\ProgramData\\Windsurf\\skills\\",
                        "C:\\ProgramData\\Windsurf\\workflows\\"
                    ],
                    "root": "system",
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
                },
                {
                    "category": "file_snapshot",
                    "collect_priority": "first",
                    "id": "windsurf.worktrees",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.windsurf\\worktrees\\*",
                        "~/.devin/worktrees/*",
                        "~/.windsurf/worktrees/*"
                    ],
                    "root": "user_profile",
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
                        "$XDG_DATA_HOME/zed/debug_adapters/",
                        "$XDG_DATA_HOME/zed/extensions/",
                        "$XDG_DATA_HOME/zed/external_agents/",
                        "$XDG_DATA_HOME/zed/prompt_overrides/",
                        "%LOCALAPPDATA%\\Zed\\debug_adapters\\",
                        "%LOCALAPPDATA%\\Zed\\extensions\\",
                        "%LOCALAPPDATA%\\Zed\\external_agents\\",
                        "%LOCALAPPDATA%\\Zed\\prompt_overrides\\",
                        "~/.config/zed/prompts/",
                        "~/Library/Application Support/Zed/debug_adapters/",
                        "~/Library/Application Support/Zed/extensions/",
                        "~/Library/Application Support/Zed/external_agents/",
                        "~/Library/Application Support/Zed/prompt_overrides/"
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
    "sha256": "0e365a21fcae64c9429b069d526229e701e1dcfc147604b701e1ad751c914717"
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
        # Keys are sorted by code point, which is what Python's json.dumps(sort_keys=True)
        # does, and this is not what it looked like.
        #
        # It was `Sort-Object -Property Key -CaseSensitive`, under a comment saying that
        # gives an ordinal sort. It does not: -CaseSensitive makes the comparison
        # case-sensitive and leaves it culture-aware, which this same file states correctly
        # thirteen hundred lines further down in Sort-Ordinal. With alphanumeric keys the
        # two orders happen to agree, so the parity check never saw it. A key beginning with
        # punctuation is where they part: a culture-aware sort put "$VAR/..." last and
        # "/etc/..." first, and Python puts them the other way round, because "$" is U+0024
        # and "/" is U+002F. A manifest whose key order depends on the machine's locale is
        # not the same document from two collections of one host.
        #
        # Entries are copied into a dictionary rather than looked up on the original. An
        # OrderedDictionary exposes both an [object] and an [int] indexer and a key that has
        # been through the pipeline comes back wrapped in PSObject, so $Value[$key] cannot
        # resolve the overload and throws "Argument types do not match" at runtime.
        $byKey = [System.Collections.Generic.Dictionary[string, object]]::new(
            [System.StringComparer]::Ordinal)
        $keys = [System.Collections.Generic.List[string]]::new()
        foreach ($entry in @($Value.GetEnumerator())) {
            $byKey[[string]$entry.Key] = $entry.Value
            $keys.Add([string]$entry.Key)
        }
        foreach ($key in (Sort-Ordinal -Items $keys)) {
            $rendered = ConvertTo-CanonicalJson -Value $byKey[$key] -Indent ($Indent + 2)
            $parts.Add($padInner + (ConvertTo-JsonString $key) + ': ' + [string]$rendered)
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
    # Per-user temporary directory, for the reason collect.py gives: several agents write
    # their logs and one writes its chat log here, and an unexpanded placeholder means the
    # logs of a failing run are never collected.
    '%TEMP%'          = 'AppData/Local/Temp'
    '%TMP%'           = 'AppData/Local/Temp'
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

# Variables the operating system owns rather than an agent. On a Windows target these are
# another platform's spelling of the same artifact, the catalogue entry carries a Windows
# sibling for it, and dropping them there is deliberate.
#
# An agent's own relocation variable is a different thing and was being treated the same
# way. CLAUDE_CONFIG_DIR, HERMES_HOME, KIRO_HOME and nine more are the same variable on
# every platform, and the Windows branch dropped every pattern rooted at one and recorded
# no refusal: 43 catalogue paths, including a credential store and two session databases.
# The default location was still searched through the entry's `~` sibling, so the failure
# was narrow and completely silent.
#
# Kept in step with the same set in collect.py by the conformance suite.
$script:PosixOnlyVariables = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@('HOME', 'HISTFILE', 'ZDOTDIR', 'TMPDIR', 'XDG_RUNTIME_DIR',
        'XDG_DATA_HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_STATE_HOME'),
    [System.StringComparer]::Ordinal)

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

# Failures to read an agent's own state file, which is where the list of working copies
# comes from. Surfaced in the manifest's errors, for the reason ADR 0009 gives: a record
# that is dropped reads as a record that never existed.
$script:StateReadProblems = [System.Collections.Generic.List[object]]::new()

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

function Test-OwnProfile {
    <#
    .SYNOPSIS
        Whether this home is the one belonging to the process running the collector.
    .DESCRIPTION
        Mirrors collect.py's _own_profile. The question decides whether this process's
        environment says anything about the profile being collected. It does for its own;
        for anybody else's it does not, and applying this user's variables to another
        user's profile would attribute one person's files to another. Compared
        case-insensitively because Windows paths are.
    #>
    param([string] $ProfileHome)

    $own = [System.Environment]::GetEnvironmentVariable('USERPROFILE')
    if (-not $own) { $own = [System.Environment]::GetFolderPath('UserProfile') }
    if (-not $own) { return $false }
    $left = $own.Replace('\', '/').TrimEnd('/')
    $right = $ProfileHome.Replace('\', '/').TrimEnd('/')
    return [string]::Equals($left, $right, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-WindowsRedirectTarget {
    <#
    .SYNOPSIS
        The extra pattern a placeholder's live value implies, or an empty string.
    .DESCRIPTION
        Mirrors collect.py's windows_redirect_target and reads no environment, so the
        decision itself can be checked with fixed inputs on both collectors without either
        depending on the machine it runs on. The self-test carries those inputs.

        Returns '' when the value is empty, when it is where the default already points, or
        when the text does not start with a placeholder this collector knows.
    #>
    param([string] $Text, [string] $ProfileHome, [string] $Value)

    if (-not $Value) { return '' }
    $upper = $Text.ToUpperInvariant()
    foreach ($key in $script:WinPlaceholders.Keys) {
        if (-not $upper.StartsWith($key)) { continue }
        # A UNC value keeps its two leading separators: \\server\share is a host and a
        # share, and collapsing it to one produces a path on this machine instead.
        $moved = $Value.Replace('\', '/').TrimEnd('/')
        $base = $ProfileHome.Replace('\', '/').TrimEnd('/')
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($piece in @($base, [string]$script:WinPlaceholders[$key])) {
            if ($piece) { $parts.Add($piece) }
        }
        $default = [string]::Join('/', $parts)
        if ([string]::Equals($moved, $default, [System.StringComparison]::OrdinalIgnoreCase)) {
            return ''
        }
        # The tail is normalised here rather than left to the caller, so this function's
        # answer is one spelling of one path and can be compared against the other
        # collector's byte for byte.
        $tail = $Text.Substring(([string]$key).Length).TrimStart('\', '/').Replace('\', '/')
        $out = [System.Collections.Generic.List[string]]::new()
        foreach ($piece in @($moved, $tail)) { if ($piece) { $out.Add($piece) } }
        return [string]::Join('/', $out)
    }
    return ''
}

function Get-WindowsRedirected {
    <#
    .SYNOPSIS
        Where a Windows placeholder actually points, when that is not the default. Or ''.
    .DESCRIPTION
        Mirrors collect.py's _windows_redirected. Folder redirection is ordinary in a
        managed fleet: %APPDATA% can be a network share and %TEMP% can be moved. The
        documented default under the profile is then an empty directory, so a collection
        finds none of the 134 catalogue paths rooted at one of these placeholders and
        reports nothing wrong. Both locations are searched rather than one replacing the
        other, because the default can still hold what was written before the redirection.

        Only for a live host and only for the process's own profile. A mounted image has no
        environment to ask, and another user's profile has one this process cannot see.
    #>
    param([string] $Text, [string] $ProfileHome, [string] $Root)

    if (-not (Test-EnvironmentApplies -ProfileHome $ProfileHome -Root $Root)) { return '' }
    $upper = $Text.ToUpperInvariant()
    foreach ($key in $script:WinPlaceholders.Keys) {
        if ($upper.StartsWith($key)) {
            $value = [System.Environment]::GetEnvironmentVariable(([string]$key).Trim('%'))
            return (Get-WindowsRedirectTarget -Text $Text -ProfileHome $ProfileHome -Value $value)
        }
    }
    return ''
}

function Get-VariableName {
    <#
    .SYNOPSIS
        The leading variable's name, or an empty string when the text does not start with one.
    .DESCRIPTION
        Mirrors collect.py's variable_name. Both spellings the catalogue uses: $NAME and the
        shell default form ${NAME:-...}.
    #>
    param([string] $Text)

    $found = [regex]::Match($Text, '^\$\{?([A-Za-z_][A-Za-z0-9_]*)')
    if ($found.Success) { return $found.Groups[1].Value }
    return ''
}

function Test-EnvironmentApplies {
    <#
    .SYNOPSIS
        Whether this process's environment says anything about the profile being collected.
    .DESCRIPTION
        Mirrors collect.py's environment_applies_to. Not for a mounted image: the analyst
        workstation's variables are not the endpoint's. And not for another user's profile,
        because a collector walking every profile on a live host has one environment, its
        own, so applying this user's CLAUDE_CONFIG_DIR to somebody else's profile searches
        this user's directory and files what it finds under that user's name.
    #>
    param([string] $ProfileHome, [string] $Root)

    if ($Root) { return $false }
    return (Test-OwnProfile -ProfileHome $ProfileHome)
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
        if (Test-EnvironmentApplies -ProfileHome $ProfileHome -Root $Root) {
            $value = [System.Environment]::GetEnvironmentVariable($name)
        }
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
        if (Test-EnvironmentApplies -ProfileHome $ProfileHome -Root $Root) {
            $value = [System.Environment]::GetEnvironmentVariable($name)
        }
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
    if (-not (Test-OwnProfile -ProfileHome $ProfileHome)) {
        # Another user's profile on a live host. Their variable is not in this process's
        # environment, and using this one's would search the wrong tree and file the result
        # under their name.
        $result['text'] = $Text
        $result['outcome'] = 'environment_unreadable_other_user'
        return $result
    }
    $value = [System.Environment]::GetEnvironmentVariable($name)
    if (-not $value) {
        $result['text'] = $Text
        $result['outcome'] = 'unset'
        return $result
    }
    # Either separator: a Windows value can end in a backslash, and joining that to a tail
    # that starts with one produces a path no glob matches.
    $result['text'] = $value.TrimEnd('/', '\') + $tail
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

function Get-PatternRootRank {
    <#
    .SYNOPSIS
        How well this collector can say where a pattern's root is. Higher is better.
    .DESCRIPTION
        Mirrors collect.py's root_rank, and the two must agree: a bundle and a directly read
        tree attributing one file differently cost a whole chat transcript once.

        2  a directory this collector can name: ~, a Windows placeholder, an absolute path.
        1  a working copy, whose location is not in the catalogue but is recorded in the
           agent's own state and substituted here.
        0  a root nothing locates: a plugin or marketplace directory, or a tree relocated by
           a variable.

        The middle and the bottom are both substituted with the same recorded working
        copies, which is why they are told apart: a pattern written for a plugin root and
        matched at a working copy root was matched somewhere it was not written for.
    #>
    param([string] $Pattern)

    $head = ($Pattern -replace '\\', '/').Split('/')[0]
    if ($head.StartsWith('<')) {
        if ($head -ceq '<project>' -or $head -ceq '<repo-root>' -or $head -ceq '<repo_root>') {
            return 1
        }
        return 0
    }
    if ($head.StartsWith('$')) { return 0 }
    return 2
}

function Get-PatternLiteralLength {
    <#
    .SYNOPSIS
        How many literal characters a catalogue pattern spells below its root.
    .DESCRIPTION
        Mirrors collect.py's pattern_specificity. The count is over the part below the root,
        because the root is a placeholder in one entry and a literal in another and counting
        it would compare two different things. A '**' segment counts nothing, and inside a
        segment a placeholder and a wildcard count nothing.
    #>
    param([string] $Pattern)

    $text = $Pattern -replace '\\', '/'
    $head = $text.Split('/')[0]
    $body = $text
    if ($head.StartsWith('<') -or $head.StartsWith('$') -or $head -ceq '~' -or
        ($head.StartsWith('%') -and $head.EndsWith('%'))) {
        $index = $text.IndexOf('/')
        if ($index -lt 0) { $body = '' } else { $body = $text.Substring($index + 1) }
    }
    $literal = 0
    foreach ($segment in $body.Split('/')) {
        if ($segment -ceq '' -or $segment -ceq '**') { continue }
        $literal += ([regex]::Replace($segment, '<[^>]*>|\*', '')).Length
    }
    return $literal
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
        if ($text.StartsWith('$')) {
            if ($script:PosixOnlyVariables.Contains((Get-VariableName -Text $text))) {
                # Another platform's spelling of the same artifact. The entry carries a
                # Windows sibling and that one is being searched, so this is the
                # cross-platform case above and not a refusal.
                return $results
            }
            # An agent's own relocation variable, which is the same variable here as it is
            # on POSIX, so it is resolved the same way and has the same three outcomes. It
            # used to be dropped with the freedesktop ones: a relocated tree was never
            # searched on a Windows target and nothing said so.
            $resolved = Resolve-EnvPrefix -Text $text -ProfileHome $ProfileHome -Root $Root
            $outcome = [string]$resolved['outcome']
            if ($outcome -ceq 'unset') { return $results }
            if ($outcome -cne 'ok') {
                Add-PatternRefusal -Pattern $Pattern -Expanded $text -Reason $outcome
                return ,$results
            }
            $text = ([string]$resolved['text']).Replace('\', '/')
        } else {
            # Asked before the substitution, while the placeholder is still there.
            $redirected = Get-WindowsRedirected -Text $text -ProfileHome $ProfileHome -Root $Root
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
            if ($redirected) {
                # Two locations, both evidence. Recursed rather than handled here so each
                # one passes the guards at the end of this function: an absolute path
                # matches no placeholder, so the recursion terminates at one level.
                $both = [System.Collections.Generic.List[string]]::new()
                foreach ($one in (Expand-CataloguePath -Pattern $text.Replace('\', '/') `
                        -ProfileHome $ProfileHome -TargetOs $TargetOs -Root $Root)) {
                    $both.Add([string]$one)
                }
                foreach ($one in (Expand-CataloguePath -Pattern $redirected `
                        -ProfileHome $ProfileHome -TargetOs $TargetOs -Root $Root)) {
                    $both.Add([string]$one)
                }
                return ,$both
            }
        }
        $text = $text.Replace('\', '/')
    } else {
        # '[^%]+' rather than '[A-Za-z_]+': %PROGRAMFILES(X86)% holds a parenthesis and a
        # digit, so the narrower class did not recognise it as a Windows spelling and the
        # pattern was refused as not absolute instead of skipped as another platform's.
        # The short registry hive names as well as HKEY_. The catalogue uses both spellings,
        # and with only the long one a pattern like HKCU\Software\... fell through: under a
        # root it was re-anchored and globbed, so a registry key was searched as a directory
        # under the image root.
        if ($text -match '^%[^%]+%' -or $text -match '^[A-Za-z]:\\' -or
            $text -match '^HK(EY_[A-Z_]+|CU|LM|U|CR|CC)\\') {
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
    if (-not ($text.StartsWith('/') -or $text -match '^[A-Za-z]:[/\\]')) {
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

function Format-LinkTarget {
    <#
    .SYNOPSIS
        A link target as the manifest records it: no extended-length prefix, one separator.
    .DESCRIPTION
        Windows hands back \\?\C:\... for a link created through the extended-length API,
        which is a Win32 calling convention rather than a fact about where the link points.
        The other collector reports the plain path, and the manifests are compared field by
        field, so the prefix has to go. Forward slashes for the same reason every other
        path in this collector uses them.
    #>
    param([string] $Target)
    $text = $Target
    if ($text.StartsWith('\\?\UNC\')) {
        $text = '\\' + $text.Substring('\\?\UNC\'.Length)
    } elseif ($text.StartsWith('\\?\')) {
        $text = $text.Substring('\\?\'.Length)
    }
    return $text.Replace('\', '/')
}

function Get-LinkTarget {
    <#
    .SYNOPSIS
        Where a symbolic link or junction points, or $null.
    .DESCRIPTION
        Two ways, because the one that reads well is not available where this runs.
        FileInfo.LinkTarget arrived in .NET 6, so it exists under PowerShell 7 and not
        under Windows PowerShell 5.1. Get-Item exposes a Target property on 5.1 for a
        reparse point and is the fallback.

        Without a target the collector cannot tell whether a link leaves the profile, and
        it then treats the entry as skipped_symlink rather than following it: on 5.1 the
        first version of this returned nothing, the link was reported as unreadable, and an
        unreadable file is an error while a link out of the profile is a deliberate
        decision. The two must not look alike in a manifest.
    #>
    param([string] $Path)
    try {
        $info = [System.IO.FileInfo]::new($Path)
        if ($info.PSObject.Properties.Name -ccontains 'LinkTarget' -and $info.LinkTarget) {
            return (Format-LinkTarget ([string]$info.LinkTarget))
        }
    } catch {
        # Fall through to Get-Item.
    }
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.PSObject.Properties.Name -ccontains 'Target') {
            $value = $item.Target
            if ($value) {
                # 5.1 returns a collection for a reparse point with several targets.
                foreach ($entry in @($value)) {
                    if ($entry) { return (Format-LinkTarget ([string]$entry)) }
                }
            }
        }
    } catch {
        # A link the platform will not describe. The caller records skipped_symlink.
    }
    return $null
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

# Names under a Windows Users directory that are not users. Two of them, All Users and
# Default User, are junctions, into ProgramData and into the default profile, so walking
# them collects another tree under a user name nobody has. Keyed on the parent being named
# Users rather than on the running platform, so an image of a Windows host collected from a
# POSIX workstation is treated the same way. Kept in step with _PSEUDO_PROFILES in
# collect.py by the conformance suite.
$script:PseudoProfiles = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@('public', 'default', 'default user', 'all users', 'defaultuser0'),
    [System.StringComparer]::OrdinalIgnoreCase)


function Get-LiveProfileParents {
    <#
    .SYNOPSIS
        The directories this host keeps its user profiles in.
    .DESCRIPTION
        Mirrors collect.py's live_profile_parents. Windows keeps them on the system drive;
        this file used to name C: literally, which is right on almost every host and wrong
        on the one that matters. POSIX keeps them under /Users and /home.
    #>
    if ([System.Environment]::OSVersion.Platform -ceq 'Unix') {
        return @('/Users', '/home')
    }
    $drive = [System.Environment]::GetEnvironmentVariable('SystemDrive')
    if (-not $drive) { $drive = 'C:' }
    return @(($drive.TrimEnd('/', '\')).Replace('\', '/') + '/Users')
}


function Get-ProfilesUnder {
    <#
    .SYNOPSIS
        The profile directories directly under one parent, ordinally sorted.
    .DESCRIPTION
        Mirrors collect.py's _profiles_under, including the two things that are easy to
        leave out. The order is ordinal, because Sort-Object is culture-aware and the order
        decides which of two profiles differing only in case keeps the plain bundle path.
        And a profile that is a symbolic link is skipped and recorded rather than passed
        over: where it points is not known to be inside the tree being collected, and
        absent and unsearched are different answers.
    #>
    param([string] $Parent, [bool] $SkipPseudo)

    $found = [System.Collections.Generic.List[object]]::new()
    $names = [System.Collections.Generic.List[string]]::new()
    try {
        foreach ($dir in [System.IO.Directory]::GetDirectories($Parent)) {
            $names.Add([System.IO.Path]::GetFileName(([string]$dir).TrimEnd('/', '\')))
        }
    } catch {
        return ,$found
    }
    foreach ($name in (Sort-Ordinal -Items $names)) {
        if ($SkipPseudo -and $script:PseudoProfiles.Contains([string]$name)) { continue }
        $profilePath = Join-BundlePath $Parent $name
        if (Test-IsSymlink $profilePath) {
            Add-PatternRefusal -Pattern $profilePath -Expanded $profilePath `
                -Reason 'profile_is_a_symlink'
            continue
        }
        $entry = [ordered]@{}
        $entry['home'] = $profilePath
        $entry['name'] = $name
        [void]$found.Add($entry)
    }
    return ,$found
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
            foreach ($entry in (Get-ProfilesUnder -Parent $base -SkipPseudo ($parent -ceq 'Users'))) {
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
        foreach ($parent in (Get-LiveProfileParents)) {
            if (-not [System.IO.Directory]::Exists($parent)) { continue }
            $leafOfParent = [System.IO.Path]::GetFileName(([string]$parent).TrimEnd('/', '\'))
            foreach ($entry in (Get-ProfilesUnder -Parent $parent -SkipPseudo ($leafOfParent -ceq 'Users'))) {
                [void]$found.Add($entry)
            }
        }
        # The superuser's own home, which is not under the profile parent on either POSIX
        # platform. Windows has no equivalent: the administrator's profile is under Users
        # like everybody else's. collect.py adds the same two and the two collectors have to
        # return the same profiles from the same host.
        foreach ($superuser in @('/var/root', '/root')) {
            if ([System.IO.Directory]::Exists($superuser)) {
                $entry = [ordered]@{}; $entry['home'] = $superuser; $entry['name'] = 'root'
                [void]$found.Add($entry)
                break
            }
        }
    } elseif ($Named -and $Named.Count -gt 0) {
        # A named user is looked up under the profile parents rather than filtered out of
        # the one profile this process happens to be running as. collect.py has always done
        # that, and this file filtered instead, so -User with somebody else's name returned
        # nothing on a host where they exist and said nothing about why.
        foreach ($name in $Named) {
            foreach ($parent in (Get-LiveProfileParents)) {
                $candidate = Join-BundlePath $parent $name
                if ([System.IO.Directory]::Exists($candidate)) {
                    $entry = [ordered]@{}; $entry['home'] = $candidate; $entry['name'] = $name
                    [void]$found.Add($entry)
                    break
                }
            }
        }
        return ,$found
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
            # Recorded, not swallowed. This file is the authoritative list of the working
            # copies an agent was used in, and the project-anchored artifacts are the
            # prompt-injection surface: failing to read it silently means the whole of
            # that surface is absent from the bundle with nothing saying why. The projects
            # directory below is a second, independent source for the same list, and it is
            # lossy, so it is a fallback rather than a replacement.
            $problem = [ordered]@{}
            $problem['detail'] = [string]$_.Exception.Message
            $problem['error'] = 'unparsable_agent_state'
            $problem['path'] = $configPath
            [void]$script:StateReadProblems.Add($problem)
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
        $target = Get-LinkTarget $Original
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
        # authorized to read. Recorded, not followed. A link whose target cannot be
        # determined at all is treated the same way, because following it blind is the one
        # thing that must not happen.
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

function Compare-ClaimKey {
    <#
    .SYNOPSIS
        Compare two claim-order keys the way Python compares its tuple. Negative, zero or
        positive, as a comparison function returns.
    .DESCRIPTION
        The first two elements are numbers and the third is an artifact id compared
        ordinally, because that is what Python's sorted() does and the two collectors have
        to attribute a file to the same catalogue entry.
    #>
    param([object[]] $Left, [object[]] $Right)

    for ($index = 0; $index -lt 2; $index++) {
        $difference = [int]$Left[$index] - [int]$Right[$index]
        if ($difference -ne 0) { return $difference }
    }
    return [System.String]::CompareOrdinal([string]$Left[2], [string]$Right[2])
}

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

    # A run that found no profile at all collects nothing, and an empty bundle has to say
    # why it is empty. Without this, zero profiles, zero files and zero errors read exactly
    # like a host with no user data on it. Mirrors collect.py.
    if ($users.Count -eq 0) {
        if ($AllUsers) {
            $asked = '-AllUsers'
        } elseif ($User -and $User.Count -gt 0) {
            $asked = '-User ' + ($User -join ', ')
        } else {
            $asked = 'this run'
        }
        if ($Root) { $where = $Root } else { $where = ((Get-LiveProfileParents) -join ', ') }
        $problem = [ordered]@{}
        $problem['detail'] = ('{0} matched no user profile under {1}, so nothing was searched' -f $asked, $where)
        $problem['error'] = 'no_profiles_found'
        $problem['path'] = $where
        [void]$errors.Add($problem)
        [Console]::Error.Write(('{0}: no user profile was found under {1}. Nothing was searched, and the ' -f $script:ToolName, $where) +
            "manifest records that as an error rather than as an empty host.`n")
    }

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
                        # Matched and sliced rather than passed to Replace. A .NET
                        # replacement string interprets $ as a group reference, and a
                        # directory name may contain one; the Python side had the same
                        # shape and re.sub interprets backslashes, which killed the whole
                        # collection on the first Windows project root it found.
                        $anchorMatch = [regex]::Match($concrete, '^<[^>]+>')
                        if ($anchorMatch.Success) {
                            $concrete = $anchor.TrimEnd('/', '\') + $concrete.Substring($anchorMatch.Length)
                        }
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
                                # The catalogue pattern travels with the claim, because a
                                # claim's specificity is a property of the pattern that
                                # matched and not of the entry that holds it.
                                $claim = [ordered]@{}
                                $claim['artifact'] = $artifact
                                $claim['pattern'] = [string]$pattern
                                [void]([System.Collections.Generic.List[object]]$matches[$target]).Add($claim)
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

            # Attributed to the most specific claim, so a file is reported under the entry
            # that names it rather than under a directory glob that happened to include it.
            #
            # This was the artifact with the fewest path patterns, which is a proxy and the
            # wrong way round: an entry holding one broad glob over a directory has fewer
            # patterns than an entry whose pattern names the file. Mirrors collect.py's
            # claim_order, including the id being the last key rather than the second. See
            # ADR 0025.
            # Sorted by hand rather than with Sort-Object, and the reason is the one this
            # file gives in Sort-Ordinal: -CaseSensitive is culture-aware, so the id
            # tiebreak would order two artifacts differently from Python's ordinal sorted().
            # Today's 460 ids happen to sort the same either way, which is luck and not a
            # property, and this key decides which catalogue entry a file is reported under.
            $best = $null
            $bestKey = $null
            foreach ($claim in $claimants) {
                $pattern = [string]$claim['pattern']
                $key = @(
                    -(Get-PatternLiteralLength $pattern),
                    -(Get-PatternRootRank $pattern),
                    [string]$claim['artifact'].id
                )
                if ($null -eq $bestKey -or (Compare-ClaimKey $key $bestKey) -lt 0) {
                    $best = $claim
                    $bestKey = $key
                }
            }
            $primary = $best['artifact']

            $withhold = $false
            $claimantIds = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($claim in $claimants) {
                $claimant = $claim['artifact']
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

    foreach ($problem in $script:StateReadProblems) { [void]$errors.Add($problem) }
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
    if ([System.Environment]::OSVersion.Platform -ceq 'Unix') {
        # collect.py answers this with geteuid() == 0, and the two collectors have to give
        # the same answer about the same host. Running this file on a POSIX host happens in
        # the differential test, where a blanket false disagreed with Python's true.
        try {
            return ([string][System.Environment]::UserName -ceq 'root')
        } catch {
            return $null
        }
    }
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        # An identity the platform will not describe. Null rather than false: "not
        # elevated" and "could not find out" lead an analyst to different conclusions
        # about why a collection is thin, and the manifest must not state the first when it
        # means the second.
        return $null
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

    # Built from code points rather than written as literal characters, so that this file
    # contains no byte above 127 anywhere.
    #
    # Windows PowerShell 5.1 reads a script file with no byte order mark as the machine's
    # ANSI code page, not as UTF-8. A literal 'Gruezi' with an umlaut was therefore parsed
    # as two characters, the serializer faithfully emitted both, and the parity check
    # failed against Python with U+00C3 where U+00FC belonged. A byte order mark would also
    # fix it, and is worse: this collector is pasted into live-response consoles and piped
    # through EDR tooling, and a tool that misparses its own source when a BOM is lost in
    # transit is a hazard. ASCII has no such dependency.
    $unicodeCase = -join @(
        'Gr', [char]0x00FC, 'ezi ', [char]0x00FC, 'nd ',
        [char]0x00E3, [char]0x00E7, 'cents ',
        [char]0x65E5, [char]0x672C, [char]0x8A9E, ' emoji'
    )
    $cases['unicode'] = $unicodeCase
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

    # The claimant-ranking rule, computed by this file's own functions. The Python side
    # computes the same patterns with collect.py's and compares, so this is the two
    # implementations checked against each other rather than both against a constant.
    #
    # The rule decides which catalogue entry a file is reported under, and that decides
    # whether the analyzer finds a parser for it. The two collectors disagreeing here would
    # be a bundle that reads differently depending on which one took it, which is the same
    # class of failure as the serializer parity above. See ADR 0025.
    $specificity = [ordered]@{}
    foreach ($pattern in @(
        '~/.claude/CLAUDE.md',
        '<project>/.claude/CLAUDE.md',
        '<project>/**/CLAUDE.md',
        '<project>/.mcp.json',
        '<plugin-root>/.mcp.json',
        '~/.gemini/',
        '~/.gemini/tmp/<hash>/chats/*.jsonl',
        '$CLAUDE_CONFIG_DIR/.claude.json',
        '%APPDATA%\Block\goose\data\sessions\sessions.db',
        '/etc/claude-code/managed-settings.json'
    )) {
        $pair = [System.Collections.Generic.List[object]]::new()
        [void]$pair.Add([int](Get-PatternLiteralLength -Pattern $pattern))
        [void]$pair.Add([int](Get-PatternRootRank -Pattern $pattern))
        $specificity[[string]$pattern] = $pair
    }
    $cases['pattern_specificity'] = $specificity

    # The Windows target's own expansion. No differential reached this branch before: every
    # conformance invocation of both collectors passes the linux target, and the only other
    # exercise of the Windows one never touched a filesystem. So the branch that decides
    # whether a relocated agent tree is searched, refused or silently dropped was checked by
    # nothing, and it was dropping it.
    #
    # A root is passed, so no environment variable is read and the answer is the same on
    # every machine: a mounted image is exactly the case where the endpoint's variables
    # cannot be consulted, which is the outcome that has to be reported rather than
    # swallowed. Kept in step with WINDOWS_PATTERNS in tests/conformance/selftest_cases.py.
    $windows = [ordered]@{}
    foreach ($pattern in @(
        '$HERMES_HOME/state.db',
        '$CLAUDE_CONFIG_DIR/.credentials.json',
        '$XDG_DATA_HOME/zed/db/0-stable/db.sqlite',
        '${XDG_STATE_HOME:-~/.local/state}/agent/x',
        '~/.hermes/state.db',
        '%APPDATA%\Block\goose\data\sessions\sessions.db',
        '%LOCALAPPDATA%\amazon-q\data.sqlite3',
        '%TEMP%\qlog\*.log',
        '%SystemRoot%\Prefetch\*.pf'
    )) {
        $script:PatternRefusals.Clear()
        $expanded = [System.Collections.Generic.List[string]]::new()
        foreach ($one in (Expand-CataloguePath -Pattern $pattern `
                -ProfileHome '/mnt/img/Users/alice' -TargetOs 'windows' -Root '/mnt/img')) {
            $expanded.Add([string]$one)
        }
        $reasons = [System.Collections.Generic.List[string]]::new()
        foreach ($record in $script:PatternRefusals) {
            $reasons.Add([string]([System.Collections.IDictionary]$record)['reason'])
        }
        $entry = [ordered]@{}
        $entry['patterns'] = $expanded
        $entry['refusals'] = $reasons
        $windows[[string]$pattern] = $entry
    }
    $script:PatternRefusals.Clear()
    $cases['windows_expansion'] = $windows

    # Folder redirection, as fixed inputs rather than as whatever this machine is set to.
    # Kept in step with REDIRECT_CASES in tests/conformance/selftest_cases.py.
    $redirect = [ordered]@{}
    foreach ($case in @(
        @('%APPDATA%\Block\goose\sessions.db', 'C:/Users/alice', '\\server\share\alice\AppData\Roaming'),
        @('%LOCALAPPDATA%\amazon-q\data.sqlite3', 'C:/Users/alice', 'D:\local\'),
        @('%TEMP%\qlog\*.log', 'C:/Users/alice', 'D:/tmp'),
        @('%APPDATA%\Block\goose\sessions.db', 'C:/Users/alice', 'C:/Users/alice/AppData/Roaming'),
        @('%APPDATA%\Block\goose\sessions.db', 'C:/Users/alice', 'C:\Users\Alice\AppData\Roaming'),
        @('%APPDATA%\Block\goose\sessions.db', 'C:/Users/alice', ''),
        @('~/.hermes/state.db', 'C:/Users/alice', 'D:/somewhere')
    )) {
        $key = ('{0} | {1} | {2}' -f $case[0], $case[1], $case[2])
        $redirect[$key] = (Get-WindowsRedirectTarget -Text $case[0] -ProfileHome $case[1] `
            -Value $case[2])
    }
    $cases['windows_redirect'] = $redirect

    # Which claimant wins, which decides the catalogue entry a file is reported under. The
    # ids are chosen so the last key decides and so that a culture-aware comparison would
    # answer differently: a hyphen and an underscore order one way by code point and the
    # other by culture. Kept in step with CLAIM_ORDER_CASES in
    # tests/conformance/selftest_cases.py.
    $claimOrder = [ordered]@{}
    foreach ($case in @(
        @(@('~/.x/y.json', 'claude-code.plans'), @('~/.x/y.json', 'claude_code.plans')),
        @(@('~/.gemini/', 'a.tree'), @('~/.gemini/tmp/<hash>/chats/*.jsonl', 'z.chats')),
        @(@('<project>/.claude/CLAUDE.md', 'a.project'), @('~/.claude/CLAUDE.md', 'z.user')),
        @(@('<plugin-root>/.mcp.json', 'a.plugin'), @('<project>/.mcp.json', 'z.project'))
    )) {
        $best = $null
        $bestKey = $null
        $labels = [System.Collections.Generic.List[string]]::new()
        foreach ($claim in $case) {
            $pattern = [string]$claim[0]
            $artifactId = [string]$claim[1]
            $labels.Add(('{0}|{1}' -f $pattern, $artifactId))
            $key = @(
                -(Get-PatternLiteralLength $pattern),
                -(Get-PatternRootRank $pattern),
                $artifactId
            )
            if ($null -eq $bestKey -or (Compare-ClaimKey $key $bestKey) -lt 0) {
                $best = $artifactId
                $bestKey = $key
            }
        }
        $claimOrder[[string]::Join(' vs ', $labels)] = $best
    }
    $cases['claim_order'] = $claimOrder

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
