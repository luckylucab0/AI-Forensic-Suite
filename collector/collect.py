#!/usr/bin/env python3
"""Collect AI coding agent artifacts from a macOS or Linux endpoint into an evidence bundle.

Single file, standard library only, Python 3.8 or newer. That is not minimalism: it is what
lets this be pushed through EDR live response, a remote shell or a USB stick and run on a
machine where nothing may be installed and nothing may be downloaded. Several agents delete
their own history on a 30 day default schedule, so the difference between collecting today
and scheduling it for next week is evidence.

The format it writes is specified in docs/BUNDLE_FORMAT.md and implemented twice, here and
in collect.ps1 for Windows. Where this file and that document disagree, the document is
right and this is a bug.

Non-negotiable behaviors, each of which has a test:

  * Nothing outside --out is ever written. No temp files, no logs, no config.
  * Nothing on the target is modified, moved, renamed or deleted, and no agent binary is
    executed.
  * Access times are preserved where the platform allows it, and recorded from before the
    read where it does not, so the manifest never reports a time this tool caused.
  * Artifacts marked sensitivity: secret are recorded as metadata and a hash only. Their
    content is copied only with --include-secrets, and that choice goes in the manifest.
  * Collection is ordered by how fast an artifact disappears, not alphabetically.
  * Output is deterministic: two runs over an unchanged tree produce identical manifests
    apart from the fields docs/BUNDLE_FORMAT.md lists as allowed to differ.

Usage:
    python3 collect.py --out /tmp/case-001
    python3 collect.py --out ./bundle --all-users --zip
    python3 collect.py --out ./bundle --root /mnt/image --os macos
    python3 collect.py --dry-run --json
"""

from __future__ import annotations

import argparse
import base64
import errno
import fnmatch
import getpass
import hashlib
import json
import os
import platform
import re
import socket
import stat
import sys
import time
import uuid
import zipfile
from datetime import datetime

TOOL_NAME = "collect.py"
TOOL_VERSION = "0.1.0"
FORMAT_VERSION = 1

# Generous by default: a transcript of a long session runs to tens of megabytes, and a
# skipped transcript is a hole in the evidence. Skipped files are still listed with a
# reason, so the hole is never silent.
DEFAULT_MAX_FILE_SIZE = 256 * 1024 * 1024

EXIT_OK = 0
EXIT_ERRORS = 1
EXIT_USAGE = 2
EXIT_NOTHING_FOUND = 3

# Collection order. live_only artifacts are destroyed by a clean shutdown and cannot be
# recovered from a powered-off image, so they come first however small they are.
PRIORITY_ORDER = ("live_only", "first", "normal", "durable")

# --- BEGIN EMBEDDED CATALOGUE ---
# Rendered from catalog/*.yaml by scripts/build_collectors.py. Do not edit by hand: CI
# regenerates it and fails if this block is stale.
EMBEDDED_CATALOGUE_JSON = r"""
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
                        "$Q_CLI_DATA_DIR/data.sqlite3-shm",
                        "$Q_CLI_DATA_DIR/data.sqlite3-wal",
                        "$XDG_DATA_HOME/amazon-q/data.sqlite3",
                        "$XDG_DATA_HOME/amazon-q/data.sqlite3-shm",
                        "$XDG_DATA_HOME/amazon-q/data.sqlite3-wal",
                        "%LOCALAPPDATA%\\amazon-q\\data.sqlite3",
                        "%LOCALAPPDATA%\\amazon-q\\data.sqlite3-shm",
                        "%LOCALAPPDATA%\\amazon-q\\data.sqlite3-wal",
                        "~/.local/share/amazon-q/data.sqlite3",
                        "~/.local/share/amazon-q/data.sqlite3-shm",
                        "~/.local/share/amazon-q/data.sqlite3-wal",
                        "~/Library/Application Support/amazon-q/data.sqlite3",
                        "~/Library/Application Support/amazon-q/data.sqlite3-shm",
                        "~/Library/Application Support/amazon-q/data.sqlite3-wal"
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
                    "category": "instructions",
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
                    "read_registry": true,
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
                    "category": "instructions",
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
                    "category": "instructions",
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
                    "read_registry": true,
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
                    "category": "instructions",
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
                        "~/.cline/data/db/connectors.db-shm",
                        "~/.cline/data/db/connectors.db-wal",
                        "~/.cline/data/db/cron.db",
                        "~/.cline/data/db/cron.db-shm",
                        "~/.cline/data/db/cron.db-wal",
                        "~/.cline/data/db/tasks.db",
                        "~/.cline/data/db/tasks.db-shm",
                        "~/.cline/data/db/tasks.db-wal"
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
                        "~/.continue/index/autocompleteCache.sqlite-shm",
                        "~/.continue/index/autocompleteCache.sqlite-wal",
                        "~/.continue/index/docs.sqlite",
                        "~/.continue/index/docs.sqlite-shm",
                        "~/.continue/index/docs.sqlite-wal",
                        "~/.continue/index/index.sqlite",
                        "~/.continue/index/index.sqlite-shm",
                        "~/.continue/index/index.sqlite-wal",
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
                        "~/.cursor/ai-tracking/*.db-shm",
                        "~/.cursor/ai-tracking/*.db-wal",
                        "~/.cursor/ai-tracking/ai-code-tracking.db",
                        "~/.cursor/ai-tracking/ai-code-tracking.db-shm",
                        "~/.cursor/ai-tracking/ai-code-tracking.db-wal"
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
                        "$XDG_CONFIG_HOME/cursor/chats/<md5>/<session-uuid>/store.db-shm",
                        "$XDG_CONFIG_HOME/cursor/chats/<md5>/<session-uuid>/store.db-wal",
                        "%USERPROFILE%\\.cursor\\chats\\<md5>\\<session-uuid>\\store.db",
                        "%USERPROFILE%\\.cursor\\chats\\<md5>\\<session-uuid>\\store.db-shm",
                        "%USERPROFILE%\\.cursor\\chats\\<md5>\\<session-uuid>\\store.db-wal",
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
                        "%APPDATA%\\Cursor\\User\\globalStorage\\conversation-search.db-shm",
                        "%APPDATA%\\Cursor\\User\\globalStorage\\conversation-search.db-wal",
                        "~/.config/Cursor/User/globalStorage/conversation-search.db",
                        "~/.config/Cursor/User/globalStorage/conversation-search.db-shm",
                        "~/.config/Cursor/User/globalStorage/conversation-search.db-wal",
                        "~/Library/Application Support/Cursor/User/globalStorage/conversation-search.db",
                        "~/Library/Application Support/Cursor/User/globalStorage/conversation-search.db-shm",
                        "~/Library/Application Support/Cursor/User/globalStorage/conversation-search.db-wal"
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
                        "%APPDATA%\\Cursor\\User\\globalStorage\\state.vscdb-shm",
                        "%APPDATA%\\Cursor\\User\\globalStorage\\state.vscdb-wal",
                        "~/.config/Cursor/User/globalStorage/state.vscdb",
                        "~/.config/Cursor/User/globalStorage/state.vscdb-shm",
                        "~/.config/Cursor/User/globalStorage/state.vscdb-wal",
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
                        "HKCU\\Software\\Classes\\cursor\\shell\\open\\command",
                        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                    ],
                    "root": "registry",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "cursor.install_dirs",
                    "os": [
                        "windows"
                    ],
                    "paths": [
                        "%LOCALAPPDATA%\\Programs\\cursor\\",
                        "%LOCALAPPDATA%\\cursor-updater\\"
                    ],
                    "root": "user_profile",
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
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "cursor.machine_identity_file",
                    "os": [
                        "macos"
                    ],
                    "paths": [
                        "~/Library/Application Support/Cursor/machineid"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "cursor.machine_identity_storage",
                    "os": [
                        "macos"
                    ],
                    "paths": [
                        "~/Library/Application Support/Cursor/User/globalStorage/statsig-cache.json",
                        "~/Library/Application Support/Cursor/User/globalStorage/storage.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "normal",
                    "id": "cursor.macos_preferences",
                    "os": [
                        "macos"
                    ],
                    "paths": [
                        "~/Library/Preferences/com.todesktop.230313mzl4w4u92.plist"
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
                        "%APPDATA%\\Cursor\\User\\workspaceStorage\\<workspace-hash>\\state.vscdb-shm",
                        "%APPDATA%\\Cursor\\User\\workspaceStorage\\<workspace-hash>\\state.vscdb-wal",
                        "~/.config/Cursor/User/workspaceStorage/<workspace-hash>/state.vscdb",
                        "~/.config/Cursor/User/workspaceStorage/<workspace-hash>/state.vscdb-shm",
                        "~/.config/Cursor/User/workspaceStorage/<workspace-hash>/state.vscdb-wal",
                        "~/Library/Application Support/Cursor/User/workspaceStorage/<workspace-hash>/state.vscdb",
                        "~/Library/Application Support/Cursor/User/workspaceStorage/<workspace-hash>/state.vscdb-shm",
                        "~/Library/Application Support/Cursor/User/workspaceStorage/<workspace-hash>/state.vscdb-wal",
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
                        "%USERPROFILE%\\.local\\share\\devin\\cli\\sessions.db-shm",
                        "%USERPROFILE%\\.local\\share\\devin\\cli\\sessions.db-wal",
                        "~/.local/share/devin/cli/sessions.db",
                        "~/.local/share/devin/cli/sessions.db-shm",
                        "~/.local/share/devin/cli/sessions.db-wal",
                        "~/.local/share/devin/cli/transcripts/<session-id>.json",
                        "~/Library/Application Support/devin/cli/sessions.db",
                        "~/Library/Application Support/devin/cli/sessions.db-shm",
                        "~/Library/Application Support/devin/cli/sessions.db-wal",
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
                    "category": "instructions",
                    "collect_priority": "durable",
                    "id": "gemini_cli.agent_definitions",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.agents\\skills\\**",
                        "%USERPROFILE%\\.gemini\\agents\\**",
                        "%USERPROFILE%\\.gemini\\skills\\**",
                        "<project>/.agents/skills/**",
                        "<project>/.gemini/skills/**",
                        "~/.agents/skills/**",
                        "~/.gemini/agents/**",
                        "~/.gemini/skills/**"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
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
                    "category": "instructions",
                    "collect_priority": "durable",
                    "id": "gemini_cli.commands",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.gemini\\commands\\**\\*.toml",
                        "<project>/.gemini/commands/**/*.toml",
                        "~/.gemini/commands/**/*.toml"
                    ],
                    "root": "project",
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
                    "category": "credentials",
                    "collect_priority": "normal",
                    "id": "gemini_cli.mcp_oauth_tokens",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.gemini\\a2a-oauth-tokens.json",
                        "%USERPROFILE%\\.gemini\\mcp-oauth-tokens.json",
                        "~/.gemini/a2a-oauth-tokens.json",
                        "~/.gemini/mcp-oauth-tokens.json"
                    ],
                    "root": "user_profile",
                    "sensitivity": "secret",
                    "status": "verified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "durable",
                    "id": "gemini_cli.policies",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%PROGRAMDATA%\\gemini-cli\\policies\\**",
                        "%USERPROFILE%\\.gemini\\policies\\**",
                        "/Library/Application Support/GeminiCli/policies/**",
                        "/etc/gemini-cli/policies/**",
                        "<project>/.gemini/policies/**",
                        "~/.gemini/policies/**"
                    ],
                    "root": "project",
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
                    "category": "prompt_history",
                    "collect_priority": "normal",
                    "id": "goose.command_history",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%APPDATA%\\Block\\goose\\data\\history.txt",
                        "~/.config/goose/history.txt",
                        "~/.local/state/goose/history.txt"
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
                    "category": "transcript",
                    "collect_priority": "first",
                    "id": "goose.llm_request_logs",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "%APPDATA%\\Block\\goose\\data\\logs\\llm_request.*.jsonl",
                        "~/.local/state/goose/logs/llm_request.*.jsonl"
                    ],
                    "root": "user_profile",
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
                        "~/Library/Application Support/Block/goose/data/sessions/sessions.db",
                        "~/Library/Application Support/Block/goose/data/sessions/sessions.db-shm",
                        "~/Library/Application Support/Block/goose/data/sessions/sessions.db-wal"
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
                        "%APPDATA%\\Block\\goose\\data\\sessions\\sessions.db",
                        "%APPDATA%\\Block\\goose\\data\\sessions\\sessions.db-shm",
                        "%APPDATA%\\Block\\goose\\data\\sessions\\sessions.db-wal"
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
                        "$HERMES_HOME/state.db-shm",
                        "$HERMES_HOME/state.db-wal",
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
                        "<project>/.idea/",
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
                    "category": "instructions",
                    "collect_priority": "durable",
                    "id": "kilo_code.agents",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\.config\\kilo\\agent\\**\\*.md",
                        "<project>/.kilo/agent/**/*.md",
                        "<project>/.kilo/agents/**/*.md",
                        "<project>/.kilocode/agents/**/*.md",
                        "~/.config/kilo/agent/**/*.md"
                    ],
                    "root": "project",
                    "sensitivity": "normal",
                    "status": "verified"
                },
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
                        "%USERPROFILE%\\.local\\share\\kilo\\kilo.db-shm",
                        "%USERPROFILE%\\.local\\share\\kilo\\kilo.db-wal",
                        "~/.local/share/kilo/kilo.db",
                        "~/.local/share/kilo/kilo.db-shm",
                        "~/.local/share/kilo/kilo.db-wal"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "config",
                    "collect_priority": "normal",
                    "id": "kilo_code.config",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "$XDG_CONFIG_HOME/kilo/kilo.jsonc",
                        "%USERPROFILE%\\.config\\kilo\\kilo.jsonc",
                        "<project>/kilo.jsonc",
                        "~/.config/kilo/kilo.jsonc"
                    ],
                    "root": "project",
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
                    "category": "project_instructions",
                    "collect_priority": "durable",
                    "id": "kilo_code.rules",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "<project>/.kilo/rules/**/*.md",
                        "<project>/.kilocode/rules/**/*.md"
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
                        "$KIRO_HOME/*.sqlite3-shm",
                        "$KIRO_HOME/*.sqlite3-wal",
                        "%USERPROFILE%\\.kiro\\*.sqlite3",
                        "%USERPROFILE%\\.kiro\\*.sqlite3-shm",
                        "%USERPROFILE%\\.kiro\\*.sqlite3-wal",
                        "~/.kiro/*.sqlite3",
                        "~/.kiro/*.sqlite3-shm",
                        "~/.kiro/*.sqlite3-wal"
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
                        "~/.ollama/db.sqlite-shm",
                        "~/.ollama/db.sqlite-wal",
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
                    "read_registry": true,
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
                        "$XDG_DATA_HOME/opencode/opencode.db-shm",
                        "$XDG_DATA_HOME/opencode/opencode.db-wal",
                        "%USERPROFILE%\\.local\\share\\opencode\\opencode.db",
                        "%USERPROFILE%\\.local\\share\\opencode\\opencode.db-shm",
                        "%USERPROFILE%\\.local\\share\\opencode\\opencode.db-wal",
                        "~/.local/share/opencode/opencode-*.db",
                        "~/.local/share/opencode/opencode-*.db-shm",
                        "~/.local/share/opencode/opencode-*.db-wal",
                        "~/.local/share/opencode/opencode.db",
                        "~/.local/share/opencode/opencode.db-shm",
                        "~/.local/share/opencode/opencode.db-wal"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "install_evidence",
                    "collect_priority": "durable",
                    "id": "opencode.install_and_runtime_trees",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$XDG_CACHE_HOME/opencode/bin/**",
                        "%USERPROFILE%\\.cache\\opencode\\bin\\**",
                        "~/.cache/opencode/bin/**"
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
                    "category": "instructions",
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
                    "category": "project_instructions",
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
                    "category": "instructions",
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
                },
                {
                    "category": "instructions",
                    "collect_priority": "durable",
                    "id": "qwen_code.workflow_generated_scripts",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\\\.qwen\\\\projects\\\\<sanitized-project-path>\\\\workflows\\\\generated\\\\**",
                        "~/.qwen/projects/<sanitized-project-path>/workflows/generated/**"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "durable",
                    "id": "qwen_code.workflow_run_journals",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\\\.qwen\\\\projects\\\\<sanitized-project-path>\\\\workflows\\\\<run-id>\\\\journal.jsonl",
                        "~/.qwen/projects/<sanitized-project-path>/workflows/<run-id>/journal.jsonl"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                },
                {
                    "category": "log",
                    "collect_priority": "durable",
                    "id": "qwen_code.workflow_run_snapshots",
                    "os": [
                        "macos",
                        "windows",
                        "linux"
                    ],
                    "paths": [
                        "%USERPROFILE%\\\\.qwen\\\\projects\\\\<sanitized-project-path>\\\\workflows\\\\<run-id>.json",
                        "~/.qwen/projects/<sanitized-project-path>/workflows/<run-id>.json"
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
                        "%APPDATA%\\Code\\User\\globalStorage\\state.vscdb-shm",
                        "%APPDATA%\\Code\\User\\globalStorage\\state.vscdb-wal",
                        "~/.config/Code/User/globalStorage/state.vscdb",
                        "~/.config/Code/User/globalStorage/state.vscdb-shm",
                        "~/.config/Code/User/globalStorage/state.vscdb-wal",
                        "~/Library/Application Support/Code/User/globalStorage/state.vscdb",
                        "~/Library/Application Support/Code/User/globalStorage/state.vscdb-shm",
                        "~/Library/Application Support/Code/User/globalStorage/state.vscdb-wal",
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
                        "${XDG_STATE_HOME:-~/.local/state}/warp-terminal/warp.sqlite-shm",
                        "${XDG_STATE_HOME:-~/.local/state}/warp-terminal/warp.sqlite-wal",
                        "%LOCALAPPDATA%\\warp\\Warp\\data\\warp.sqlite",
                        "%LOCALAPPDATA%\\warp\\Warp\\data\\warp.sqlite-shm",
                        "%LOCALAPPDATA%\\warp\\Warp\\data\\warp.sqlite-wal",
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
                        "~/.codeium/windsurf/database/<hash>/embedding_database.sqlite-shm",
                        "~/.codeium/windsurf/database/<hash>/embedding_database.sqlite-wal",
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
                        "HKCU\\Software\\Policies\\Windsurf\\<ProductName>",
                        "HKLM\\Software\\Policies\\Windsurf\\<ProductName>"
                    ],
                    "read_registry": true,
                    "root": "registry",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "normal",
                    "id": "windsurf.enterprise_policy_bundled",
                    "os": [
                        "macos"
                    ],
                    "paths": [
                        "/Applications/Devin.app/Contents/Resources/app/policies"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "normal",
                    "id": "windsurf.enterprise_policy_json",
                    "os": [
                        "linux"
                    ],
                    "paths": [
                        "/etc/windsurf/policies/policy.json"
                    ],
                    "root": "system",
                    "sensitivity": "normal",
                    "status": "unverified"
                },
                {
                    "category": "permissions",
                    "collect_priority": "normal",
                    "id": "windsurf.enterprise_policy_templates",
                    "os": [
                        "windows"
                    ],
                    "paths": [
                        "C:\\Windows\\PolicyDefinitions\\en-US\\windsurf.adml",
                        "C:\\Windows\\PolicyDefinitions\\windsurf.admx"
                    ],
                    "root": "system",
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
                        "%APPDATA%\\Devin\\User\\globalStorage\\state.vscdb-shm",
                        "%APPDATA%\\Devin\\User\\globalStorage\\state.vscdb-wal",
                        "%APPDATA%\\Windsurf - Next\\User\\globalStorage\\state.vscdb",
                        "%APPDATA%\\Windsurf - Next\\User\\globalStorage\\state.vscdb-shm",
                        "%APPDATA%\\Windsurf - Next\\User\\globalStorage\\state.vscdb-wal",
                        "%APPDATA%\\Windsurf Insiders\\User\\globalStorage\\state.vscdb",
                        "%APPDATA%\\Windsurf Insiders\\User\\globalStorage\\state.vscdb-shm",
                        "%APPDATA%\\Windsurf Insiders\\User\\globalStorage\\state.vscdb-wal",
                        "%APPDATA%\\Windsurf\\User\\globalStorage\\state.vscdb",
                        "%APPDATA%\\Windsurf\\User\\globalStorage\\state.vscdb-shm",
                        "%APPDATA%\\Windsurf\\User\\globalStorage\\state.vscdb-wal",
                        "~/.config/Devin/User/globalStorage/state.vscdb",
                        "~/.config/Devin/User/globalStorage/state.vscdb-shm",
                        "~/.config/Devin/User/globalStorage/state.vscdb-wal",
                        "~/.config/Windsurf/User/globalStorage/state.vscdb",
                        "~/.config/Windsurf/User/globalStorage/state.vscdb-shm",
                        "~/.config/Windsurf/User/globalStorage/state.vscdb-wal",
                        "~/Library/Application Support/Devin/User/globalStorage/state.vscdb",
                        "~/Library/Application Support/Devin/User/globalStorage/state.vscdb-shm",
                        "~/Library/Application Support/Devin/User/globalStorage/state.vscdb-wal",
                        "~/Library/Application Support/Windsurf - Next/User/globalStorage/state.vscdb",
                        "~/Library/Application Support/Windsurf - Next/User/globalStorage/state.vscdb-shm",
                        "~/Library/Application Support/Windsurf - Next/User/globalStorage/state.vscdb-wal",
                        "~/Library/Application Support/Windsurf/User/globalStorage/state.vscdb",
                        "~/Library/Application Support/Windsurf/User/globalStorage/state.vscdb-shm",
                        "~/Library/Application Support/Windsurf/User/globalStorage/state.vscdb-wal",
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
                        "%APPDATA%\\Windsurf\\User\\workspaceStorage\\<hash>\\state.vscdb-shm",
                        "%APPDATA%\\Windsurf\\User\\workspaceStorage\\<hash>\\state.vscdb-wal",
                        "~/.config/Windsurf/User/settings.json",
                        "~/.config/Windsurf/User/workspaceStorage/<hash>/state.vscdb",
                        "~/.config/Windsurf/User/workspaceStorage/<hash>/state.vscdb-shm",
                        "~/.config/Windsurf/User/workspaceStorage/<hash>/state.vscdb-wal",
                        "~/Library/Application Support/Windsurf/User/workspaceStorage/<hash>/state.vscdb",
                        "~/Library/Application Support/Windsurf/User/workspaceStorage/<hash>/state.vscdb-shm",
                        "~/Library/Application Support/Windsurf/User/workspaceStorage/<hash>/state.vscdb-wal"
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
                        "~/Library/Application Support/Zed/debug_adapters/",
                        "~/Library/Application Support/Zed/extensions/",
                        "~/.config/zed/prompt_overrides/",
                        "~/Library/Application Support/Zed/external_agents/"
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
                    "category": "instructions",
                    "collect_priority": "durable",
                    "id": "zed.prompt_library",
                    "os": [
                        "macos",
                        "linux",
                        "windows"
                    ],
                    "paths": [
                        "$XDG_DATA_HOME/zed/prompts/",
                        "%LOCALAPPDATA%\\Zed\\prompts\\",
                        "~/.config/zed/prompts/",
                        "~/.local/share/zed/prompts/"
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
                        "$XDG_DATA_HOME/zed/db/0-<release_channel>/db.sqlite-shm",
                        "$XDG_DATA_HOME/zed/db/0-<release_channel>/db.sqlite-wal",
                        "%LOCALAPPDATA%\\Zed\\db\\0-<release_channel>\\db.sqlite",
                        "%LOCALAPPDATA%\\Zed\\db\\0-<release_channel>\\db.sqlite-shm",
                        "%LOCALAPPDATA%\\Zed\\db\\0-<release_channel>\\db.sqlite-wal",
                        "~/Library/Application Support/Zed/db/0-stable/db.sqlite",
                        "~/Library/Application Support/Zed/db/0-stable/db.sqlite-shm",
                        "~/Library/Application Support/Zed/db/0-stable/db.sqlite-wal"
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
                        "$XDG_DATA_HOME/zed/threads/threads.db-shm",
                        "$XDG_DATA_HOME/zed/threads/threads.db-wal",
                        "%LOCALAPPDATA%\\Zed\\threads\\threads.db",
                        "%LOCALAPPDATA%\\Zed\\threads\\threads.db-shm",
                        "%LOCALAPPDATA%\\Zed\\threads\\threads.db-wal",
                        "~/.local/share/zed/threads/threads.db",
                        "~/.local/share/zed/threads/threads.db-shm",
                        "~/.local/share/zed/threads/threads.db-wal",
                        "~/Library/Application Support/Zed/threads/threads.db",
                        "~/Library/Application Support/Zed/threads/threads.db-shm",
                        "~/Library/Application Support/Zed/threads/threads.db-wal"
                    ],
                    "root": "user_profile",
                    "sensitivity": "normal",
                    "status": "verified"
                }
            ]
        }
    ],
    "sha256": "b62061c6c69648d67e098241bc0987172211845137ebe9c88fb6dbe7ecc10d86"
}
"""
EMBEDDED_CATALOGUE = json.loads(EMBEDDED_CATALOGUE_JSON)
# --- END EMBEDDED CATALOGUE ---


# ---------------------------------------------------------------------------- utilities


def utc(seconds: float | None) -> str | None:
    """Format a POSIX timestamp as the bundle's one timestamp format.

    Microseconds are always present and the zone is always UTC, because a manifest that
    sometimes carries them and sometimes not cannot be compared byte for byte. A time the
    platform cannot supply is None, never zero and never the epoch: the epoch is a real
    instant and would read as a genuine 1970 timestamp in a timeline.
    """
    if seconds is None:
        return None
    return datetime.utcfromtimestamp(seconds).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def sha256_file(path: str, preserve_atime: bool) -> tuple[str, int]:
    """Hash a file's bytes, trying not to disturb its access time.

    O_NOATIME only works for a file we own or as root, and only on Linux, so the caller
    also captures atime beforehand and writes that value into the manifest. Between the
    two, the manifest never reports an access time this tool caused.
    """
    # O_BINARY, or nothing else in this function is true. On Windows os.open defaults to
    # text mode and os.read then translates CRLF to LF, so the hash and the byte count
    # described content that is not what is on disk and not what the copy puts in the
    # bundle: every text file in a Windows collection failed its own verification. The
    # flag does not exist on POSIX, where there is no translation to turn off.
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if preserve_atime:
        flags |= getattr(os, "O_NOATIME", 0)
    digest = hashlib.sha256()
    size = 0
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if preserve_atime and exc.errno in (errno.EPERM, errno.EACCES):
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        else:
            raise
    try:
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest(), size


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: object) -> str:
    """Serialize deterministically, so two runs can be compared by hash."""
    return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


# ------------------------------------------------------------------------ path mapping

# Bytes that cannot appear in a path component on at least one supported platform, plus
# the separator itself. See docs/BUNDLE_FORMAT.md, "Path mapping".
_RESERVED_CHARS = set('<>:"|?*\\/')
_RESERVED_NAMES = (
    {"CON", "PRN", "AUX", "NUL"}
    | {"COM%d" % i for i in range(10)}
    | {"LPT%d" % i for i in range(10)}
)


def _pct(char: str) -> str:
    """Percent-encode one character, including one that is not valid UTF-8.

    A filename on Linux is a byte string, so it can hold bytes that are not valid UTF-8.
    Python surfaces those as lone surrogates, and str.encode("utf-8") raises on a
    surrogate. Using surrogateescape here means one oddly named file cannot abort a whole
    collection, which on a compromised endpoint is exactly the file worth having.
    """
    return "".join("%%%02X" % b for b in char.encode("utf-8", "surrogateescape"))


def encode_segment(segment: str) -> str:
    """Make one path component safe on every supported filesystem, reversibly."""
    # '%' first, or the encoding of anything else below would be ambiguous.
    out = []
    for char in segment.replace("%", "\x00"):
        if char == "\x00":
            out.append("%25")
        elif char in _RESERVED_CHARS or ord(char) < 0x20 or 0xD800 <= ord(char) <= 0xDFFF:
            out.append(_pct(char))
        else:
            out.append(char)
    encoded = "".join(out)

    # Windows strips a trailing dot or space from a file name, which would silently change
    # the name and could collide with a sibling.
    if encoded and encoded[-1] in ". ":
        encoded = encoded[:-1] + _pct(encoded[-1])

    # A reserved device name cannot be a file name on Windows at all.
    stem = encoded.split(".", 1)[0].upper()
    if stem in _RESERVED_NAMES:
        encoded = _pct(encoded[0]) + encoded[1:]

    # Over-long components. Not reversible, which is why original_path is mandatory.
    raw = encoded.encode("utf-8", "surrogateescape")
    if len(raw) > 200:
        cut = raw[:190]
        # Do not split a multi-byte character.
        while cut and (cut[-1] & 0xC0) == 0x80:
            cut = cut[:-1]
        tag = sha256_bytes(segment.encode("utf-8", "surrogateescape"))[:10]
        encoded = cut.decode("utf-8", "ignore") + "~" + tag
    return encoded


def bundle_path_for(original: str, used: dict, target_os: str) -> str:
    """Map an original absolute path to its path inside the bundle.

    `used` maps a case-folded bundle path to the original it came from, so a collision
    between two paths that differ only in case can be detected and broken. Without that, a
    case-sensitive source written to a case-insensitive destination silently loses one of
    them.
    """
    if target_os == "windows":
        norm = original.replace("\\", "/")
        if norm.startswith("//"):
            segments = ["UNC"] + [s for s in norm[2:].split("/") if s]
        elif re.match(r"^[A-Za-z]:/", norm):
            segments = [norm[0].upper()] + [s for s in norm[3:].split("/") if s]
        else:
            segments = [s for s in norm.split("/") if s]
    else:
        segments = [s for s in original.split("/") if s]

    encoded = [encode_segment(s) for s in segments]
    candidate = "/".join(encoded)
    folded = candidate.lower()
    if folded in used and used[folded] != original:
        suffix = "~" + sha256_bytes(original.encode("utf-8", "surrogateescape"))[:10]
        encoded[-1] = encoded[-1] + suffix
        candidate = "/".join(encoded)
        folded = candidate.lower()
    used[folded] = original
    return candidate


# ------------------------------------------------------------- placeholder expansion

_XDG_DEFAULTS = {
    "XDG_DATA_HOME": ".local/share",
    "XDG_CONFIG_HOME": ".config",
    "XDG_CACHE_HOME": ".cache",
    "XDG_STATE_HOME": ".local/state",
}

# Variables the operating system owns rather than an agent. On a Windows target these are
# another platform's spelling of the same artifact, the catalogue entry carries a Windows
# sibling for it, and dropping them there is deliberate: that is the cross-platform case the
# comment in expand_paths describes.
#
# An agent's own relocation variable is a different thing and was being treated the same
# way. CLAUDE_CONFIG_DIR, HERMES_HOME, KIRO_HOME and nine more are the same variable on
# every platform, and the Windows branch dropped every pattern rooted at one and recorded no
# refusal: 43 catalogue paths, including a credential store and two session databases. The
# default location was still searched through the entry's `~` sibling, so the failure was
# narrow and completely silent, which is the combination this project exists to prevent.
_POSIX_ONLY_VARIABLES = frozenset(
    {"HOME", "HISTFILE", "ZDOTDIR", "TMPDIR", "XDG_RUNTIME_DIR"}
) | frozenset(_XDG_DEFAULTS)

# The user directory of VS Code and of the forks that inherit its storage layout. A dozen
# agentic extensions keep their conversations under it, so <vscode-user> in the catalogue
# expands to all of these rather than to a wildcard: a wildcard would match one directory
# level and find nothing, which is how an extension's entire history goes missing without
# anyone being told.
#
# The product list is the part that will age. Adding a fork is a one-line change here and
# in the same table in collect.ps1, and an unknown fork simply does not match.
_VSCODE_PRODUCTS = (
    "Code",
    "Code - Insiders",
    "VSCodium",
    "Cursor",
    "Windsurf",
    "Kiro",
    "Trae",
    "Positron",
)

_VSCODE_USER_TEMPLATES = {
    "macos": "Library/Application Support/{product}/User",
    "linux": ".config/{product}/User",
    "windows": "AppData/Roaming/{product}/User",
}

# Windows placeholders, expanded relative to a profile. Used when collecting a mounted
# Windows profile from an analyst workstation with --root and --os windows.
_WIN_PLACEHOLDERS = {
    "%USERPROFILE%": "",
    "%APPDATA%": "AppData/Roaming",
    "%LOCALAPPDATA%": "AppData/Local",
    # Per-user temporary directory. Three agents write their logs here and one writes its
    # chat log here, and without this the patterns were refused as not absolute, so the
    # logs of a crashed or failing agent run were never collected. Windows sets both names
    # to the same place by default; a host that has moved them is why the live value is
    # searched as well when it can be read, which _windows_redirected does.
    "%TEMP%": "AppData/Local/Temp",
    "%TMP%": "AppData/Local/Temp",
}

# Windows placeholders that are machine-wide rather than relative to a profile. Kept apart
# from _WIN_PLACEHOLDERS because they must not be joined to a user's home directory.
#
# The drive is assumed to be C: because the alternative is worse. On a live host the real
# value could be read from the environment, but a mounted image collected with --root has
# no environment to read, and the paths here are the ones that prove an agent binary
# executed at all: Amcache and Prefetch. Getting them from the wrong drive letter costs an
# empty result; not looking at all costs the execution evidence.
_WIN_SYSTEM_PLACEHOLDERS = {
    "%SYSTEMROOT%": "C:/Windows",
    "%WINDIR%": "C:/Windows",
    "%SYSTEMDRIVE%": "C:",
    "%PROGRAMFILES(X86)%": "C:/Program Files (x86)",
    "%PROGRAMFILES%": "C:/Program Files",
    "%PROGRAMDATA%": "C:/ProgramData",
    "%ALLUSERSPROFILE%": "C:/ProgramData",
    "%PUBLIC%": "C:/Users/Public",
}


def target_os_for(system, requested):
    """Which platform's catalogue spellings to search.

    A named target wins: that is what --os is for, and a mounted image is collected from a
    workstation whose own platform says nothing about it.

    Otherwise it comes from this host. "Windows" was missing from this map and the fallback
    was the linux target, so a live run of this collector on a Windows host searched POSIX
    paths, skipped every %APPDATA% one as another platform's spelling, and reported a
    collection that looked clean. collect.ps1 is the collector for Windows and the one that
    belongs in live response, but the wrong answer has to be the one that cannot happen
    rather than the one nobody meant.
    """
    return requested or {"Darwin": "macos", "Windows": "windows"}.get(system, "linux")


def _own_profile(home):
    """Whether this home is the one belonging to the process running the collector.

    The question decides whether this process's environment says anything about the profile
    being collected. It does for its own; for anybody else's it does not, and applying this
    user's variables to another user's profile would attribute one person's files to
    another. Compared case-insensitively because Windows paths are.
    """
    try:
        own = os.path.expanduser("~")
    except Exception:
        return False
    return own.replace("\\", "/").rstrip("/").lower() == home.replace("\\", "/").rstrip("/").lower()


def windows_redirect_target(text, home, value):
    """The extra pattern a placeholder's live value implies, or "". Reads no environment.

    Separate from the lookup so the decision itself can be checked with fixed inputs, on
    both collectors, without either of them depending on the machine it runs on.

    Returns "" when the value is empty, when it is where the default already points, or when
    the text does not start with a placeholder this collector knows.
    """
    if not value:
        return ""
    upper = text.upper()
    for placeholder, relative in _WIN_PLACEHOLDERS.items():
        if not upper.startswith(placeholder):
            continue
        # A UNC value keeps its two leading separators: `\\server\share` is a host and a
        # share, and collapsing it to one produces a path on this machine instead.
        moved = value.replace("\\", "/").rstrip("/")
        base = home.replace("\\", "/").rstrip("/")
        default = "/".join(x for x in (base, relative) if x)
        if moved.lower() == default.lower():
            return ""
        # The tail is normalised here rather than left to the caller, so this function's
        # answer is one spelling of one path and can be compared against the other
        # collector's byte for byte.
        tail = text[len(placeholder) :].lstrip("\\/").replace("\\", "/")
        return "/".join(x for x in (moved, tail) if x)
    return ""


def environment_applies_to(home, root):
    """Whether this process's environment says anything about the profile being collected.

    Not for a mounted image: the analyst workstation's variables are not the endpoint's.

    And not for another user's profile, which is the half this was missing. A collector
    walking every profile on a live host has one environment, its own, so applying this
    user's CLAUDE_CONFIG_DIR to somebody else's profile searches this user's directory and
    files what it finds under that user's name. A wrong answer under somebody's name is
    worse than no answer, so the pattern is refused and reported instead.
    """
    return not root and _own_profile(home)


def _windows_redirected(text, home, root):
    """Where a Windows placeholder actually points, when that is not the default. Or "".

    Folder redirection is ordinary in a managed fleet: %APPDATA% can be a network share and
    %TEMP% can be moved. The documented default under the profile is then an empty
    directory, so a collection finds none of the 134 catalogue paths rooted at one of these
    placeholders and reports nothing wrong, which is the failure this tool exists to
    prevent. Both locations are searched rather than one replacing the other, because the
    default can still hold what was written before the redirection.

    Only for a live host and only for the process's own profile. A mounted image has no
    environment to ask, and another user's profile has one this process cannot see: using
    this user's value there would attribute one person's files to another.
    """
    if not environment_applies_to(home, root):
        return ""
    upper = text.upper()
    for placeholder in _WIN_PLACEHOLDERS:
        if upper.startswith(placeholder):
            return windows_redirect_target(text, home, os.environ.get(placeholder.strip("%")))
    return ""


def variable_name(text):
    """The leading variable's name, or "" when the text does not start with one.

    Both spellings the catalogue uses: `$NAME` and the shell default form `${NAME:-...}`.
    """
    found = re.match(r"^\$\{?([A-Za-z_][A-Za-z0-9_]*)", text)
    return found.group(1) if found else ""


def resolve_env_prefix(text, home, root):
    """Resolve a leading environment variable in a catalogue path.

    Agents relocate their whole data tree with a variable of their own: CLAUDE_CONFIG_DIR,
    CODEX_HOME, HERMES_HOME, OLLAMA_MODELS, ZED_DATA_DIR and a dozen more. The catalogue
    records those spellings precisely so a relocated tree is still found, and leaving them
    unexpanded defeated the point: the pattern was globbed against the process working
    directory, matched nothing, and the bundle looked like a host where the agent had never
    run. That is the one failure this tool must not have.

    Returns (text, outcome). Three outcomes, because the three cases are genuinely
    different and only one of them is a problem:

    'ok'      the variable is set and the path was rewritten.
    'unset'   the variable is not set on this host, so the pattern does not apply. Every
              such entry has a default-location sibling in the same artifact, which is
              already being searched, so this is the cross-platform case again and is not
              worth reporting.
    a reason  the variable could not be consulted at all, which happens when collecting a
              mounted image: the analyst's own environment says nothing about the endpoint
              and reading it would be worse than useless. Reported, so the analyst knows
              to look for the variable in the image's shell profiles by hand.
    """
    # ${VAR:-default} is shell syntax and appears in the catalogue where vendor
    # documentation used it. The default half is what the agent uses when the variable is
    # unset, so it is a real path and not a fallback for our benefit.
    braced = re.match(r"^\$\{([A-Za-z_][A-Za-z0-9_]*):-([^}]*)\}(.*)$", text)
    if braced:
        name, fallback, tail = braced.group(1), braced.group(2), braced.group(3)
        value = os.environ.get(name) if environment_applies_to(home, root) else None
        base = value if value else fallback
        if base.startswith("~"):
            base = home + base[1:]
        return base.rstrip("/") + tail, "ok"

    plain = re.match(r"^\$([A-Za-z_][A-Za-z0-9_]*)(.*)$", text)
    if not plain:
        return text, "malformed_variable"
    name, tail = plain.group(1), plain.group(2)

    mine = environment_applies_to(home, root)
    if name == "HOME":
        return home.rstrip("/") + tail, "ok"
    if name in _XDG_DEFAULTS:
        # Also a literal separator rather than os.path.join, for the reason given at the
        # re-anchoring below: this string is a pattern that every consumer splits on "/".
        # The documented default for a profile whose environment this process cannot speak
        # for, which is every profile but its own. The default is where the agent looks
        # when the variable is unset, so it is a real location rather than a guess.
        base = (os.environ.get(name) if mine else None) or (
            home.rstrip("/") + "/" + _XDG_DEFAULTS[name]
        )
        return base.rstrip("/") + tail, "ok"

    if root:
        # A mounted image. The variable belongs to the endpoint, not to this workstation.
        return text, "environment_unreadable_offline"
    if not mine:
        # Another user's profile on a live host. Their variable is not in this process's
        # environment, and using this one's would search the wrong tree and file the result
        # under their name.
        return text, "environment_unreadable_other_user"
    value = os.environ.get(name)
    if not value:
        return text, "unset"
    # Either separator: a Windows value can end in a backslash, and joining that to a tail
    # that starts with one produces a path no glob matches.
    return value.rstrip("/\\") + tail, "ok"


def _expand_vscode_user(pattern: str, home: str, target_os: str) -> list[str]:
    """Turn one <vscode-user> pattern into one pattern per known product."""
    template = _VSCODE_USER_TEMPLATES.get(target_os)
    if template is None:
        return []
    tail = pattern[len("<vscode-user>") :].lstrip("\\/")
    out = []
    for product in _VSCODE_PRODUCTS:
        base = template.format(product=product)
        out.append("/".join(x for x in (home.rstrip("/"), base, tail) if x))
    return out


# Patterns this run refused to search, with the reason. Module state rather than a return
# value so every call site stays a plain list of patterns, and surfaced in the manifest
# because a pattern the collector declined to follow is a hole in the evidence and has to
# be visible as one. See docs/BUNDLE_FORMAT.md.
PATTERN_REFUSALS = []

# Failures to read an agent's own state file, which is where the list of working copies
# comes from. Surfaced in the manifest's errors for the reason ADR 0009 gives: a record
# that is dropped reads as a record that never existed.
STATE_READ_PROBLEMS = []


# The hive names the catalogue uses, both spellings. A key is recognised before any
# expansion, because nothing here can turn one into a path and every later step would
# make it look more like one.
_REGISTRY_KEY = re.compile(r"^HK(EY_[A-Z_]+|CU|LM|U|CR|CC)[\\/]")


def refuse_pattern(pattern, expanded, reason):
    """Record a refusal once and return the empty result the caller expects."""
    record = {"pattern": pattern, "expanded": expanded, "reason": reason}
    if record not in PATTERN_REFUSALS:
        PATTERN_REFUSALS.append(record)
    return []


def substitute_anchor(pattern: str, anchor: str) -> str:
    """Replace a leading <placeholder> with a discovered working copy, literally.

    Not re.sub. A replacement string in re.sub interprets backslash escapes, and a project
    root on Windows is "C:\\Users\\alice\\src\\app": the \\U is not a valid escape and
    re.sub raises. The collection then died the moment any project root was discovered, on
    the platform most endpoints run, before the manifest had been written.

    Matching and slicing has no such interpretation and cannot fail on the content of a
    path.
    """
    match = re.match(r"^<[^>]+>", pattern)
    if not match:
        return pattern
    return anchor.rstrip("/\\") + pattern[match.end() :]


# Everything a catalogue pattern can hold that is not literal text: a placeholder and a
# wildcard. Stripped to count how much of a pattern claims a name rather than whatever
# happens to be there.
_PATTERN_HOLE = re.compile(r"<[^>]*>|\*")


def root_rank(pattern: str) -> int:
    """How well this collector can say where a pattern's root is. Higher is better.

    Three answers, and the middle one is the reason this is a rank rather than a flag.

      2  a directory this collector can name: `~`, a Windows placeholder, an absolute path.
      1  a working copy, whose location is not in the catalogue but is recorded in the
         agent's own state and substituted here.
      0  a root nothing locates: a plugin or marketplace directory, or a tree relocated by
         a variable.

    The middle and the bottom matter because both are substituted with the same recorded
    working copies. A pattern written for a plugin root and matched at a working copy root
    was matched somewhere it was not written for, so it is the weaker claim: that is what
    made `<project>/.mcp.json` lose to `<plugin-root>/.mcp.json` for a project's own server
    configuration, both spelling the same nine literal characters.
    """
    head = pattern.replace("\\", "/").partition("/")[0]
    if head.startswith("<"):
        return 1 if head in ("<project>", "<repo-root>", "<repo_root>") else 0
    if head.startswith("$"):
        return 0
    return 2


def pattern_specificity(pattern: str) -> tuple[int, int]:
    """How specific one catalogue path is: literal characters, then how known its root is.

    Two catalogue entries can claim the same file, one naming a directory and one naming the
    file, and the manifest reports it under one of them, which is what decides whether a
    parser is found for it. This is that decision. It mirrors the analyzer's rule in
    src/agentforensics/ingest/match.py so a bundle and a directly read tree attribute a file
    the same way: the two disagreeing cost one agent's whole chat transcript, because the
    entry that won had no parser behind it. See ADR 0025.

    The count is over the part below the root, because the root is a placeholder in one
    entry and a literal in another, and counting it would compare two different things.
    That is also why the root needs its own key: `~/.claude/CLAUDE.md` and
    `<project>/.claude/CLAUDE.md` both spell sixteen literal characters and are not the
    same claim, the first naming one directory and the second any directory on the disk.
    """
    text = pattern.replace("\\", "/")
    head, _, tail = text.partition("/")
    if head.startswith(("<", "$")) or head == "~" or (head.startswith("%") and head.endswith("%")):
        body = tail
    else:
        body = text
    literal = 0
    for segment in body.split("/"):
        if segment in ("", "**"):
            continue
        literal += len(_PATTERN_HOLE.sub("", segment))
    return literal, root_rank(pattern)


def claim_order(artifact: dict, pattern: str) -> tuple[int, int, str]:
    """The sort key that picks a file's primary claimant. Most specific first.

    The id is the last key and not the second: deciding which catalogue entry a file belongs
    to by alphabet is deciding it by accident.
    """
    literal, rank = pattern_specificity(pattern)
    return (-literal, -rank, artifact["id"])


def expand_paths(pattern: str, home: str, target_os: str, root: str | None) -> list[str]:
    """Turn one catalogue path pattern into concrete glob patterns on this filesystem.

    An angle-bracket segment is a human-readable placeholder in the catalogue. Here it
    becomes a single-level wildcard, which is always safe: a false match costs a skipped
    entry in the manifest, while treating it literally would collect nothing.

    Anything this function declines to search is recorded in PATTERN_REFUSALS, never
    dropped: a collector that quietly searches nothing produces a clean bundle from a
    host it never looked at.
    """
    # Both of these are a prefix of every pattern this function returns, and a Windows
    # caller hands them over with backslashes: str(Path) does, and so does an operator
    # typing --root D:\image. The collector's own entry point normalises them and this
    # function relied on that, which left it wrong for every other caller. A backslashed
    # root failed the startswith test in the re-anchoring below, so the path was anchored a
    # second time and the profile home appeared twice in it. Normalised here, where the
    # precondition cannot be missed.
    home = as_posix(home)
    if root:
        root = as_posix(root)

    text = pattern
    if text.startswith("<vscode-user>"):
        results = []
        for expanded in _expand_vscode_user(text, home, target_os):
            results.extend(expand_paths(expanded, home, target_os, root))
        return results

    # A catalogue entry lists every operating system's spelling of the same artifact in one
    # paths list, so on any given host most of them do not apply. That is expected and is
    # not a refusal: dropping the other platform's spellings quietly is the whole point of
    # having them in one entry. What must never be quiet is a pattern that applies here and
    # still cannot be resolved, which is what the refusal at the end of this function is
    # for.
    if target_os == "windows":
        if _REGISTRY_KEY.match(text):
            # A registry key on a Windows target is evidence this collector cannot reach.
            # It is not a malformed pattern and it is not another platform's spelling, and
            # it used to be reported as the first: the key fell through to the end of this
            # function, failed the absolute-path test and was refused as `not_absolute`,
            # which tells a reader the catalogue is broken rather than that a whole class
            # of evidence was never collected. Two of these keys are the managed policy
            # that says what an agent was allowed to do, so reading the refusal correctly
            # is the difference between "no policy was in force" and "nobody looked".
            # The file pass cannot search a key, and the four entries the registry pass
            # does read never reach here: they are skipped before expansion so a collected
            # key is not also reported as a refusal. What is left are the registry entries
            # this collector does not read at all, and naming them is the answer for them.
            return refuse_pattern(pattern, text, "registry_key")
        if text.startswith("$"):
            if variable_name(text) in _POSIX_ONLY_VARIABLES:
                # Another platform's spelling of the same artifact. The entry carries a
                # Windows sibling and that one is being searched, so this is the
                # cross-platform case above and not a refusal.
                return []
            # An agent's own relocation variable, which is the same variable here as it is
            # on POSIX, so it is resolved the same way and has the same three outcomes. It
            # used to be dropped with the freedesktop ones: a relocated tree was never
            # searched on a Windows target and nothing said so.
            resolved, outcome = resolve_env_prefix(text, home, root)
            if outcome == "unset":
                return []
            if outcome != "ok":
                return refuse_pattern(pattern, text, outcome)
            text = resolved
        else:
            # Asked before the substitution, while the placeholder is still there.
            redirected = _windows_redirected(text, home, root)
            for placeholder, relative in _WIN_PLACEHOLDERS.items():
                if text.upper().startswith(placeholder):
                    tail = text[len(placeholder) :].lstrip("\\/")
                    text = "/".join(x for x in (home, relative, tail) if x)
                    break
            else:
                upper = text.upper()
                for placeholder, absolute in _WIN_SYSTEM_PLACEHOLDERS.items():
                    if upper.startswith(placeholder):
                        text = absolute + text[len(placeholder) :]
                        break
                if text.startswith("~"):
                    # ~ is the catalogue's ordinary spelling for the user profile and many
                    # entries give no other. Leaving it unexpanded here meant the pattern
                    # was globbed against the process working directory, so on Windows
                    # those artifacts were never found and the manifest reported a clean
                    # host.
                    text = home.rstrip("/") + text[1:]
            if redirected:
                # Two locations, both evidence. Recursed rather than handled here so each
                # one passes the guards at the end of this function: an absolute path
                # matches no placeholder, so the recursion terminates at one level.
                default = expand_paths(text.replace("\\", "/"), home, target_os, root)
                moved = expand_paths(redirected, home, target_os, root)
                return default + moved
        text = text.replace("\\", "/")
    else:
        # `[^%]+` rather than `[A-Za-z_]+`: %PROGRAMFILES(X86)% holds a parenthesis and a
        # digit, so the narrower class did not recognise it as a Windows spelling and the
        # pattern was refused as not absolute instead of skipped as another platform's.
        #
        # The short registry hive names as well as HKEY_. The catalogue uses both spellings,
        # and with only the long one a pattern like `HKCU\Software\...` fell through: under
        # --root it was re-anchored and globbed, so a registry key was searched as a
        # directory under the image root and would have been collected as a file if one
        # happened to be there.
        if re.match(r"^%[^%]+%|^[A-Za-z]:\\|^HK(EY_[A-Z_]+|CU|LM|U|CR|CC)\\", text):
            return []  # a Windows spelling or a registry key, meaningless here
        if text.startswith("$"):
            resolved, outcome = resolve_env_prefix(text, home, root)
            if outcome == "unset":
                return []
            if outcome != "ok":
                return refuse_pattern(pattern, text, outcome)
            text = resolved
        if text.startswith("~"):
            text = home + text[1:]

    text = re.sub(r"<[^>]+>", "*", text)

    if root and not text.startswith(root.rstrip("/") + "/") and text != root.rstrip("/"):
        # Re-anchor under the mounted root, but only when it is not already anchored there.
        #
        # Three kinds of path reach this point and one prefix test handles all of them. A
        # profile-relative path already carries the root, because `home` was discovered
        # inside it. An absolute system path does not. And a project root read out of the
        # agent's own state carries the ORIGINAL machine's absolute path, which also does
        # not exist under the root. Re-anchoring unconditionally double-prefixed the first
        # kind, which made every profile artifact silently fail to match: the collection
        # came back empty and looked like a host with no agents on it.
        #
        # lstrip() takes a character set rather than a prefix, so the drive letter is
        # removed with an explicit match: lstrip("C:/") would also eat a leading 'C' from
        # a directory name.
        relative = re.sub(r"^[A-Za-z]:/", "", text).lstrip("/")
        # Joined with a literal separator, not os.path.join, and the difference is a real
        # failure rather than a preference. os.path.join uses the separator of the machine
        # this collector runs on, so an analyst workstation running Windows produced
        # "/mnt/img\Windows/Prefetch/*.pf" for a machine-wide pattern. Every consumer of
        # this list splits on "/", so iter_matches looked for one segment named
        # "mnt/img\Windows" and found nothing: on a Windows workstation, collecting a
        # mounted image, the wildcarded execution evidence matched nothing and said so
        # nowhere. Found by the collectors' self-test parity case, which is the only check
        # that runs both of them on the platform where they differ.
        text = root.rstrip("/") + "/" + relative

    # A pattern that reduces to a bare wildcard near the top of the tree would collect the
    # whole filesystem under one artifact id. That is not hypothetical: a catalogue entry
    # carried prose in angle brackets, this function turned it into a wildcard, and one
    # artifact swallowed an entire home directory. The schema now rejects such an entry,
    # and this is the second line of defence, because a collector in the field has to fail
    # closed rather than hoover.
    stripped = text.rstrip("/")
    if stripped.endswith("/*") and stripped.count("/") <= 1:
        return refuse_pattern(pattern, text, "wildcard_too_broad")
    if re.sub(r"[*?/]", "", stripped) == "":
        return refuse_pattern(pattern, text, "wildcard_only")

    # A relative pattern would be globbed against the process working directory, which on
    # an analyst workstation is somewhere in the case folder and on an endpoint is wherever
    # the responder happened to be. Both find the wrong thing or nothing, and neither says
    # so. This happens when a placeholder at the start of a path is one the collector does
    # not know: "<agent-home>/config.json" becomes "*/config.json", which is a valid glob
    # and a search of entirely the wrong tree.
    if not (text.startswith("/") or re.match(r"^[A-Za-z]:[/\\]", text)):
        return refuse_pattern(pattern, text, "not_absolute")

    # as_posix after normpath, because normpath returns backslashes on Windows and every
    # consumer of this list splits on "/": iter_matches walks the pattern segment by
    # segment and bundle_path_for maps a path to its place in the bundle the same way. A
    # backslash path would become one enormous percent-encoded segment.
    if "*" in text or "?" in text:
        return [text]
    return [as_posix(os.path.normpath(text))]


# --------------------------------------------------------------------- discovery


def iter_matches(pattern: str) -> list[str]:
    """Expand a glob without following symlinks into directories outside the tree.

    glob.glob would work, but it has surprising behavior with '**' across versions, and
    this needs to be identical in the PowerShell implementation, so the walk is explicit.
    """
    if "*" not in pattern and "?" not in pattern:
        return [as_posix(pattern)] if os.path.lexists(pattern) else []

    parts = pattern.split("/")
    # An absolute pattern starts with an empty first part.
    bases = ["/"] if pattern.startswith("/") else ["."]
    if parts and parts[0] == "":
        parts = parts[1:]
    elif re.match(r"^[A-Za-z]:$", parts[0] if parts else ""):
        bases = [parts[0] + "/"]
        parts = parts[1:]

    for index, part in enumerate(parts):
        nxt = []
        if part == "**":
            for base in bases:
                for dirpath, dirnames, _files in os.walk(base):
                    # Do not descend into symlinked directories: a link out of the profile
                    # would take the collection with it.
                    dirnames[:] = [
                        d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))
                    ]
                    nxt.append(as_posix(dirpath))
        elif "*" in part or "?" in part:
            for base in bases:
                try:
                    entries = sorted(os.listdir(base))
                except OSError:
                    continue
                for name in entries:
                    if fnmatch.fnmatch(name, part):
                        nxt.append(as_posix(os.path.join(base, name)))
        else:
            for base in bases:
                candidate = as_posix(os.path.join(base, part))
                if os.path.lexists(candidate):
                    nxt.append(candidate)
        bases = nxt
        if not bases:
            return []
        is_last = index == len(parts) - 1
        if not is_last:
            bases = [b for b in bases if os.path.isdir(b)]
    return sorted(set(bases))


def format_link_target(target: str) -> str:
    """A link target as the manifest records it: no extended-length prefix, one separator.

    Windows hands back \\\\?\\C:\\... for a link created through the extended-length API,
    which is a Win32 calling convention rather than a fact about where the link points, and
    the two collectors' manifests are compared field by field.
    """
    text = target
    if text.startswith("\\\\?\\UNC\\"):
        text = "\\\\" + text[len("\\\\?\\UNC\\") :]
    elif text.startswith("\\\\?\\"):
        text = text[len("\\\\?\\") :]
    return as_posix(text)


def as_posix(path: str) -> str:
    """One separator convention inside the collector, whatever the platform gave us.

    Every path this collector holds uses forward slashes: patterns are split on "/", the
    bundle path mapping splits on "/", and the absoluteness check below looks for "/". A
    Windows-shaped home or --root arrives with backslashes, and mixing the two meant every
    pattern was refused as not absolute: the run reported 638 unsearched patterns and zero
    hits against a tree full of evidence.

    collect.py is the POSIX collector and collect.ps1 is the Windows one, but a POSIX-style
    path can still be Windows-shaped: an analyst pointing --root at a mounted image from a
    Windows workstation is the case the conformance suite exercises.
    """
    return path.replace("\\", "/")


# Names under a Windows "Users" directory that are not users. Two of them, "All Users" and
# "Default User", are junctions, into ProgramData and into the default profile, so walking
# them collects another tree under a user name nobody has. Keyed on the parent being named
# Users rather than on the running platform, so an image of a Windows host collected from a
# POSIX workstation is treated the same way.
_PSEUDO_PROFILES = frozenset({"public", "default", "default user", "all users", "defaultuser0"})


def live_profile_parents() -> list:
    """The directories this host keeps its user profiles in.

    Windows keeps them on the system drive, and "/Users" is not a path to them. Measured on
    a Windows host: ntpath.isabs("/Users") is False, and ntpath.abspath("/Users") resolved
    it against the working directory's drive, which was D: there. So --all-users looked for
    D:/Users, found nothing, and returned no profiles at all. The flag collected nothing and
    reported nothing, which is worse than a flag that is not there.

    This is about the machine the collector is running on, not about the target platform: a
    mounted image goes through the root branch of discover_users and names its own parents.
    """
    if os.name == "nt":
        # Spelled in capitals for the linter's sake and because that is the convention.
        # Windows' own environment is case-insensitive and os.environ mirrors that there,
        # so the lookup finds the variable however the host spells it.
        drive = (os.environ.get("SYSTEMDRIVE") or "C:").rstrip("/\\")
        return [as_posix(drive) + "/Users"]
    return ["/Users", "/home"]


def _profiles_under(parent: str, skip_pseudo: bool) -> list:
    """The profile directories directly under one parent.

    A profile that is a symbolic link is not followed, because where it points is not known
    to be inside the tree being collected: on a live host it can leave the machine's own
    profile directory, and in a mounted image it can carry the original machine's absolute
    path and land on the analyst's own disk. It is recorded rather than passed over, which
    is the part this was missing. Routing the image branch through this function was meant
    to remove a duplicate loop and it also applied the link check there for the first time,
    so a relocated home in an image went from collected to absent with nothing said. Absent
    and unsearched are different answers and a bundle has to be able to tell them apart.
    """
    found = []
    try:
        names = sorted(os.listdir(parent))
    except OSError:
        return found
    for name in names:
        if skip_pseudo and name.lower() in _PSEUDO_PROFILES:
            continue
        home = os.path.join(parent, name)
        if not os.path.isdir(home):
            continue
        if os.path.islink(home):
            refuse_pattern(as_posix(home), as_posix(home), "profile_is_a_symlink")
            continue
        found.append({"name": name, "home": as_posix(home)})
    return found


def discover_users(root: str | None, all_users: bool, named: list) -> list:
    """Return [{'name', 'home'}] for the profiles to scan."""
    if root:
        # A mounted image or an exported profile. Look for the usual profile parents, and
        # fall back to treating the root itself as one profile.
        #
        # Every home is normalised through as_posix before it leaves this function. It is
        # built with os.path.join, which uses the separator of the machine running the
        # collector, so on a Windows workstation a home came out as "/mnt/img\Users\alice"
        # and that string is the prefix of every pattern for that profile. The Windows
        # target normalises separators later and would have survived it; a POSIX target,
        # which is how a Windows workstation collects a macOS or Linux image, does not.
        found = []
        for parent in ("Users", "home", "root"):
            base = os.path.join(root, parent)
            if not os.path.isdir(base):
                continue
            if parent == "root":
                found.append({"name": "root", "home": as_posix(base)})
                continue
            found.extend(_profiles_under(base, skip_pseudo=parent == "Users"))
        if not found:
            name = os.path.basename(root.rstrip("/")) or "root"
            found = [{"name": name, "home": as_posix(root)}]
        if named:
            found = [u for u in found if u["name"] in named]
        return found

    if all_users:
        found = []
        for parent in live_profile_parents():
            if not os.path.isdir(parent):
                continue
            found.extend(_profiles_under(parent, skip_pseudo=os.path.basename(parent) == "Users"))
        # The superuser's own home, which is not under the profile parent on either POSIX
        # platform. Windows has no equivalent: the administrator's profile is under Users
        # like everybody else's and is already listed above.
        if os.path.isdir("/var/root"):
            found.append({"name": "root", "home": "/var/root"})
        elif os.path.isdir("/root"):
            found.append({"name": "root", "home": "/root"})
        if named:
            found = [u for u in found if u["name"] in named]
        return found

    if named:
        # The same parents --all-users uses. This branch kept the hardcoded POSIX pair when
        # that one was fixed, so `--user alice` on a live Windows host looked under a
        # directory that is not where Windows keeps profiles and found nobody.
        out = []
        for name in named:
            for parent in live_profile_parents():
                home = os.path.join(parent, name)
                if os.path.isdir(home):
                    out.append({"name": name, "home": as_posix(home)})
                    break
        return out

    try:
        who = getpass.getuser()
    except Exception:
        who = os.environ.get("USER") or "unknown"
    return [{"name": who, "home": as_posix(os.path.expanduser("~"))}]


def running_elevated():
    """Whether this process can read another user's profile. None when it cannot be told.

    Three answers rather than two, because "not elevated" and "could not find out" lead to
    different sentences and a collector must not print the first when it means the second.

    hasattr(os, "geteuid") is False on Windows, so the check that guarded this was skipped
    there entirely: an unelevated Windows run walked the profile directory, was refused
    every other user's subtree by the filesystem, and said nothing about why its collection
    was thin.
    """
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return None


def discover_project_roots(home: str) -> list:
    """Find the working copies whose project-anchored artifacts we should collect.

    Project instruction files (CLAUDE.md, .claude/rules and the rest) live inside a user's
    repositories, not under the profile, and they are the prompt-injection surface. They
    cannot be found by expanding a profile, so the agent's own state is read for the list:
    the projects key of ~/.claude.json is authoritative, and the encoded directory names
    under projects/ are a fallback hint. The encoding replaces every non-alphanumeric
    character with a dash and is therefore not reversible, so a decoded name is only used
    when it happens to name a directory that exists.
    """
    roots = []

    def is_dir(path: str) -> bool:
        """os.path.isdir that cannot raise.

        On Windows a path whose syntax is invalid, and a drive colon in the middle of one
        is, raises OSError rather than returning False. These paths come out of an agent's
        own state file, so they are attacker-influenced in the sense that matters: one odd
        entry must not end a collection that has not written its manifest yet.
        """
        try:
            return os.path.isdir(path)
        except (OSError, ValueError):
            return False

    config = os.path.join(home, ".claude.json")
    if os.path.isfile(config):
        try:
            with open(config, "rb") as handle:
                data = json.loads(handle.read().decode("utf-8", "replace"))
            projects = data.get("projects")
            if isinstance(projects, dict):
                for path in sorted(projects):
                    if is_dir(path):
                        roots.append(
                            {"path": as_posix(path), "source": "claude_code.global_config"}
                        )
        except (OSError, ValueError) as exc:
            # Recorded, not swallowed. This file is the authoritative list of the working
            # copies an agent was used in, and the project-anchored artifacts are the
            # prompt-injection surface. Failing to read it silently means the whole of
            # that surface is absent from the bundle with nothing saying why.
            STATE_READ_PROBLEMS.append(
                {
                    "path": as_posix(config),
                    "error": "unparsable_agent_state",
                    "detail": type(exc).__name__ + ": " + str(exc)[:200],
                }
            )

    projects_dir = os.path.join(home, ".claude", "projects")
    if os.path.isdir(projects_dir):
        try:
            for name in sorted(os.listdir(projects_dir)):
                guess = "/" + name.lstrip("-").replace("-", "/")
                if is_dir(guess) and all(r["path"] != guess for r in roots):
                    roots.append({"path": guess, "source": "claude_code.projects_dir_name"})
        except OSError:
            pass
    return roots


# ------------------------------------------------------------------------- collection

# A single glob can match an unbounded number of files, for example a project directory
# with tens of thousands of transcripts. The cap keeps one artifact from consuming a whole
# collection window, and hitting it is recorded as an error rather than passing silently.
DEFAULT_MAX_FILES_PER_ARTIFACT = 20000


def _stat_times(st: os.stat_result) -> dict:
    """Read every timestamp the platform offers, and say null for the ones it does not.

    st_birthtime exists on macOS and on some BSDs, and does not exist on Linux. st_ctime
    means inode change time on Unix and creation time on Windows: the same field name with
    two meanings, which docs/BUNDLE_FORMAT.md documents rather than tries to reconcile.
    """
    birth = getattr(st, "st_birthtime", None)
    return {
        "mtime_utc": utc(st.st_mtime),
        "ctime_utc": utc(st.st_ctime),
        "atime_utc": utc(st.st_atime),
        "birthtime_utc": utc(birth) if birth else None,
    }


def collect_file(
    artifact: dict,
    original: str,
    profile_home: str,
    user_name: str,
    files_dir: str | None,
    used: dict,
    target_os: str,
    args: argparse.Namespace,
    withhold: bool = False,
) -> dict:
    """Collect one file and return its manifest entry.

    Every path out of this function produces an entry. A file that could not be read is
    still described, with a reason, because a collection that silently omits what it could
    not open leaves the analyst unable to tell "absent" from "unreadable".
    """
    entry = {
        "artifact_id": artifact["id"],
        "agent": artifact["id"].split(".", 1)[0],
        "category": artifact["category"],
        "status": artifact.get("status", "unverified"),
        "user": user_name,
        "original_path": original,
        "bundle_path": None,
        "size": None,
        "sha256": None,
        "collected": False,
        "reason": None,
        "symlink": None,
        "reparse_point": False,
        "changed_while_reading": False,
        "mtime_utc": None,
        "ctime_utc": None,
        "atime_utc": None,
        "birthtime_utc": None,
    }

    try:
        st = os.lstat(original)
    except OSError as exc:
        entry["reason"] = "permission_denied" if exc.errno == errno.EACCES else "unreadable"
        return entry

    if stat.S_ISLNK(st.st_mode):
        try:
            target = os.readlink(original)
        except OSError:
            target = None
        entry["symlink"] = format_link_target(target) if target else target
        # A symbolic link is a reparse point on Windows, which is the platform this field
        # is named for. Set here so the value means something and so both collectors agree.
        entry["reparse_point"] = True
        resolved = os.path.realpath(original)
        # A link out of the profile would take the collection somewhere it was never
        # authorized to read. Recorded, not followed.
        if not resolved.startswith(os.path.realpath(profile_home) + os.sep):
            entry["reason"] = "skipped_symlink"
            return entry
        try:
            st = os.stat(original)
        except OSError:
            entry["reason"] = "unreadable"
            return entry

    if not stat.S_ISREG(st.st_mode):
        entry["reason"] = "not_a_file"
        return entry

    entry.update(_stat_times(st))
    entry["size"] = st.st_size

    if st.st_size > args.max_file_size:
        entry["reason"] = "too_large"
        return entry

    if args.dry_run:
        # No read at all: hashing would touch access times and cost the time a dry run
        # exists to save. The entry says what would have happened.
        entry["reason"] = "dry_run"
        return entry

    # Resolved by the caller across every artifact claiming this path, so a credential
    # file caught by a broad directory glob is still withheld.
    secret = withhold and not args.include_secrets

    try:
        digest, read_size = sha256_file(original, preserve_atime=True)
    except OSError as exc:
        entry["reason"] = "permission_denied" if exc.errno == errno.EACCES else "unreadable"
        return entry

    entry["sha256"] = digest
    entry["size"] = read_size

    try:
        after = os.stat(original)
        if after.st_mtime != st.st_mtime or after.st_size != st.st_size:
            entry["changed_while_reading"] = True
    except OSError:
        pass

    if secret:
        # Presence, identity and timestamps are recorded; the bytes are not copied. See
        # SECURITY.md: the tool locates credential material, and copying it by default
        # would make every bundle a liability of its own.
        entry["reason"] = "secret_policy"
        return entry

    if files_dir is None:
        entry["collected"] = True
        return entry

    relative = bundle_path_for(original, used, target_os)
    destination = os.path.join(files_dir, *relative.split("/"))
    # os.path.join is right here: this one is a real path on the collecting machine rather
    # than a value that goes into the manifest.
    try:
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        with open(original, "rb") as src, open(destination, "wb") as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                dst.write(chunk)
        # Carry the original mtime onto the copy, so a bundle extracted on another machine
        # still shows when the evidence was last written.
        os.utime(destination, (st.st_atime, st.st_mtime))
    except OSError as exc:
        entry["reason"] = "permission_denied" if exc.errno == errno.EACCES else "unreadable"
        return entry

    entry["bundle_path"] = "files/" + relative
    entry["collected"] = True
    return entry


def walk_regular_files(base: str, limit: int) -> tuple[list, bool]:
    """List regular files under a directory without following symlinked directories."""
    found = []
    truncated = False
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if not os.path.islink(os.path.join(dirpath, d)))
        for name in sorted(filenames):
            found.append(as_posix(os.path.join(dirpath, name)))
            if len(found) >= limit:
                return found, True
    return found, truncated


# The registry's own type names, by the winreg constant each one has. Written out because a
# document carrying Python's constant name would name a type that does not exist on the
# platform it came from, and because docs/BUNDLE_FORMAT.md and the analyzer promise these.
REGISTRY_TYPE_NAMES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    7: "REG_MULTI_SZ",
    11: "REG_QWORD",
}

# The hive a key name starts with, in both spellings the catalogue uses. Mapped to the
# winreg root rather than to a string, so an unknown head is a key this collector declines
# rather than one it guesses a hive for.
_REGISTRY_HIVES = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKEY_CLASSES_ROOT": "HKEY_CLASSES_ROOT",
    "HKU": "HKEY_USERS",
    "HKEY_USERS": "HKEY_USERS",
}

# The registry stores times as 100 nanosecond intervals since 1601. This is the offset to
# the epoch every other timestamp in a bundle is counted from.
_FILETIME_EPOCH = 11644473600


def read_registry_key(key: str) -> dict:
    """One registry key as the document docs/BUNDLE_FORMAT.md specifies, or None.

    Only four catalogue entries are read this way and which four is decided by
    scripts/build_collectors.py, which marks them in the embedded catalogue and says why
    there. They are the managed policy keys and one relocation key: agent-specific things
    no general purpose registry tool knows to look at.

    Read on the host and never from a mounted image, because a hive file needs a parser
    this suite does not have. Evidence stays read-only: the key is opened for reading and
    nothing is written back.

    This collector records the key's last-write time and the PowerShell one cannot. The
    difference is real and is documented rather than papered over: reaching that time from
    PowerShell 5.1 needs RegQueryInfoKey through P/Invoke, which means compiling code on a
    machine under investigation, and here it is one stdlib call.
    """
    try:
        # Windows only, and this function is the only caller.
        import winreg
    except ImportError:
        return None

    normalised = key.replace("/", "\\")
    at = normalised.find("\\")
    if at < 1:
        return None
    hive = _REGISTRY_HIVES.get(normalised[:at].upper())
    if hive is None:
        return None
    try:
        handle = winreg.OpenKey(getattr(winreg, hive), normalised[at + 1 :], 0, winreg.KEY_READ)
    except OSError:
        return None

    try:
        subkey_count, value_count, written = winreg.QueryInfoKey(handle)
        values = []
        for index in range(value_count):
            name, data, kind = winreg.EnumValue(handle, index)
            entry = {"name": name, "type": REGISTRY_TYPE_NAMES.get(kind, "REG_UNKNOWN")}
            if kind == winreg.REG_BINARY:
                # Bytes put through a text encoding stop being the bytes that were there.
                entry["data_base64"] = base64.b64encode(bytes(data)).decode("ascii")
            elif kind == winreg.REG_MULTI_SZ:
                entry["data"] = [str(one) for one in data]
            elif kind in (winreg.REG_DWORD, winreg.REG_QWORD):
                entry["data"] = int(data)
            else:
                entry["data"] = str(data)
            values.append(entry)
        subkeys = [winreg.EnumKey(handle, index) for index in range(subkey_count)]
    except OSError:
        return None
    finally:
        winreg.CloseKey(handle)

    values.sort(key=lambda entry: entry["name"])
    subkeys.sort()
    return {
        "format_version": FORMAT_VERSION,
        "key": key,
        "last_write_utc": utc(written / 10000000.0 - _FILETIME_EPOCH),
        "subkeys": subkeys,
        "values": values,
    }


def collect_registry_keys(entries: list, files_dir: str, root: str, dry_run: bool) -> None:
    """Read every catalogue key marked for it and append one manifest entry each.

    A key that is not there gets an entry with collected false and no document, the same
    shape a missing file gets. That distinction is the point for a policy key: an empty
    document means the policy was not set, a missing one means the key was never created,
    and both are different from nobody having looked.
    """
    for agent in EMBEDDED_CATALOGUE.get("agents", []):
        for artifact in agent.get("artifacts", []):
            if not artifact.get("read_registry"):
                continue
            for key in artifact.get("paths", []):
                entry = {
                    "agent": agent["agent"],
                    "artifact_id": artifact["id"],
                    "bundle_path": None,
                    "category": artifact.get("category"),
                    "collected": False,
                    "mtime_utc": None,
                    "original_path": key,
                    "reason": "not_present",
                    "sha256": None,
                    "size": None,
                    "source_kind": "registry",
                    "status": artifact.get("status"),
                    "user": _current_user(),
                }
                document = None if root else read_registry_key(key)
                if document is None:
                    # Said rather than left as a plain absence: a mounted image and a
                    # non-Windows host both have no live registry, and an entry that looked
                    # the same as an absent key would read as a policy that was not set.
                    if root or os.name != "nt":
                        entry["reason"] = "registry_needs_a_live_host"
                    entries.append(entry)
                    continue
                text = canonical_json(document)
                data = text.encode("utf-8")
                relative = "registry/" + key.replace("\\", "/") + ".json"
                entry["bundle_path"] = "files/" + relative
                entry["collected"] = True
                entry["mtime_utc"] = document["last_write_utc"]
                entry["reason"] = None
                entry["sha256"] = sha256_bytes(data)
                entry["size"] = len(data)
                if not dry_run:
                    destination = os.path.join(files_dir, *relative.split("/"))
                    os.makedirs(os.path.dirname(destination), exist_ok=True)
                    # O_BINARY, for the reason write_text_file gives at length: on Windows
                    # os.open defaults to text mode, the bytes on disk would then differ
                    # from the bytes that were hashed, and the bundle would fail its own
                    # verification in the way tampering looks.
                    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
                    with os.fdopen(os.open(destination, flags), "wb") as handle:
                        handle.write(data)
                entries.append(entry)


def run(args: argparse.Namespace) -> dict:
    """Collect everything the catalogue describes for this platform."""
    started = time.time()
    target_os = target_os_for(platform.system(), args.os)

    artifacts = []
    for agent in EMBEDDED_CATALOGUE.get("agents", []):
        if args.agents and agent["agent"] not in args.agents:
            continue
        for artifact in agent.get("artifacts", []):
            if target_os in artifact.get("os", []):
                artifacts.append(artifact)
    # Most volatile first, then by id so two runs queue the same work in the same order.
    artifacts.sort(
        key=lambda a: (PRIORITY_ORDER.index(a.get("collect_priority", "normal")), a["id"])
    )

    users = discover_users(args.root, args.all_users, args.user or [])
    for user in users:
        user["home"] = as_posix(user["home"])
    files_dir = None
    if not args.dry_run:
        files_dir = os.path.join(args.out, "files")
        os.makedirs(files_dir, exist_ok=True)

    root_prefix = as_posix(args.root) if args.root else None

    entries: list = []
    errors: list = []
    project_roots: list = []
    # A run that found no profile at all collects nothing, and an empty bundle has to say
    # why it is empty. Without this it was indistinguishable from a host with no user data
    # on it, which is the one answer this tool must never give by accident. The two ways to
    # get here are a --all-users run on a platform whose profile parent this collector had
    # wrong, which is how the Windows case went unnoticed, and a --user naming somebody who
    # is not on this host.
    if not users:
        asked = "--all-users" if args.all_users else ("--user " + ", ".join(args.user or []))
        where = ", ".join(live_profile_parents()) if not args.root else args.root
        errors.append(
            {
                "path": where,
                "error": "no_profiles_found",
                "detail": "%s matched no user profile under %s, so nothing was searched"
                % (asked if asked.strip() else "this run", where),
            }
        )
        sys.stderr.write(
            "%s: no user profile was found under %s. Nothing was searched, and the "
            "manifest records that as an error rather than as an empty host.\n" % (TOOL_NAME, where)
        )
    used: dict = {}
    # Paths already decided, so a second user's glob cannot re-collect a shared file and a
    # scan over the growing entry list is not needed for every candidate.
    seen_paths = set()

    for user in users:
        home = user["home"]
        if not os.path.isdir(home):
            user["collected"] = False
            user["reason"] = "unreadable"
            continue
        user["collected"] = True
        roots = discover_project_roots(home)
        for root in roots:
            if all(r["path"] != root["path"] for r in project_roots):
                project_roots.append(root)

        # Two passes, not one.
        #
        # A single file is often claimed by more than one artifact: a broad directory glob
        # and a specific entry for one file inside it. Deciding as each match is found
        # means whichever artifact the loop reaches first decides whether the bytes get
        # copied, and that was a real protective failure rather than a theoretical one. A
        # JetBrains directory glob marked normal matches the c.kdbx password database,
        # which the catalogue marks secret, so the credential store would have been copied
        # or withheld depending on iteration order. Resolving every claim on a path before
        # deciding makes "secret wins" a property of the file instead.
        matches = {}
        for artifact in artifacts:
            if artifact.get("read_registry"):
                # Collected by the registry pass instead, so expanding its patterns here
                # would refuse each key as unsearchable and put a refusal in the manifest
                # next to the entry that carries the key's contents. The registry keys
                # this collector does not read still go through the expander and are
                # refused by name, which is the answer for them.
                continue
            is_project = artifact.get("root") in ("project", "repo_root", "plugin")
            anchors = [home]
            if is_project:
                anchors = [r["path"] for r in roots]
                if not anchors:
                    continue
            for anchor in anchors:
                for pattern in artifact["paths"]:
                    concrete = substitute_anchor(pattern, anchor) if is_project else pattern
                    for expanded in expand_paths(concrete, home, target_os, root_prefix):
                        for match in iter_matches(expanded):
                            targets = [match]
                            if os.path.isdir(match) and not os.path.islink(match):
                                targets, truncated = walk_regular_files(
                                    match, args.max_files_per_artifact
                                )
                                if truncated:
                                    errors.append(
                                        {
                                            "path": match,
                                            "error": "too_many_files",
                                            "detail": "stopped after %d files; raise "
                                            "--max-files-per-artifact"
                                            % args.max_files_per_artifact,
                                        }
                                    )
                            for target in targets:
                                # The catalogue pattern travels with the claim, because a
                                # claim's specificity is a property of the pattern that
                                # matched and not of the entry that holds it.
                                matches.setdefault(target, []).append((artifact, pattern))

        for target in sorted(matches):
            if target in seen_paths:
                continue
            seen_paths.add(target)
            claimants = matches[target]
            # Attributed to the most specific claim, so a file is reported under the entry
            # that names it rather than under a directory glob that happened to include it.
            #
            # This was the artifact with the fewest path patterns, which is a proxy and the
            # wrong way round: an entry holding one broad glob over a directory has fewer
            # patterns than an entry whose pattern names the file. A chat transcript was
            # therefore attributed to the home tree containing it and reported with category
            # config, while the analyzer, which ranks by the pattern, disagreed. See
            # pattern_specificity and ADR 0025.
            primary = sorted(claimants, key=lambda c: claim_order(c[0], c[1]))[0][0]
            withhold = any(a.get("sensitivity") == "secret" for a, _ in claimants)
            entry = collect_file(
                primary,
                target,
                home,
                user["name"],
                files_dir,
                used,
                target_os,
                args,
                withhold,
            )
            # One artifact can claim the same path through two of its own patterns, which
            # is not a second claim and must not produce a one-element list.
            claimant_ids = sorted({a["id"] for a, _ in claimants})
            if len(claimant_ids) > 1:
                entry["artifact_ids"] = claimant_ids
            entries.append(entry)
            if entry["reason"] in ("permission_denied", "unreadable"):
                errors.append(
                    {
                        "path": target,
                        "error": entry["reason"],
                        "detail": entry["artifact_id"],
                    }
                )
    # The registry pass, once per collection rather than once per profile: a machine key
    # is not a property of a user, and the user hive this reads is the collecting account's
    # own. It runs only on a live host, and with --root it records that instead.
    if target_os == "windows":
        collect_registry_keys(entries, files_dir, args.root, args.dry_run)

    errors.extend(STATE_READ_PROBLEMS)
    entries.sort(key=lambda e: (e["artifact_id"], e["original_path"]))

    offset = time.strftime("%z")
    manifest = {
        "format_version": FORMAT_VERSION,
        "tool": {
            "name": TOOL_NAME,
            "version": TOOL_VERSION,
            "sha256": tool_sha256(),
            "catalogue_version": EMBEDDED_CATALOGUE.get("sha256", ""),
        },
        "collection": {
            "uuid": str(uuid.uuid4()),
            "started_utc": utc(started),
            "finished_utc": utc(time.time()),
            "local_timezone": (offset[:3] + ":" + offset[3:]) if offset else None,
            "local_timezone_name": time.tzname[time.daylight and time.localtime().tm_isdst > 0],
            "hostname": socket.gethostname(),
            "os": target_os,
            "os_version": platform.release(),
            "architecture": platform.machine(),
            "collector_user": _current_user(),
            # running_elevated, not a geteuid test: hasattr(os, "geteuid") is False on
            # Windows, so the custody record said this run was not elevated on every
            # Windows collection whether it was or not. It answers None where it cannot
            # tell, which is a third thing and not the same as false.
            "elevated": running_elevated(),
            "argv": [os.path.basename(sys.argv[0]), *sys.argv[1:]],
            "include_secrets": bool(args.include_secrets),
            "max_file_size": args.max_file_size,
            "root": args.root,
            "agents_filter": sorted(args.agents) if args.agents else None,
        },
        "users": users,
        "project_roots": sorted(project_roots, key=lambda r: r["path"]),
        "files": entries,
        "counts": {
            "hit": len(entries),
            "collected": sum(1 for e in entries if e["collected"]),
            "skipped": sum(1 for e in entries if not e["collected"]),
            "errors": len(errors),
            "refused_patterns": len(PATTERN_REFUSALS),
        },
        "errors": sorted(errors, key=lambda e: (e["path"], e["error"])),
        # A pattern the collector declined to search is a hole in the coverage, so it is
        # reported next to the errors rather than left implicit in an absent file entry.
        "refused_patterns": sorted(PATTERN_REFUSALS, key=lambda r: (r["pattern"], r["reason"])),
    }
    return manifest


def _current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER") or "unknown"


def tool_sha256() -> str:
    """Hash this file as it ran, so a bundle can be tied to the exact collector build."""
    try:
        with open(os.path.abspath(__file__), "rb") as handle:
            return sha256_bytes(handle.read())
    except OSError:
        return ""


# --------------------------------------------------------------------- bundle writing


def custody_record(seq: int, event: str, manifest_sha: str, prev_sha: str | None, **extra) -> dict:
    """Build one hash-chained custody record.

    Each record commits to the previous one, so removing or editing a single record breaks
    the chain at a detectable point. This is tamper-evident, not tamper-proof: anyone who
    can write the file can rewrite the whole chain. See docs/BUNDLE_FORMAT.md.
    """
    record = {
        "seq": seq,
        "event": event,
        "time_utc": utc(time.time()),
        "actor": _current_user(),
        "host": socket.gethostname(),
        "tool": "%s %s" % (TOOL_NAME, TOOL_VERSION),
        "manifest_sha256": manifest_sha,
        "prev_sha256": prev_sha,
    }
    record.update(extra)
    record["sha256"] = sha256_bytes(
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return record


def write_text_file(path: str, text: str) -> None:
    """Write text as UTF-8 with no newline translation, on every platform.

    open(path, "w") uses the platform's default encoding and translates "\n" to the
    platform's line ending. Both are wrong here and the second is worse than wrong: the
    custody record commits to the SHA-256 of the manifest, that hash is computed over the
    text, and on Windows the file on disk then had different bytes than the ones hashed.
    Every bundle written on Windows failed its own verification with "the chain describes a
    different manifest than the one in this bundle", which is what tampering looks like.

    collect.ps1 has always written through WriteAllText with an explicit encoding, which is
    why the differential test caught this: two implementations of one format disagreeing is
    the signal the second implementation exists to give.
    """
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(text)


def write_bundle(out: str, manifest: dict) -> str:
    manifest_text = canonical_json(manifest)
    manifest_sha = sha256_bytes(manifest_text.encode("utf-8"))
    write_text_file(os.path.join(out, "manifest.json"), manifest_text)
    record = custody_record(0, "collected", manifest_sha, None)
    write_text_file(
        os.path.join(out, "chain_of_custody.jsonl"),
        json.dumps(record, sort_keys=True) + "\n",
    )
    return manifest_sha


# Fixed timestamp for the two metadata files inside the zip. The zip format cannot store
# anything before 1980, and using the collection time would make two zips over an
# unchanged tree differ in more places than their content.
ZIP_METADATA_TIME = (1980, 1, 1, 0, 0, 0)


def write_zip(out: str, manifest: dict) -> str:
    """Pack the bundle, in manifest order, and write a .sha256 sidecar beside it."""
    archive = out.rstrip(os.sep) + ".zip"
    base = os.path.basename(out.rstrip(os.sep))
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in ("manifest.json", "chain_of_custody.jsonl"):
            info = zipfile.ZipInfo(base + "/" + name, ZIP_METADATA_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(os.path.join(out, name), "rb") as handle:
                zf.writestr(info, handle.read())
        for entry in manifest["files"]:
            if not entry.get("bundle_path"):
                continue
            source = os.path.join(out, *entry["bundle_path"].split("/"))
            if not os.path.isfile(source):
                continue
            st = os.stat(source)
            info = zipfile.ZipInfo(
                base + "/" + entry["bundle_path"], time.localtime(st.st_mtime)[:6]
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(source, "rb") as handle:
                zf.writestr(info, handle.read())
    with open(archive, "rb") as handle:
        digest = sha256_bytes(handle.read())
    write_text_file(archive + ".sha256", "%s  %s\n" % (digest, os.path.basename(archive)))
    return archive


# ------------------------------------------------------------------------------- CLI


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=__doc__.strip().splitlines()[0],
        epilog="Use requires proper authorization. Exit codes: 0 collected, 1 collected "
        "with errors, 2 could not run, 3 nothing found.",
    )
    parser.add_argument("--out", help="bundle directory to create. Required unless --dry-run")
    parser.add_argument("--zip", action="store_true", help="also write <out>.zip and a .sha256")
    parser.add_argument("--user", action="append", metavar="NAME", help="repeatable")
    parser.add_argument(
        "--all-users",
        action="store_true",
        help="scan every profile. Needs elevation, which is recorded in the manifest",
    )
    parser.add_argument("--agents", action="append", metavar="KEY", help="repeatable")
    parser.add_argument(
        "--include-secrets",
        action="store_true",
        help="copy the content of credential artifacts too. Off by default: their "
        "presence, hash and timestamps are recorded without copying the material",
    )
    parser.add_argument("--max-file-size", type=int, default=DEFAULT_MAX_FILE_SIZE)
    parser.add_argument(
        "--max-files-per-artifact", type=int, default=DEFAULT_MAX_FILES_PER_ARTIFACT
    )
    parser.add_argument(
        "--root", metavar="PATH", help="collect from a mounted image or an exported profile"
    )
    parser.add_argument(
        "--os",
        choices=("macos", "linux", "windows"),
        help="target platform, for use with --root when it differs from this machine",
    )
    parser.add_argument("--dry-run", action="store_true", help="list what would be collected")
    parser.add_argument("--json", action="store_true", help="machine-readable summary on stdout")
    parser.add_argument("--version", action="version", version="%s %s" % (TOOL_NAME, TOOL_VERSION))
    return parser


def main(argv: list | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not EMBEDDED_CATALOGUE.get("agents"):
        sys.stderr.write(
            "%s: the embedded catalogue is empty. This file was not built by "
            "scripts/build_collectors.py.\n" % TOOL_NAME
        )
        return EXIT_USAGE

    if not args.dry_run:
        if not args.out:
            parser.error("--out is required unless --dry-run is given")
        try:
            os.makedirs(args.out, exist_ok=True)
        except OSError as exc:
            sys.stderr.write("%s: cannot create %s: %s\n" % (TOOL_NAME, args.out, exc))
            return EXIT_USAGE
        if os.listdir(args.out):
            sys.stderr.write(
                "%s: %s is not empty. Refusing to write into an existing bundle, because "
                "mixing two collections makes both unusable as evidence.\n" % (TOOL_NAME, args.out)
            )
            return EXIT_USAGE

    if args.all_users:
        elevated = running_elevated()
        if elevated is False:
            sys.stderr.write(
                "%s: --all-users without elevation will miss other users' profiles. "
                "Continuing, and recording that this run was not elevated.\n" % TOOL_NAME
            )
        elif elevated is None:
            sys.stderr.write(
                "%s: --all-users, and whether this process is elevated could not be "
                "determined. If it is not, other users' profiles will be missing from the "
                "collection without an error against them.\n" % TOOL_NAME
            )

    manifest = run(args)

    if not args.dry_run:
        write_bundle(args.out, manifest)
        if args.zip:
            write_zip(args.out, manifest)

    summary = {
        "bundle": None if args.dry_run else os.path.abspath(args.out),
        "dry_run": bool(args.dry_run),
        "users": [u["name"] for u in manifest["users"]],
        "project_roots": [r["path"] for r in manifest["project_roots"]],
        "counts": manifest["counts"],
        "by_priority": {},
    }
    priorities = {}
    for agent in EMBEDDED_CATALOGUE.get("agents", []):
        for artifact in agent.get("artifacts", []):
            priorities[artifact["id"]] = artifact.get("collect_priority", "normal")
    for entry in manifest["files"]:
        key = priorities.get(entry["artifact_id"], "normal")
        bucket = summary["by_priority"].setdefault(key, {"hit": 0, "collected": 0})
        bucket["hit"] += 1
        bucket["collected"] += 1 if entry["collected"] else 0

    if args.json:
        sys.stdout.write(json.dumps(summary, sort_keys=True, indent=2) + "\n")
    else:
        counts = manifest["counts"]
        sys.stderr.write(
            "%s: %d hit, %d collected, %d skipped, %d error(s)\n"
            % (TOOL_NAME, counts["hit"], counts["collected"], counts["skipped"], counts["errors"])
        )
        for priority in PRIORITY_ORDER:
            bucket = summary["by_priority"].get(priority)
            if bucket:
                sys.stderr.write("  %-10s %d/%d\n" % (priority, bucket["collected"], bucket["hit"]))
        # Said on the terminal, not only in the manifest. An analyst who reads the summary
        # line and nothing else would otherwise take a clean run as full coverage, when
        # some of the catalogue could not be resolved on this host.
        if counts.get("refused_patterns"):
            sys.stderr.write(
                "  %d pattern(s) not searched, see refused_patterns in the manifest\n"
                % counts["refused_patterns"]
            )
        if not args.dry_run:
            sys.stderr.write("  bundle: %s\n" % os.path.abspath(args.out))

    if manifest["counts"]["hit"] == 0:
        # Distinct from failure on purpose: a host with no agent artifacts is a valid and
        # useful result, and a fleet sweep that cannot tell the two apart draws a wrong
        # picture of where agents are in use.
        return EXIT_NOTHING_FOUND
    if manifest["counts"]["errors"]:
        return EXIT_ERRORS
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
