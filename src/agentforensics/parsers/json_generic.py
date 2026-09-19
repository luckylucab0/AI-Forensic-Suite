"""Read a whole JSON document the suite has no verified shape for, without inventing one.

The first of the whole-document readers, and the one that needed a decision rather than
just a rule. See ADR 0027. The reading itself now lives in `structured_generic`, because
the same decision answers the same question for YAML and for TOML, and three copies of it
would drift; what stays here is which artifacts are JSON, which of them are configurations,
and how a JSON file is turned into a value. See ADR 0028.

The other two are handed their own records: a SQLite store has rows and a line-delimited
log has lines, so the honest floor under both is "return each one, read nothing out of it
but what it literally says". A whole JSON document has no records. It has a value, and
where the records are inside it is a question about what the document means. A reader that
went hunting for the array that is probably the conversation, by trying keys named
`messages`, `items` or `conversation`, would be right for most agents and quietly wrong for
the rest, and it is the wrong ones an investigation turns on.

So this module splits by structure, which is checkable against the bytes, and never by
meaning:

- a root that is a list is one event per element, at `$[n]`
- a root that is an object is one event for the document, then one event per element of
  each **top-level** key whose value is a list of objects, at `$.key[n]`
- anything else is one event, at `$`

One level deep and no further. A document that nests its records under another object keeps
them in the document event, whole and searchable, because descending to find them means
deciding which branch holds the records. That is visibly a partial reading rather than a
wrong one, and it is the shape that justifies writing a verified parser for that agent.

From a record it reads only what the record literally names, in the same field names and
the same order as `jsonl_generic`, so the two agree about an unmapped record, and every
event says on itself that nobody has read this format.
"""

from __future__ import annotations

from collections.abc import Iterator

from agentforensics.model import Event, unparsed
from agentforensics.parsers.base import ParseContext, read_json
from agentforensics.parsers.structured_generic import (
    NOT_SPLIT,
    SPLIT_LIMIT,
    UNINTERPRETED,
    documents,
)

# Every JSON artifact in the catalogue except the credential stores, written out rather
# than derived from the format field at runtime, for the reason `sqlite_generic.STORES` is
# written out: a parser is handed an artifact id and not a catalogue entry, and a document
# added to the catalogue should be read because somebody decided it should be.
# tests/unit/test_json_generic.py asserts that this set is exactly the catalogue's
# non-secret JSON artifacts, so adding one there fails CI until it is listed here.
#
# The credential stores are left out on purpose and it is a narrowing of what is read, not
# of what is kept: the collector does not copy their content by default, the file and its
# hash are in the case either way, and a token in the payload of a timeline event is not
# what `--include-secrets` was for.
DOCUMENTS = frozenset(
    {
        "aider.analytics",
        "aider.caches",
        "aider.model_metadata",
        "amazonq.cli_agents",
        "amazonq.cli_mcp_config",
        "amazonq.cli_settings",
        "amazonq.cli_todo_lists",
        "amazonq.ide_agent_config",
        "amazonq.ide_chat_history",
        "amazonq.knowledge_bases",
        "amazonq.legacy_profiles_and_context",
        "amp.continuations",
        "amp.session_pointer",
        "amp.settings",
        "amp.threads",
        "claude_code.anthropic_profile_configs",
        "claude_code.config_backups",
        "claude_code.daemon_state",
        "claude_code.feedback_drafts",
        "claude_code.global_config",
        "claude_code.jobs",
        "claude_code.keybindings",
        "claude_code.known_marketplaces",
        "claude_code.legacy_dirs",
        "claude_code.legacy_state_dirs",
        "claude_code.managed_mcp_json",
        "claude_code.managed_settings_dropins",
        "claude_code.managed_settings_file",
        "claude_code.org_policy_cache",
        "claude_code.plugin_cache",
        "claude_code.plugin_manifests",
        "claude_code.plugin_marketplaces_clones",
        "claude_code.plugins_root",
        "claude_code.plugins_synced",
        "claude_code.policy_limits",
        "claude_code.project_mcp_json",
        "claude_code.project_settings",
        "claude_code.project_settings_local",
        "claude_code.session_env",
        "claude_code.sessions_dir",
        "claude_code.stats_cache",
        "claude_code.task_lists",
        "claude_code.themes",
        "claude_code.user_settings",
        "claude_code.user_settings_local",
        "claude_desktop.code_launch_config",
        "claude_desktop.code_session_index",
        "claude_desktop.cowork_account_settings",
        "claude_desktop.local_config_library",
        "claude_desktop.managed_policy_linux",
        "claude_desktop.mcp_config",
        "cline.agent_schedules",
        "cline.cache_and_remote_config",
        "cline.cli_sessions",
        "cline.data_tasks",
        "cline.global_settings",
        "cline.global_state_json",
        "cline.mcp_settings",
        "cline.team_data",
        "cline.vscode_task_transcripts",
        "continue.sessions",
        "copilot.command_history",
        "copilot.config_json",
        "copilot.lsp_config",
        "copilot.lsp_config_repo",
        "copilot.mcp_config",
        "copilot.mcp_config_jetbrains",
        "copilot.permissions",
        "copilot.providers",
        "copilot.settings",
        "crosscutting.mcp_config_files",
        "crosscutting.npm_global_install_dirs",
        "crosscutting.npm_npx_cache",
        "crosscutting.pipx_home_and_bin",
        "cursor.agent_cli_state",
        "cursor.chat_session_meta_json",
        "cursor.chat_session_prompt_history",
        "cursor.cli_config",
        "cursor.commit_checkpoints",
        "cursor.extensions",
        "cursor.global_prompt_history",
        "cursor.hooks",
        "cursor.local_file_history",
        "cursor.mcp_config",
        "cursor.pasted_text",
        "cursor.plugins",
        "cursor.project_metadata",
        "factory_droid.auth",
        "factory_droid.config",
        "factory_droid.mcp_and_hooks",
        "gemini_cli.chats",
        "gemini_cli.google_accounts",
        "gemini_cli.project_config",
        "gemini_cli.system_settings",
        "gemini_cli.trusted_folders",
        "gemini_cli.user_settings",
        "jetbrains_ai.mcp_config",
        "junie.allowlist",
        "junie.home_config",
        "junie.mcp_config",
        "kilo_code.extension_id_legacy_tree",
        "kiro.agents",
        "kiro.cli_settings",
        "kiro.hooks",
        "kiro.ide_legacy_global_storage",
        "kiro.managed_settings",
        "kiro.mcp_config_project",
        "kiro.mcp_config_user",
        "lmstudio.conversations",
        "lmstudio.hub_downloads",
        "lmstudio.mcp_config",
        "lmstudio.presets",
        "ollama.app_config",
        "ollama.cli_config",
        "ollama.model_manifests",
        "opencode.config",
        "opencode.legacy_json_storage",
        "opencode.managed_config",
        "opencode.tui_config",
        "pi.models",
        "pi.settings",
        "qwen_code.channels_scheduled_tasks",
        "qwen_code.mcp_approvals",
        "qwen_code.openai_api_logs",
        "qwen_code.project_mcp_config",
        "qwen_code.project_settings",
        "qwen_code.prompt_history_log",
        "qwen_code.session_registry",
        "qwen_code.session_sidecars",
        "qwen_code.system_settings",
        "qwen_code.trusted_folders",
        "qwen_code.user_settings",
        "roo_code.custom_storage_path",
        "roo_code.settings",
        "roo_code.tasks",
        "vscode.extension_dirs",
        "vscode.extension_install_evidence",
        "vscode.mcp_config",
        "windsurf.acp_registry",
        "windsurf.hooks",
        "windsurf.ide_user_data",
        "windsurf.mcp_config",
        "zed.settings",
    }
)


# The documents the catalogue files as configuration, which is the one thing about them
# that is known without reading a byte. A record out of one of these is a snapshot of that
# configuration, so it is `config.snapshot` rather than `unparsed.record`: the kind says
# what the record is, and the catalogue is what says it, not a guess at the document.
#
# It matters beyond tidiness. A rule is shown the events its `applies_to` names, and the
# pack that asks which MCP servers were configured, whether the model endpoint was pointed
# elsewhere, whether retention was lowered and which hooks were set is written against
# `config.snapshot`. Filed as unparsed records, every one of those documents would be in
# the case and invisible to the rules that exist to read them, which was the state this
# catalogue was in: four shipped rules could not fire on a real collection at all.
#
# Everything else keeps `unparsed.record`, because for a transcript or a log the catalogue
# says what the file is and not what a record inside it is, and a turn read as a snapshot
# would be worse than one read as unknown.
CONFIGURATIONS = frozenset(
    {
        "aider.model_metadata",
        "amazonq.cli_agents",
        "amazonq.cli_mcp_config",
        "amazonq.cli_settings",
        "amazonq.ide_agent_config",
        "amazonq.legacy_profiles_and_context",
        "amp.session_pointer",
        "amp.settings",
        "claude_code.anthropic_profile_configs",
        "claude_code.config_backups",
        "claude_code.global_config",
        "claude_code.keybindings",
        "claude_code.known_marketplaces",
        "claude_code.managed_mcp_json",
        "claude_code.managed_settings_dropins",
        "claude_code.managed_settings_file",
        "claude_code.org_policy_cache",
        "claude_code.plugin_manifests",
        "claude_code.policy_limits",
        "claude_code.project_mcp_json",
        "claude_code.project_settings",
        "claude_code.project_settings_local",
        "claude_code.session_env",
        "claude_code.themes",
        "claude_code.user_settings",
        "claude_code.user_settings_local",
        "claude_desktop.code_launch_config",
        "claude_desktop.cowork_account_settings",
        "claude_desktop.local_config_library",
        "claude_desktop.managed_policy_linux",
        "claude_desktop.mcp_config",
        "cline.agent_schedules",
        "cline.global_settings",
        "cline.global_state_json",
        "cline.mcp_settings",
        "cline.team_data",
        "copilot.config_json",
        "copilot.lsp_config",
        "copilot.mcp_config",
        "copilot.mcp_config_jetbrains",
        "copilot.permissions",
        "copilot.providers",
        "copilot.settings",
        "crosscutting.mcp_config_files",
        "cursor.agent_cli_state",
        "cursor.cli_config",
        "cursor.hooks",
        "cursor.mcp_config",
        "cursor.plugins",
        "cursor.project_metadata",
        "factory_droid.auth",
        "factory_droid.config",
        "factory_droid.mcp_and_hooks",
        "gemini_cli.google_accounts",
        "gemini_cli.system_settings",
        "gemini_cli.trusted_folders",
        "gemini_cli.user_settings",
        "jetbrains_ai.mcp_config",
        "junie.allowlist",
        "junie.home_config",
        "junie.mcp_config",
        "kiro.agents",
        "kiro.cli_settings",
        "kiro.hooks",
        "kiro.managed_settings",
        "kiro.mcp_config_project",
        "kiro.mcp_config_user",
        "lmstudio.mcp_config",
        "ollama.app_config",
        "ollama.cli_config",
        "opencode.config",
        "opencode.managed_config",
        "opencode.tui_config",
        "pi.models",
        "pi.settings",
        "qwen_code.channels_scheduled_tasks",
        "qwen_code.mcp_approvals",
        "qwen_code.project_mcp_config",
        "qwen_code.project_settings",
        "qwen_code.system_settings",
        "qwen_code.trusted_folders",
        "qwen_code.user_settings",
        "roo_code.custom_storage_path",
        "roo_code.settings",
        "vscode.mcp_config",
        "windsurf.acp_registry",
        "windsurf.hooks",
        "windsurf.ide_user_data",
        "windsurf.mcp_config",
        "zed.settings",
    }
)


class JsonGenericParser:
    """The reading of last resort for a whole JSON document."""

    name = "json_generic"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in DOCUMENTS

    def parse(self, context: ParseContext) -> Iterator[Event]:
        document, problem = read_json(context.local_path)
        if problem is not None:
            # A truncated write, another encoding, or a file that is not JSON at all. The
            # reason is the event, because "we collected this and could not read it" is
            # something an analyst has to see rather than a blank.
            yield unparsed(
                context.provenance("$"),
                context.agent,
                None,
                problem,
                user=context.user,
                host=context.host,
            )
            return
        yield from documents(
            context,
            document,
            configuration=context.artifact_id in CONFIGURATIONS,
        )


__all__ = [
    "CONFIGURATIONS",
    "DOCUMENTS",
    "NOT_SPLIT",
    "SPLIT_LIMIT",
    "UNINTERPRETED",
    "JsonGenericParser",
]
