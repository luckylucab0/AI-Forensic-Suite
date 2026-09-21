#!/bin/sh
# Measure which of an agent's catalogued paths actually exist on this machine, on macOS or
# Linux. Read only, and names only.
#
# Why this exists. More than a hundred catalogue entries rest on somebody else's reading of
# a closed-source product rather than on a vendor page, and two families rest on no vendor
# source at all. A path that was invented is the worst defect this catalogue can carry: a
# collection searches it, finds nothing, and an analyst concludes the agent was never used.
# Only a real installation settles that, and no amount of further reading will.
#
# The probe list is generated from catalog/ by scripts/gen_layout_probes.py and every line
# of it names the entries it came from. That is not tidiness. The first version of this
# script carried a list typed by hand, and held against a real machine it probed a path
# that is in no entry and missed two that are, which is exactly the confusion the
# measurement exists to remove: a path nobody probed looks, in the output, like a path that
# was probed and was not there.
#
# What it takes, and what it refuses to take. Directory names, file names, sizes and
# modification times. Never the content of a file. That is the second non-negotiable in
# CLAUDE.md and it is not negotiable here either: the operator's own conversations,
# prompts, credentials and source code are off limits, and a layout is all this needs.
#
# Two things in the output are still yours. A path under your home directory is printed
# with the home part replaced by a tilde, so your user name does not travel. Some file and
# directory names carry project names, which is your business rather than this catalogue's:
# read the output before you send it and delete whatever you do not want to share. A gap is
# recorded as a gap. A guess would be worse than either.
#
# Usage:
#   sh scripts/measure_layout.sh > layout.txt              # every family, which is a lot
#   sh scripts/measure_layout.sh cursor > layout.txt       # one family
#   sh scripts/measure_layout.sh --list                    # what the families are
#   DEPTH=2 sh scripts/measure_layout.sh cursor            # shallower walk
#
# Then read layout.txt, remove anything you would rather not share, and send it.

set -u

DEPTH=${DEPTH:-4}
WANT=${1:-all}

# The tilde substitution is done with sed rather than with a shell parameter expansion,
# because a home directory can contain a character that expansion treats as a pattern.
shorten() {
    sed -e "s|^$HOME|~|" -e "s| $HOME| ~|g"
}

section() {
    printf '\n===== %s\n' "$1"
}

# One probe, to a bounded depth, names and metadata only. A missing path is reported as
# missing rather than skipped: an absence is a finding here, and the ids on the line say
# which catalogue entries that absence is about.
tree_of() {
    path=$1
    ids=$2
    how=$3
    if [ ! -e "$path" ]; then
        printf 'ABSENT   %s [%s]\n' "$path" "$ids" | shorten
        return
    fi
    printf 'PRESENT  %s [%s]\n' "$path" "$ids" | shorten
    # A path some other probe already walks is answered and not walked again, so no tree
    # appears twice in the output.
    [ "$how" = walk ] || return
    # find -printf is not portable to BSD find, so the metadata comes from a second call
    # per entry. Slower and portable, which is the right trade for a one-off measurement.
    find "$path" -maxdepth "$DEPTH" 2>/dev/null | sort | while IFS= read -r found; do
        if [ -d "$found" ]; then
            kind=d
            size=-
        else
            kind=f
            size=$(wc -c <"$found" 2>/dev/null | tr -d ' ')
        fi
        printf '  %s %10s  %s\n' "$kind" "$size" "$found" | shorten
    done
    # A macOS application bundle carries its version in a file, which is the one version
    # this measurement can read without running anything. Reading a version out of a file
    # rather than by executing the product is the third non-negotiable in CLAUDE.md.
    case $path in
    *.app)
        if [ -f "$path/Contents/Info.plist" ] && command -v defaults >/dev/null 2>&1; then
            printf 'VERSION  %s = %s\n' "$path" \
                "$(defaults read "$path/Contents/Info.plist" CFBundleShortVersionString \
                    2>/dev/null || echo unknown)" | shorten
        fi
        ;;
    esac
}

# The bundle identifiers a vendor actually ships under, found by name rather than assumed.
# This is the part of the measurement that finds what no source documents: three entries in
# the catalogue today are identifiers that turned up here and nowhere else.
identifiers_of() {
    for word in $1; do
        for parent in "$HOME/Library/Group Containers" "$HOME/Library/Containers" \
            "$HOME/Library/Application Support" "$HOME/Library/Caches" \
            "$HOME/Library/HTTPStorages" "$HOME/Library/Preferences"; do
            [ -d "$parent" ] || continue
            find "$parent" -maxdepth 1 -iname "*$word*" 2>/dev/null | sort | shorten
        done
    done
}

measure() {
    family=$1
    probes=$(probes_for "$family") || {
        printf 'unknown family: %s\n' "$family" >&2
        return 1
    }
    section "$family"
    # The ids come first on the line and the path second, so a path containing a space
    # survives the read: only the first field is split off.
    printf '%s\n' "$probes" | while read -r how ids path; do
        [ -n "$path" ] || continue
        case $path in
        "~"*) path="$HOME${path#\~}" ;;
        esac
        case $path in
        *[*?]*)
            # A pattern whose wildcard is in the file name. The empty IFS is what makes
            # this safe: it turns off field splitting, so a path containing a space stays
            # one word, while pathname expansion still happens. An unmatched pattern comes
            # back unchanged, which tree_of reports as absent.
            IFS=
            for match in $path; do
                tree_of "$match" "$ids" "$how"
            done
            unset IFS
            ;;
        *) tree_of "$path" "$ids" "$how" ;;
        esac
    done
    words=$(tokens_for "$family" 2>/dev/null) || words=
    if [ -n "$words" ] && [ "$(uname -s)" = Darwin ]; then
        section "$family: identifiers found by name"
        identifiers_of "$words"
    fi
}

# BEGIN generated probes -- scripts/gen_layout_probes.py
# Regenerate with: uv run python scripts/gen_layout_probes.py
#
# One line per probe: walk or check, the catalogue entries that claim it, then
# the path. A walk lists the tree below it, a check answers present or absent
# for a path some other walk already covers. A wildcard is expanded by the shell.
#
# Not probed from this catalogue, and the reasons are in the generator's docstring:
#     27 path(s) a registry key
#    368 path(s) anchored in a working copy
#    336 path(s) anchored in an environment variable
#    800 path(s) for the other platform
#      1 path(s) in a scratch directory shared with every process on the machine
probes_for() {
    case "$1" in
    aider)
        cat <<'PROBES'
walk aider.analytics,aider.caches,aider.installs,aider.oauth_keys ~/.aider
walk aider.config ~/.aider.conf.yml
walk aider.model_metadata ~/.aider.model.metadata.json
walk aider.model_settings ~/.aider.model.settings.yml
check aider.analytics ~/.aider/analytics.json
check aider.caches ~/.aider/caches
check aider.installs ~/.aider/installs.json
check aider.oauth_keys ~/.aider/oauth-keys.env
walk aider.dotenv ~/.env
PROBES
        ;;
    amazonq)
        cat <<'PROBES'
walk amazonq.cli_logs /tmp/qlog/*.log
walk amazonq.cli_checkpoints,amazonq.cli_mcp_config,amazonq.cli_prompt_history,amazonq.ide_agent_config,amazonq.ide_chat_history,amazonq.knowledge_bases,amazonq.legacy_profiles_and_context ~/.aws
check amazonq.cli_prompt_history ~/.aws/amazonq/.cli_bash_history
check amazonq.ide_agent_config ~/.aws/amazonq/agents/default.json
check amazonq.cli_agents ~/.aws/amazonq/cli-agents/*.json
check amazonq.cli_checkpoints ~/.aws/amazonq/cli-checkouts
check amazonq.ide_agent_config ~/.aws/amazonq/default.json
check amazonq.legacy_profiles_and_context ~/.aws/amazonq/global_context.json
check amazonq.ide_chat_history ~/.aws/amazonq/history/*.json
check amazonq.ide_chat_history ~/.aws/amazonq/history/chat-history-<hash>.json
check amazonq.ide_chat_history ~/.aws/amazonq/history/chat-history-no-workspace.json
check amazonq.knowledge_bases ~/.aws/amazonq/knowledge_bases
check amazonq.cli_mcp_config ~/.aws/amazonq/mcp.json
check amazonq.legacy_profiles_and_context ~/.aws/amazonq/profiles/**
check amazonq.prompt_library ~/.aws/amazonq/prompts/*.md
check amazonq.cli_user_rules ~/.aws/amazonq/rules/*
check amazonq.sso_token_cache ~/.aws/sso/cache/<hash>.json
check amazonq.sso_token_cache ~/.aws/sso/cache/aws-toolkit-vscode-client-id-*.json
walk amazonq.cli_settings,amazonq.cli_state_database ~/.local/share/amazon-q
check amazonq.cli_state_database ~/.local/share/amazon-q/data.sqlite3
check amazonq.cli_state_database ~/.local/share/amazon-q/data.sqlite3-shm
check amazonq.cli_state_database ~/.local/share/amazon-q/data.sqlite3-wal
check amazonq.cli_settings ~/.local/share/amazon-q/settings.json
walk amazonq.ide_extension_install ~/.vscode/extensions
walk amazonq.cli_settings,amazonq.cli_state_database ~/Library/Application Support/amazon-q
check amazonq.cli_state_database ~/Library/Application Support/amazon-q/data.sqlite3
check amazonq.cli_state_database ~/Library/Application Support/amazon-q/data.sqlite3-shm
check amazonq.cli_state_database ~/Library/Application Support/amazon-q/data.sqlite3-wal
check amazonq.cli_settings ~/Library/Application Support/amazon-q/settings.json
PROBES
        ;;
    amp)
        cat <<'PROBES'
walk amp.managed_instructions,amp.settings /Library/Application Support/ampcode
check amp.managed_instructions /Library/Application Support/ampcode/AGENTS.md
check amp.settings /Library/Application Support/ampcode/managed-settings.json
walk amp.managed_instructions,amp.settings /etc/ampcode
check amp.managed_instructions /etc/ampcode/AGENTS.md
check amp.settings /etc/ampcode/managed-settings.json
walk amp.skills ~/.agents/skills
walk amp.secrets ~/.amp/oauth
walk amp.thread_logs ~/.cache/amp/logs/threads/*.log
walk amp.skills ~/.claude
check amp.skills ~/.claude/plugins/cache
check amp.skills ~/.claude/skills
walk amp.global_instructions ~/.config/AGENTS.md
walk amp.skills ~/.config/agents/skills
walk amp.global_instructions,amp.plugins,amp.settings,amp.skills ~/.config/amp
check amp.global_instructions ~/.config/amp/AGENTS.md
check amp.plugins ~/.config/amp/plugins
check amp.settings ~/.config/amp/settings.json
check amp.settings ~/.config/amp/settings.jsonc
check amp.skills ~/.config/amp/skills
walk amp.ledger,amp.secrets,amp.session_pointer ~/.local/share/amp
check amp.continuations ~/.local/share/amp/continuations/*.json
check amp.ledger ~/.local/share/amp/ledger.jsonl
check amp.secrets ~/.local/share/amp/secrets.json
check amp.session_pointer ~/.local/share/amp/session.json
check amp.threads ~/.local/share/amp/threads/T-*.json
walk amp.threads ~/Library/Application Support/amp/threads/T-*.json
PROBES
        ;;
    chatgpt_desktop)
        cat <<'PROBES'
walk chatgpt_desktop.macos_computer_use_service /Library/Application Support/CodexComputerUseAuthorizationPlugin
walk chatgpt_desktop.macos_codex_home ~/.codex
walk chatgpt_desktop.macos_legacy_app_support ~/Library/Application Scripts/com.openai.chat.Widgets
walk chatgpt_desktop.macos_legacy_app_support ~/Library/Application Scripts/group.com.openai.chat
walk chatgpt_desktop.macos_legacy_app_support ~/Library/Application Support/ChatGPT
walk chatgpt_desktop.macos_codex_app_support ~/Library/Application Support/Codex
walk chatgpt_desktop.macos_openai_shared_locations ~/Library/Application Support/OpenAI
check chatgpt_desktop.macos_codex_app_support ~/Library/Application Support/OpenAI/Codex
walk chatgpt_desktop.macos_app_pairing_extensions,chatgpt_desktop.macos_conversations,chatgpt_desktop.macos_crash_reports,chatgpt_desktop.macos_legacy_app_support,chatgpt_desktop.macos_workspace_state ~/Library/Application Support/com.openai.chat
check chatgpt_desktop.macos_app_pairing_extensions ~/Library/Application Support/com.openai.chat/app_pairing_extensions
check chatgpt_desktop.macos_legacy_conversations_dir ~/Library/Application Support/com.openai.chat/conversations-*
check chatgpt_desktop.macos_drafts ~/Library/Application Support/com.openai.chat/drafts-v2-<account-id>
check chatgpt_desktop.macos_crash_reports ~/Library/Application Support/com.openai.chat/io.sentry
walk chatgpt_desktop.macos_codex_app_support ~/Library/Application Support/com.openai.codex
walk chatgpt_desktop.macos_openai_shared_locations ~/Library/Application Support/com.openai.codex.installer
walk chatgpt_desktop.macos_codex_app_support ~/Library/Caches/Codex
walk chatgpt_desktop.macos_crash_reports,chatgpt_desktop.macos_legacy_app_support,chatgpt_desktop.macos_url_cache,chatgpt_desktop.macos_web_content_cache ~/Library/Caches/com.openai.chat
check chatgpt_desktop.macos_url_cache ~/Library/Caches/com.openai.chat/Cache.db
check chatgpt_desktop.macos_url_cache ~/Library/Caches/com.openai.chat/Cache.db-shm
check chatgpt_desktop.macos_url_cache ~/Library/Caches/com.openai.chat/Cache.db-wal
check chatgpt_desktop.macos_web_content_cache ~/Library/Caches/com.openai.chat/WebKit
check chatgpt_desktop.macos_web_content_cache ~/Library/Caches/com.openai.chat/fsCachedData
check chatgpt_desktop.macos_crash_reports ~/Library/Caches/com.openai.chat/io.sentry
walk chatgpt_desktop.macos_codex_app_support ~/Library/Caches/com.openai.codex
walk chatgpt_desktop.macos_computer_use_service ~/Library/Caches/com.openai.sky.CUAService
walk chatgpt_desktop.macos_legacy_app_support ~/Library/Containers/com.openai.chat.Widgets
walk chatgpt_desktop.macos_computer_use_service ~/Library/Group Containers/*.com.openai.sky.CUAService
walk chatgpt_desktop.macos_openai_shared_locations ~/Library/Group Containers/<team-id>.com.openai.codex.notifications
walk chatgpt_desktop.macos_legacy_app_support ~/Library/Group Containers/group.com.openai.chat
walk chatgpt_desktop.macos_httpstorages ~/Library/HTTPStorages/ChatGPTHelper.binarycookies
walk chatgpt_desktop.macos_httpstorages,chatgpt_desktop.macos_httpstorages_db ~/Library/HTTPStorages/com.openai.chat
walk chatgpt_desktop.macos_cookies ~/Library/HTTPStorages/com.openai.chat.binarycookies
check chatgpt_desktop.macos_httpstorages_db ~/Library/HTTPStorages/com.openai.chat/httpstorages.sqlite
check chatgpt_desktop.macos_httpstorages_db ~/Library/HTTPStorages/com.openai.chat/httpstorages.sqlite-shm
check chatgpt_desktop.macos_httpstorages_db ~/Library/HTTPStorages/com.openai.chat/httpstorages.sqlite-wal
walk chatgpt_desktop.macos_httpstorages,chatgpt_desktop.macos_httpstorages_db ~/Library/HTTPStorages/com.openai.codex
walk chatgpt_desktop.macos_cookies ~/Library/HTTPStorages/com.openai.codex.binarycookies
check chatgpt_desktop.macos_httpstorages_db ~/Library/HTTPStorages/com.openai.codex/httpstorages.sqlite
check chatgpt_desktop.macos_httpstorages_db ~/Library/HTTPStorages/com.openai.codex/httpstorages.sqlite-shm
check chatgpt_desktop.macos_httpstorages_db ~/Library/HTTPStorages/com.openai.codex/httpstorages.sqlite-wal
walk chatgpt_desktop.macos_computer_use_service,chatgpt_desktop.macos_httpstorages,chatgpt_desktop.macos_httpstorages_db ~/Library/HTTPStorages/com.openai.sky.CUAService
walk chatgpt_desktop.macos_cookies ~/Library/HTTPStorages/com.openai.sky.CUAService.binarycookies
check chatgpt_desktop.macos_httpstorages_db ~/Library/HTTPStorages/com.openai.sky.CUAService/httpstorages.sqlite
check chatgpt_desktop.macos_httpstorages_db ~/Library/HTTPStorages/com.openai.sky.CUAService/httpstorages.sqlite-shm
check chatgpt_desktop.macos_httpstorages_db ~/Library/HTTPStorages/com.openai.sky.CUAService/httpstorages.sqlite-wal
walk chatgpt_desktop.macos_saved_state_and_logs ~/Library/Logs/com.openai.codex
walk chatgpt_desktop.macos_preferences ~/Library/Preferences/ChatGPTHelper.plist
walk chatgpt_desktop.macos_preferences ~/Library/Preferences/com.openai.chat.*.plist
walk chatgpt_desktop.macos_preferences ~/Library/Preferences/com.openai.chat.plist
walk chatgpt_desktop.macos_preferences ~/Library/Preferences/com.openai.codex.plist
walk chatgpt_desktop.macos_computer_use_service ~/Library/Preferences/com.openai.sky.CUAService.cli.plist
walk chatgpt_desktop.macos_computer_use_service ~/Library/Preferences/com.openai.sky.CUAService.plist
walk chatgpt_desktop.macos_saved_state_and_logs ~/Library/Saved Application State/com.openai.chat.savedState
walk chatgpt_desktop.macos_saved_state_and_logs ~/Library/Saved Application State/com.openai.codex.savedState
walk chatgpt_desktop.macos_legacy_app_support ~/Library/WebKit/com.openai.chat
PROBES
        ;;
    claude_code)
        cat <<'PROBES'
walk claude_code.managed_claude_md,claude_code.managed_mcp_json,claude_code.managed_settings_file,claude_code.skills /Library/Application Support/ClaudeCode
check claude_code.skills /Library/Application Support/ClaudeCode/.claude/skills
check claude_code.managed_claude_md /Library/Application Support/ClaudeCode/CLAUDE.md
check claude_code.managed_mcp_json /Library/Application Support/ClaudeCode/managed-mcp.json
check claude_code.managed_settings_dropins /Library/Application Support/ClaudeCode/managed-settings.d/*.json
check claude_code.managed_settings_file /Library/Application Support/ClaudeCode/managed-settings.json
walk claude_code.managed_settings_macos_profile /Library/Managed Preferences
check claude_code.managed_settings_macos_profile /Library/Managed Preferences/com.anthropic.claudecode.plist
walk claude_code.managed_claude_md,claude_code.managed_mcp_json,claude_code.managed_settings_file,claude_code.skills /etc/claude-code
check claude_code.skills /etc/claude-code/.claude/skills
check claude_code.managed_claude_md /etc/claude-code/CLAUDE.md
check claude_code.managed_mcp_json /etc/claude-code/managed-mcp.json
check claude_code.managed_settings_dropins /etc/claude-code/managed-settings.d/*.json
check claude_code.managed_settings_file /etc/claude-code/managed-settings.json
walk claude_code.install_legacy_and_npm /opt/homebrew/lib/node_modules/@anthropic-ai/claude-code
walk claude_code.shell_snapshots /tmp/claude-shell-snapshot*
walk claude_code.install_legacy_and_npm /usr/lib/node_modules/@anthropic-ai/claude-code
walk claude_code.install_legacy_and_npm /usr/local/lib/node_modules/@anthropic-ai/claude-code
walk claude_code.shell_profile_evidence ~/.bash_login
walk claude_code.shell_profile_evidence ~/.bash_profile
walk claude_code.shell_profile_evidence ~/.bashrc
walk claude_code.mcp_logs ~/.cache/claude-cli-nodejs
walk claude_code.agent_memory,claude_code.auto_memory,claude_code.changelog_cache,claude_code.config_backups,claude_code.credentials,claude_code.daemon_state,claude_code.feedback_bundles,claude_code.feedback_drafts,claude_code.file_history_snapshots,claude_code.history_jsonl,claude_code.image_cache,claude_code.install_legacy_and_npm,claude_code.jobs,claude_code.keybindings,claude_code.known_marketplaces,claude_code.legacy_dirs,claude_code.legacy_state_dirs,claude_code.loop_instructions,claude_code.org_policy_cache,claude_code.paste_cache,claude_code.plugin_cache,claude_code.plugins_root,claude_code.plugins_synced,claude_code.policy_limits,claude_code.session_env,claude_code.sessions_dir,claude_code.settings_referenced_executables,claude_code.shell_snapshots,claude_code.skills,claude_code.skills_trash,claude_code.stats_cache,claude_code.subagent_transcripts,claude_code.synced_skills,claude_code.task_lists,claude_code.tool_result_spills,claude_code.transcripts,claude_code.transcripts_set_aside,claude_code.uploads,claude_code.usage_data,claude_code.usage_reports,claude_code.user_claude_md,claude_code.user_rules,claude_code.user_settings,claude_code.user_settings_local,claude_code.workflow_runs ~/.claude
walk claude_code.global_config ~/.claude.json
check claude_code.credentials ~/.claude/.credentials.json
check claude_code.user_claude_md ~/.claude/CLAUDE.md
check claude_code.agent_memory ~/.claude/agent-memory
check claude_code.agent_memory ~/.claude/agent-memory/<agent-name>
check claude_code.agents ~/.claude/agents/*.md
check claude_code.config_backups ~/.claude/backups
check claude_code.config_backups ~/.claude/backups/*
check claude_code.config_backups ~/.claude/backups/.claude.json.corrupted.<timestamp>
check claude_code.changelog_cache ~/.claude/cache/changelog.md
check claude_code.commands ~/.claude/commands/*.md
check claude_code.daemon_state ~/.claude/daemon.lock
check claude_code.daemon_state ~/.claude/daemon.log
check claude_code.daemon_state ~/.claude/daemon/roster.json
check claude_code.debug_logs ~/.claude/debug/*.txt
check claude_code.debug_logs ~/.claude/debug/<session-id>.txt
check claude_code.feedback_bundles ~/.claude/feedback-bundles
check claude_code.feedback_bundles ~/.claude/feedback-bundles/*
check claude_code.feedback_bundles,claude_code.feedback_drafts ~/.claude/feedback/drafts
check claude_code.feedback_drafts ~/.claude/feedback/drafts/*
check claude_code.file_history_snapshots ~/.claude/file-history
check claude_code.file_history_snapshots ~/.claude/file-history/<session-id>
check claude_code.history_jsonl ~/.claude/history.jsonl
check claude_code.settings_referenced_executables ~/.claude/hooks
check claude_code.settings_referenced_executables ~/.claude/hooks/*
check claude_code.image_cache ~/.claude/image-cache
check claude_code.image_cache ~/.claude/image-cache/<session-id>
check claude_code.jobs ~/.claude/jobs
check claude_code.keybindings ~/.claude/keybindings.json
check claude_code.install_legacy_and_npm ~/.claude/local
check claude_code.legacy_dirs,claude_code.legacy_state_dirs ~/.claude/logs
check claude_code.loop_instructions ~/.claude/loop.md
check claude_code.output_styles ~/.claude/output-styles/*.md
check claude_code.paste_cache ~/.claude/paste-cache
check claude_code.paste_cache ~/.claude/paste-cache/*
check claude_code.plans ~/.claude/plans/*.md
check claude_code.plugins_root ~/.claude/plugins
check claude_code.plugin_cache ~/.claude/plugins/cache
check claude_code.plugin_data ~/.claude/plugins/data/<sanitized-plugin-id>
check claude_code.known_marketplaces ~/.claude/plugins/known_marketplaces.json
check claude_code.plugin_marketplaces_clones ~/.claude/plugins/marketplaces/<name>
check claude_code.plugins_synced ~/.claude/plugins/synced
check claude_code.org_policy_cache,claude_code.policy_limits ~/.claude/policy-limits.json
check claude_code.auto_memory,claude_code.subagent_transcripts,claude_code.tool_result_spills,claude_code.transcripts,claude_code.transcripts_set_aside,claude_code.workflow_runs ~/.claude/projects
check claude_code.org_policy_cache ~/.claude/remote-settings.json
check claude_code.user_rules ~/.claude/rules
check claude_code.session_env ~/.claude/session-env
check claude_code.session_env ~/.claude/session-env/*
check claude_code.sessions_dir ~/.claude/sessions
check claude_code.sessions_dir ~/.claude/sessions/*
check claude_code.user_settings ~/.claude/settings.json
check claude_code.user_settings_local ~/.claude/settings.local.json
check claude_code.shell_snapshots ~/.claude/shell-snapshots
check claude_code.shell_snapshots ~/.claude/shell-snapshots/*
check claude_code.skills ~/.claude/skills
check claude_code.skills_trash ~/.claude/skills/.trash
check claude_code.synced_skills ~/.claude/skills/synced
check claude_code.stats_cache ~/.claude/stats-cache.json
check claude_code.legacy_dirs,claude_code.legacy_state_dirs ~/.claude/statsig
check claude_code.task_lists ~/.claude/tasks
check claude_code.themes ~/.claude/themes/*.json
check claude_code.legacy_dirs,claude_code.legacy_state_dirs ~/.claude/todos
check claude_code.uploads ~/.claude/uploads
check claude_code.uploads ~/.claude/uploads/<session-id>
check claude_code.usage_data ~/.claude/usage-data
check claude_code.usage_reports ~/.claude/usage-data/*
check claude_code.usage_data,claude_code.usage_reports ~/.claude/usage-data/report.html
check claude_code.workflows ~/.claude/workflows/*.js
walk claude_code.anthropic_active_config ~/.config/anthropic/active_config
walk claude_code.anthropic_profile_configs ~/.config/anthropic/configs/<profile>.json
walk claude_code.anthropic_profile_credentials ~/.config/anthropic/credentials/<profile>.json
walk claude_code.shell_profile_evidence ~/.config/fish/config.fish
walk claude_code.git_global_excludes ~/.config/git/ignore
walk claude_code.install_native ~/.local/bin/claude
walk claude_code.install_native ~/.local/share/claude/versions/<version>
walk claude_code.install_legacy_and_npm ~/.npm-global/lib/node_modules/@anthropic-ai/claude-code
walk claude_code.install_legacy_and_npm ~/.npm-packages/lib/node_modules/@anthropic-ai/claude-code
walk claude_code.install_legacy_and_npm ~/.nvm/versions/node
walk claude_code.shell_profile_evidence ~/.profile
walk claude_code.shell_profile_evidence ~/.zshrc
walk claude_code.install_legacy_and_npm ~/Library/Application Support/Claude/claude-code/<version>
walk claude_code.mcp_logs ~/Library/Caches/claude-cli-nodejs
walk claude_code.macos_keychain_credentials ~/Library/Keychains/login.keychain-db
PROBES
        ;;
    claude_desktop)
        cat <<'PROBES'
walk claude_desktop.install_evidence_macos /Applications/Claude.app
walk claude_desktop.org_plugins /Library/Application Support/Claude/org-plugins
walk claude_desktop.managed_policy_macos /Library/Managed Preferences
check claude_desktop.managed_policy_macos /Library/Managed Preferences/com.anthropic.claudefordesktop.plist
walk claude_desktop.install_evidence_linux /etc/apt/sources.list.d/claude-desktop.list
walk claude_desktop.managed_policy_linux /etc/claude-desktop/managed-settings.json
walk claude_desktop.install_evidence_linux /etc/default/claude-desktop
walk claude_desktop.install_evidence_linux /usr/share/keyrings/claude-desktop-archive-keyring.asc
walk claude_desktop.install_evidence_linux /var/lib/dpkg/info/claude-desktop.*
walk claude_desktop.ssh_remote_artifacts ~/.claude/remote/ccd-cli/<version>
walk claude_desktop.ssh_remote_artifacts ~/.claude/remote/plugins/<hash>
walk claude_desktop.ssh_remote_artifacts ~/.claude/remote/run/<id>
walk claude_desktop.ssh_remote_artifacts ~/.claude/remote/srv/<version>
walk claude_desktop.scheduled_tasks ~/.claude/scheduled-tasks
walk claude_desktop.app_logs,claude_desktop.cowork_session_store,claude_desktop.mcp_config,claude_desktop.user_plugins ~/.config/Claude
walk claude_desktop.app_logs,claude_desktop.cowork_session_store,claude_desktop.device_identifier,claude_desktop.local_config_library ~/.config/Claude-3p
check claude_desktop.device_identifier ~/.config/Claude-3p/ant-did
check claude_desktop.local_config_library ~/.config/Claude-3p/configLibrary
check claude_desktop.cowork_session_store ~/.config/Claude-3p/local-agent-mode-sessions
check claude_desktop.app_logs ~/.config/Claude-3p/logs/main.log
check claude_desktop.mcp_config ~/.config/Claude/claude_desktop_config.json
check claude_desktop.user_plugins ~/.config/Claude/cowork_plugins
check claude_desktop.cowork_session_store ~/.config/Claude/local-agent-mode-sessions
check claude_desktop.app_logs ~/.config/Claude/logs/main.log
walk claude_desktop.install_evidence_macos ~/Applications/Claude.app
walk claude_desktop.user_output_folder ~/Claude
check claude_desktop.user_output_folder ~/Claude/Projects/<name>
walk claude_desktop.user_output_folder ~/Documents/Claude
walk claude_desktop.code_session_index,claude_desktop.cowork_account_settings,claude_desktop.cowork_audit_key,claude_desktop.cowork_audit_log,claude_desktop.cowork_memory,claude_desktop.cowork_session_files,claude_desktop.cowork_session_store,claude_desktop.cowork_vm_bundle,claude_desktop.embedded_claude_code,claude_desktop.mcp_config,claude_desktop.renderer_state,claude_desktop.user_plugins ~/Library/Application Support/Claude
walk claude_desktop.code_session_index,claude_desktop.cowork_account_settings,claude_desktop.cowork_audit_key,claude_desktop.cowork_audit_log,claude_desktop.cowork_memory,claude_desktop.cowork_session_files,claude_desktop.cowork_session_store,claude_desktop.cowork_vm_bundle,claude_desktop.device_identifier,claude_desktop.embedded_claude_code,claude_desktop.local_config_library,claude_desktop.renderer_state,claude_desktop.user_plugins ~/Library/Application Support/Claude-3p
check claude_desktop.renderer_state ~/Library/Application Support/Claude-3p/IndexedDB
check claude_desktop.device_identifier ~/Library/Application Support/Claude-3p/ant-did
check claude_desktop.transient_session_credentials ~/Library/Application Support/Claude-3p/ccd-session-secrets/<session-id>
check claude_desktop.embedded_claude_code ~/Library/Application Support/Claude-3p/claude-code
check claude_desktop.code_session_index ~/Library/Application Support/Claude-3p/claude-code-sessions
check claude_desktop.local_config_library ~/Library/Application Support/Claude-3p/configLibrary/<id>.json
check claude_desktop.local_config_library ~/Library/Application Support/Claude-3p/configLibrary/_meta.json
check claude_desktop.user_plugins ~/Library/Application Support/Claude-3p/cowork_plugins
check claude_desktop.transient_session_credentials ~/Library/Application Support/Claude-3p/host-creds-<hash>.json
check claude_desktop.cowork_account_settings,claude_desktop.cowork_audit_key,claude_desktop.cowork_audit_log,claude_desktop.cowork_memory,claude_desktop.cowork_session_files,claude_desktop.cowork_session_store ~/Library/Application Support/Claude-3p/local-agent-mode-sessions
check claude_desktop.cowork_vm_bundle ~/Library/Application Support/Claude-3p/vm_bundles
check claude_desktop.renderer_state ~/Library/Application Support/Claude/IndexedDB
check claude_desktop.renderer_state ~/Library/Application Support/Claude/Local Storage
check claude_desktop.renderer_state ~/Library/Application Support/Claude/Session Storage
check claude_desktop.transient_session_credentials ~/Library/Application Support/Claude/ccd-session-secrets/<session-id>
check claude_desktop.embedded_claude_code ~/Library/Application Support/Claude/claude-code
check claude_desktop.code_session_index ~/Library/Application Support/Claude/claude-code-sessions
check claude_desktop.embedded_claude_code ~/Library/Application Support/Claude/claude-code-vm
check claude_desktop.mcp_config ~/Library/Application Support/Claude/claude_desktop_config.json
check claude_desktop.user_plugins ~/Library/Application Support/Claude/cowork_plugins
check claude_desktop.transient_session_credentials ~/Library/Application Support/Claude/host-creds-<hash>.json
check claude_desktop.cowork_account_settings,claude_desktop.cowork_audit_key,claude_desktop.cowork_audit_log,claude_desktop.cowork_memory,claude_desktop.cowork_session_files,claude_desktop.cowork_session_store ~/Library/Application Support/Claude/local-agent-mode-sessions
check claude_desktop.cowork_vm_bundle ~/Library/Application Support/Claude/vm_bundles
walk claude_desktop.oauth_and_signin_tokens ~/Library/Keychains/login.keychain-db
walk claude_desktop.app_logs,claude_desktop.coworkd_service_log ~/Library/Logs/Claude
walk claude_desktop.app_logs ~/Library/Logs/Claude-3p/main.log
check claude_desktop.app_logs ~/Library/Logs/Claude/claude.ai-web.log
check claude_desktop.app_logs ~/Library/Logs/Claude/cowork_vm_node.log
check claude_desktop.coworkd_service_log ~/Library/Logs/Claude/coworkd.log
check claude_desktop.app_logs ~/Library/Logs/Claude/main.log
check claude_desktop.app_logs ~/Library/Logs/Claude/mcp-server-<name>.log
check claude_desktop.app_logs ~/Library/Logs/Claude/mcp.log
walk claude_desktop.managed_policy_macos ~/Library/Preferences/com.anthropic.claudefordesktop.plist
PROBES
        ;;
    cline)
        cat <<'PROBES'
walk cline.home_config_tree ~/.agents/plugins
walk cline.agent_schedules,cline.chat_workspace,cline.checkpoint_scratch,cline.cli_sessions,cline.connector_settings_and_logs,cline.data_dir_root,cline.data_tasks,cline.global_settings,cline.global_state_json,cline.home_config_tree,cline.hooks_audit_log,cline.mcp_settings,cline.provider_settings,cline.secrets_json,cline.sqlite_dbs,cline.team_data ~/.cline
check cline.home_config_tree ~/.cline/agents
check cline.home_config_tree ~/.cline/cron
check cline.data_dir_root ~/.cline/data
check cline.checkpoint_scratch ~/.cline/data/checkpoint-scratch
check cline.connector_settings_and_logs ~/.cline/data/connectors/settings.json
check cline.sqlite_dbs ~/.cline/data/db/connectors.db
check cline.sqlite_dbs ~/.cline/data/db/connectors.db-shm
check cline.sqlite_dbs ~/.cline/data/db/connectors.db-wal
check cline.sqlite_dbs ~/.cline/data/db/cron.db
check cline.sqlite_dbs ~/.cline/data/db/cron.db-shm
check cline.sqlite_dbs ~/.cline/data/db/cron.db-wal
check cline.sqlite_dbs ~/.cline/data/db/tasks.db
check cline.sqlite_dbs ~/.cline/data/db/tasks.db-shm
check cline.sqlite_dbs ~/.cline/data/db/tasks.db-wal
check cline.global_state_json ~/.cline/data/globalState.json
check cline.connector_settings_and_logs ~/.cline/data/logs
check cline.connector_settings_and_logs ~/.cline/data/logs/connectors
check cline.hooks_audit_log ~/.cline/data/logs/hooks.jsonl
check cline.secrets_json ~/.cline/data/secrets.json
check cline.cli_sessions ~/.cline/data/sessions
check cline.mcp_settings ~/.cline/data/settings/cline_mcp_settings.json
check cline.global_settings ~/.cline/data/settings/global-settings.json
check cline.provider_settings ~/.cline/data/settings/providers.json
check cline.data_tasks ~/.cline/data/tasks
check cline.team_data ~/.cline/data/teams
check cline.global_state_json ~/.cline/data/workspaces
check cline.chat_workspace ~/.cline/data/workspaces/chat
check cline.home_config_tree ~/.cline/hooks
check cline.home_config_tree ~/.cline/plugins
check cline.home_config_tree ~/.cline/rules
check cline.agent_schedules ~/.cline/schedules
check cline.home_config_tree ~/.cline/skills
check cline.home_config_tree ~/.cline/tasks
check cline.home_config_tree ~/.cline/workflows
walk cline.rules_global ~/Cline/Rules
walk cline.home_config_tree,cline.mcp_settings,cline.rules_global ~/Documents
check cline.home_config_tree ~/Documents/Cline/Agents
check cline.rules_global ~/Documents/Cline/Hooks
check cline.mcp_settings ~/Documents/Cline/MCP
check cline.home_config_tree ~/Documents/Cline/Plugins
check cline.rules_global ~/Documents/Cline/Rules
check cline.rules_global ~/Documents/Cline/Workflows
PROBES
        ;;
    codex)
        cat <<'PROBES'
walk codex.archived_sessions,codex.auth,codex.config,codex.log_dir,codex.mcp_and_notify,codex.mcp_oauth_credentials,codex.prompt_history,codex.requirements_and_permissions,codex.rollouts,codex.rollouts_compressed,codex.state_databases ~/.codex
check codex.config ~/.codex/*.config.toml
check codex.sqlite_glob ~/.codex/*.sqlite
check codex.sqlite_write_ahead_logs ~/.codex/*.sqlite-shm
check codex.sqlite_write_ahead_logs ~/.codex/*.sqlite-wal
check codex.mcp_oauth_credentials ~/.codex/.credentials.json
check codex.archived_sessions ~/.codex/archived_sessions
check codex.auth ~/.codex/auth.json
check codex.config,codex.mcp_and_notify ~/.codex/config.toml
check codex.state_databases ~/.codex/goals_1.sqlite
check codex.prompt_history ~/.codex/history.jsonl
check codex.log_dir ~/.codex/log
check codex.state_databases ~/.codex/logs_2.sqlite
check codex.state_databases ~/.codex/memories_1.sqlite
check codex.state_databases ~/.codex/memories_v2_1.sqlite
check codex.requirements_and_permissions ~/.codex/permissions.toml
check codex.state_databases ~/.codex/queue_1.sqlite
check codex.requirements_and_permissions ~/.codex/requirements.toml
check codex.rollouts,codex.rollouts_compressed ~/.codex/sessions
check codex.state_databases ~/.codex/state_5.sqlite
check codex.state_databases ~/.codex/thread_history_1.sqlite
PROBES
        ;;
    continue)
        cat <<'PROBES'
walk continue.aux_config,continue.cli_auth,continue.compiled_config,continue.config,continue.dev_data,continue.dev_data_db,continue.devbox_env,continue.diffs,continue.dotenv,continue.downloaded_binaries,continue.environment_markers,continue.global_context,continue.hook_settings,continue.index,continue.input_history,continue.permissions,continue.prompt_log,continue.sessions ~/.continue
check continue.aux_config ~/.continue/.configs
check continue.aux_config ~/.continue/.continueignore
check continue.environment_markers ~/.continue/.continuerc.json
check continue.diffs ~/.continue/.diffs
check continue.dotenv ~/.continue/.env
check continue.environment_markers ~/.continue/.local
check continue.aux_config ~/.continue/.migrations
check continue.environment_markers ~/.continue/.onboarding_complete
check continue.environment_markers ~/.continue/.staging
check continue.downloaded_binaries ~/.continue/.utils/.chromium-browser-snapshots
check continue.downloaded_binaries ~/.continue/.utils/esbuild
check continue.index ~/.continue/.utils/repo_map.txt
check continue.agents ~/.continue/agents/*.yaml
check continue.agents ~/.continue/assistants/*.yaml
check continue.cli_auth ~/.continue/auth.json
check continue.config ~/.continue/config.json
check continue.config ~/.continue/config.ts
check continue.config ~/.continue/config.yaml
check continue.dev_data ~/.continue/dev_data
check continue.dev_data_db ~/.continue/dev_data/devdata.sqlite
check continue.dev_data_db ~/.continue/dev_data/devdata.sqlite-shm
check continue.dev_data_db ~/.continue/dev_data/devdata.sqlite-wal
check continue.devbox_env ~/.continue/devbox-env
check continue.index ~/.continue/index/autocompleteCache.sqlite
check continue.index ~/.continue/index/autocompleteCache.sqlite-shm
check continue.index ~/.continue/index/autocompleteCache.sqlite-wal
check continue.index ~/.continue/index/docs.sqlite
check continue.index ~/.continue/index/docs.sqlite-shm
check continue.index ~/.continue/index/docs.sqlite-wal
check continue.global_context ~/.continue/index/globalContext.json
check continue.index ~/.continue/index/index.sqlite
check continue.index ~/.continue/index/index.sqlite-shm
check continue.index ~/.continue/index/index.sqlite-wal
check continue.index ~/.continue/index/lancedb
check continue.input_history ~/.continue/input_history.json
check continue.logs ~/.continue/logs/**
check continue.dev_data ~/.continue/logs/core.log
check continue.prompt_log ~/.continue/logs/prompt.log
check continue.compiled_config ~/.continue/out/config.js
check continue.permissions ~/.continue/permissions.yaml
check continue.rules_and_skills ~/.continue/prompts/**
check continue.rules_and_skills ~/.continue/rules/**
check continue.sessions ~/.continue/sessions/<session-id>.json
check continue.sessions ~/.continue/sessions/sessions.json
check continue.hook_settings ~/.continue/settings.json
check continue.global_context ~/.continue/sharedConfig.json
check continue.rules_and_skills ~/.continue/skills/**
PROBES
        ;;
    copilot)
        cat <<'PROBES'
walk copilot.cache ~/.cache/copilot
walk copilot.mcp_config_jetbrains ~/.config/github-copilot
check copilot.mcp_config_jetbrains ~/.config/github-copilot/intellij/mcp.json
walk copilot.agents_skills_hooks,copilot.command_history,copilot.config_json,copilot.extensions_and_plugins,copilot.ide_locks,copilot.instructions,copilot.logs,copilot.lsp_config,copilot.mcp_config,copilot.mcp_credentials,copilot.permissions,copilot.providers,copilot.session_event_log,copilot.session_state,copilot.session_store,copilot.session_store_sidecars,copilot.settings ~/.copilot
check copilot.agents_skills_hooks ~/.copilot/agents
check copilot.command_history ~/.copilot/command-history-state
check copilot.config_json ~/.copilot/config.json
check copilot.instructions ~/.copilot/copilot-instructions.md
check copilot.extensions_and_plugins ~/.copilot/extensions
check copilot.agents_skills_hooks ~/.copilot/hooks
check copilot.ide_locks ~/.copilot/ide
check copilot.extensions_and_plugins ~/.copilot/installed-plugins
check copilot.instructions ~/.copilot/instructions
check copilot.logs ~/.copilot/logs
check copilot.lsp_config ~/.copilot/lsp-config.json
check copilot.mcp_config ~/.copilot/mcp-config.json
check copilot.mcp_credentials ~/.copilot/mcp-oauth-config
check copilot.mcp_credentials ~/.copilot/mcp-secrets
check copilot.permissions ~/.copilot/permissions-config.json
check copilot.extensions_and_plugins ~/.copilot/plugin-data
check copilot.providers ~/.copilot/providers.json
check copilot.session_event_log,copilot.session_state ~/.copilot/session-state
check copilot.session_store ~/.copilot/session-store.db
check copilot.session_store_sidecars ~/.copilot/session-store.db-shm
check copilot.session_store_sidecars ~/.copilot/session-store.db-wal
check copilot.settings ~/.copilot/settings.json
check copilot.agents_skills_hooks ~/.copilot/skills
walk copilot.cache ~/Library/Caches/copilot
PROBES
        ;;
    crosscutting)
        cat <<'PROBES'
walk crosscutting.instructions_claude_md /Library/Application Support/ClaudeCode/CLAUDE.md
walk crosscutting.instructions_claude_md /etc/claude-code/CLAUDE.md
walk crosscutting.homebrew_prefixes /home/linuxbrew
check crosscutting.homebrew_prefixes /home/linuxbrew/.linuxbrew
check crosscutting.homebrew_prefixes /home/linuxbrew/.linuxbrew/Cellar
walk crosscutting.homebrew_prefixes,crosscutting.npm_global_install_dirs /opt/homebrew
check crosscutting.homebrew_prefixes /opt/homebrew/Caskroom
check crosscutting.homebrew_prefixes /opt/homebrew/Cellar
check crosscutting.homebrew_prefixes /opt/homebrew/bin
check crosscutting.npm_global_install_dirs /opt/homebrew/lib/node_modules
walk crosscutting.pipx_home_and_bin /opt/pipx
check crosscutting.homebrew_prefixes /usr/local
walk crosscutting.homebrew_prefixes /usr/local/Cellar
check crosscutting.npm_global_install_dirs /usr/local/bin
walk crosscutting.npm_global_install_dirs /usr/local/lib/node_modules
walk crosscutting.shell_bash_history ~/.bash_history
walk crosscutting.uv_tool_dir ~/.cache/uv
walk crosscutting.instructions_claude_md ~/.claude
walk crosscutting.mcp_config_files ~/.claude.json
check crosscutting.instructions_claude_md ~/.claude/CLAUDE.md
check crosscutting.instructions_claude_md ~/.claude/rules
walk crosscutting.instructions_gemini_md ~/.gemini/GEMINI.md
check crosscutting.pipx_home_and_bin,crosscutting.uv_tool_dir ~/.local/bin
walk crosscutting.pipx_home_and_bin ~/.local/pipx
walk crosscutting.shell_fish_history ~/.local/share/fish/fish_history
walk crosscutting.pipx_home_and_bin ~/.local/share/pipx/venvs/*
walk crosscutting.shell_psreadline_history ~/.local/share/powershell/PSReadLine/ConsoleHost_history.txt
walk crosscutting.uv_tool_dir ~/.local/share/uv/python
walk crosscutting.uv_tool_dir ~/.local/share/uv/tools/*
walk crosscutting.npm_debug_logs ~/.npm/_logs/*-debug-*.log
walk crosscutting.npm_npx_cache ~/.npm/_npx
walk crosscutting.npm_global_install_dirs ~/.nvm/versions/node
walk crosscutting.shell_zsh_history ~/.zhistory
walk crosscutting.shell_zsh_history ~/.zsh_history
walk crosscutting.hook_scripts,crosscutting.instructions_clinerules ~/Documents
check crosscutting.hook_scripts ~/Documents/Cline/Hooks
check crosscutting.instructions_clinerules ~/Documents/Cline/Rules
check crosscutting.instructions_clinerules ~/Documents/Cline/Workflows
walk crosscutting.pipx_home_and_bin ~/Library/Application Support/pipx/venvs/*
walk crosscutting.macos_download_provenance ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2
walk crosscutting.macos_download_provenance ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2-shm
walk crosscutting.macos_download_provenance ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2-wal
walk crosscutting.macos_launch_services_registrations ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
PROBES
        ;;
    cursor)
        cat <<'PROBES'
walk cursor.hooks /Library/Application Support/Cursor/hooks.json
walk cursor.hooks /etc/cursor/hooks.json
walk cursor.worker_data /opt/cursor/**
walk cursor.skills ~/.agents/skills
walk cursor.retrieval_index ~/.cache/cursor-compile-cache
walk cursor.subagents ~/.claude/agents
walk cursor.subagents ~/.codex/agents
walk cursor.commit_checkpoints,cursor.conversation_search_db,cursor.global_state_vscdb,cursor.local_file_history,cursor.logs,cursor.machine_identity_file,cursor.workspace_state_vscdb ~/.config/Cursor
check cursor.local_file_history ~/.config/Cursor/User/History
check cursor.commit_checkpoints ~/.config/Cursor/User/globalStorage/anysphere.cursor-commits/checkpoints
check cursor.commit_checkpoints ~/.config/Cursor/User/globalStorage/anysphere.cursor-retrieval/checkpoints/<uuid>
check cursor.conversation_search_db ~/.config/Cursor/User/globalStorage/conversation-search.db
check cursor.conversation_search_db ~/.config/Cursor/User/globalStorage/conversation-search.db-shm
check cursor.conversation_search_db ~/.config/Cursor/User/globalStorage/conversation-search.db-wal
check cursor.global_state_vscdb ~/.config/Cursor/User/globalStorage/state.vscdb
check cursor.global_state_vscdb ~/.config/Cursor/User/globalStorage/state.vscdb-shm
check cursor.global_state_vscdb ~/.config/Cursor/User/globalStorage/state.vscdb-wal
check cursor.workspace_state_vscdb ~/.config/Cursor/User/workspaceStorage
check cursor.logs ~/.config/Cursor/logs
check cursor.machine_identity_file ~/.config/Cursor/machineid
walk cursor.auth_credentials ~/.config/cursor/auth.json
walk cursor.acp_session_store,cursor.agent_cli_state,cursor.agent_transcripts_jsonl,cursor.ai_code_tracking_db,cursor.auth_credentials,cursor.bundled_skills,cursor.chat_session_meta_json,cursor.chat_session_prompt_history,cursor.chat_store_db,cursor.cli_config,cursor.cli_workspaces,cursor.extensions,cursor.feature_flag_cache,cursor.global_prompt_history,cursor.hooks,cursor.mcp_config,cursor.mdm_policy,cursor.pasted_text,cursor.plugins,cursor.project_mcp_definitions,cursor.project_mcp_instructions,cursor.project_metadata,cursor.runtime_arguments,cursor.skills,cursor.subagent_output,cursor.subagents ~/.cursor
walk cursor.extensions ~/.cursor-server/extensions
check cursor.acp_session_store ~/.cursor/acp-sessions
check cursor.agent_cli_state ~/.cursor/agent-cli-state.json
check cursor.subagents ~/.cursor/agents
check cursor.ai_code_tracking_db ~/.cursor/ai-tracking/*.db
check cursor.ai_code_tracking_db ~/.cursor/ai-tracking/*.db-shm
check cursor.ai_code_tracking_db ~/.cursor/ai-tracking/*.db-wal
check cursor.ai_code_tracking_db ~/.cursor/ai-tracking/ai-code-tracking.db
check cursor.ai_code_tracking_db ~/.cursor/ai-tracking/ai-code-tracking.db-shm
check cursor.ai_code_tracking_db ~/.cursor/ai-tracking/ai-code-tracking.db-wal
check cursor.runtime_arguments ~/.cursor/argv.json
check cursor.auth_credentials ~/.cursor/auth.json
check cursor.agent_cli_state ~/.cursor/browser-logs
check cursor.chat_session_meta_json,cursor.chat_session_prompt_history,cursor.chat_store_db,cursor.pasted_text ~/.cursor/chats
check cursor.cli_config ~/.cursor/cli-config.json
check cursor.cli_config ~/.cursor/cli-config.json.bad
check cursor.cli_workspaces ~/.cursor/cli-workspaces.json
check cursor.agent_cli_state ~/.cursor/commands/*.md
check cursor.computer_use_sidecar ~/.cursor/cursor-computer-use/**
check cursor.extensions ~/.cursor/extensions
check cursor.extensions ~/.cursor/extensions/extensions.json
check cursor.hooks ~/.cursor/hooks
check cursor.agent_cli_state,cursor.hooks ~/.cursor/hooks.json
check cursor.cli_workspaces ~/.cursor/ide_state.json
check cursor.mcp_config ~/.cursor/mcp.json
check cursor.plugins ~/.cursor/plugins
check cursor.plugins ~/.cursor/plugins/local
check cursor.mdm_policy ~/.cursor/policy.json
check cursor.agent_transcripts_jsonl,cursor.project_mcp_definitions,cursor.project_mcp_instructions,cursor.project_metadata ~/.cursor/projects
check cursor.project_metadata ~/.cursor/projects-metadata.json
check cursor.agent_data_cleanup_marker ~/.cursor/projects/.agent-data-cleanup-<yyyy-mm-dd>
check cursor.global_prompt_history ~/.cursor/prompt_history.json
check cursor.agent_cli_state ~/.cursor/sandbox-policies
check cursor.skills ~/.cursor/skills
check cursor.bundled_skills ~/.cursor/skills-cursor
check cursor.bundled_skills ~/.cursor/skills-cursor/.sync-manifest.json
check cursor.agent_cli_state ~/.cursor/snapshots
check cursor.feature_flag_cache ~/.cursor/statsig-cache.json
check cursor.subagent_output ~/.cursor/subagents
check cursor.agent_cli_state ~/.cursor/worktrees
check cursor.worktrees ~/.cursor/worktrees/*
walk cursor.worker_data ~/.local/share/cursor-agent/**
walk cursor.agent_store_sync,cursor.commit_checkpoints,cursor.conversation_search_db,cursor.extensions,cursor.global_state_vscdb,cursor.local_file_history,cursor.logs,cursor.machine_identity_file,cursor.machine_identity_storage,cursor.macos_update_state,cursor.retrieval_index,cursor.workspace_state_vscdb ~/Library/Application Support/Cursor
check cursor.macos_update_state ~/Library/Application Support/Cursor/3.21-main.sock
check cursor.agent_store_sync ~/Library/Application Support/Cursor/AgentStores/cursor_agent_stores
check cursor.macos_update_state ~/Library/Application Support/Cursor/Backups
check cursor.retrieval_index ~/Library/Application Support/Cursor/CachedData
check cursor.macos_update_state ~/Library/Application Support/Cursor/Crashpad
check cursor.machine_identity_file ~/Library/Application Support/Cursor/SharedStorage
check cursor.local_file_history ~/Library/Application Support/Cursor/User/History
check cursor.commit_checkpoints ~/Library/Application Support/Cursor/User/globalStorage/anysphere.cursor-commits/checkpoints
check cursor.commit_checkpoints ~/Library/Application Support/Cursor/User/globalStorage/anysphere.cursor-retrieval/checkpoints/<uuid>
check cursor.conversation_search_db ~/Library/Application Support/Cursor/User/globalStorage/conversation-search.db
check cursor.conversation_search_db ~/Library/Application Support/Cursor/User/globalStorage/conversation-search.db-shm
check cursor.conversation_search_db ~/Library/Application Support/Cursor/User/globalStorage/conversation-search.db-wal
check cursor.global_state_vscdb ~/Library/Application Support/Cursor/User/globalStorage/state.vscdb
check cursor.global_state_vscdb ~/Library/Application Support/Cursor/User/globalStorage/state.vscdb-shm
check cursor.global_state_vscdb ~/Library/Application Support/Cursor/User/globalStorage/state.vscdb-wal
check cursor.global_state_vscdb ~/Library/Application Support/Cursor/User/globalStorage/state.vscdb.backup
check cursor.machine_identity_storage ~/Library/Application Support/Cursor/User/globalStorage/statsig-cache.json
check cursor.machine_identity_storage ~/Library/Application Support/Cursor/User/globalStorage/storage.json
check cursor.logs ~/Library/Application Support/Cursor/User/process-monitor
check cursor.retrieval_index,cursor.workspace_state_vscdb ~/Library/Application Support/Cursor/User/workspaceStorage
check cursor.extensions ~/Library/Application Support/Cursor/extensions
check cursor.logs ~/Library/Application Support/Cursor/logs
check cursor.logs ~/Library/Application Support/Cursor/logs/<launch-timestamp>
check cursor.machine_identity_file ~/Library/Application Support/Cursor/machineid
check cursor.logs ~/Library/Application Support/Cursor/process-monitor
walk cursor.macos_bundle_storage ~/Library/Caches/com.todesktop.230313mzl4w4u92
walk cursor.macos_update_state ~/Library/Caches/com.todesktop.230313mzl4w4u92.ShipIt
check cursor.macos_bundle_storage ~/Library/Caches/com.todesktop.230313mzl4w4u92/Cache.db
check cursor.macos_bundle_storage ~/Library/Caches/com.todesktop.230313mzl4w4u92/Cache.db-shm
check cursor.macos_bundle_storage ~/Library/Caches/com.todesktop.230313mzl4w4u92/Cache.db-wal
walk cursor.retrieval_index ~/Library/Caches/cursor-compile-cache
check cursor.retrieval_index ~/Library/Caches/cursor-compile-cache/v<runtime-version>-<arch>-<hash>-<uid>
walk cursor.macos_bundle_storage ~/Library/HTTPStorages/com.todesktop.230313mzl4w4u92
check cursor.macos_bundle_storage ~/Library/HTTPStorages/com.todesktop.230313mzl4w4u92/httpstorages.sqlite
check cursor.macos_bundle_storage ~/Library/HTTPStorages/com.todesktop.230313mzl4w4u92/httpstorages.sqlite-shm
check cursor.macos_bundle_storage ~/Library/HTTPStorages/com.todesktop.230313mzl4w4u92/httpstorages.sqlite-wal
walk cursor.macos_preferences ~/Library/Preferences/com.todesktop.230313mzl4w4u92.plist
PROBES
        ;;
    devin)
        cat <<'PROBES'
walk devin.cli_system_policy /Library/Application Support/Devin/system.json
walk devin.cli_system_policy /etc/devin/system.json
walk devin.acp_events ~/.config/Devin
check devin.acp_events ~/.config/Devin/User/acp-events
check devin.acp_events ~/.config/Devin/logs
walk devin.cli_config,devin.cli_config_dir,devin.cli_mcp_config,devin.cli_subagents ~/.config/devin
check devin.cli_subagents ~/.config/devin/agents
check devin.cli_config_dir ~/.config/devin/cli
check devin.cli_config ~/.config/devin/config.json
check devin.cli_mcp_config ~/.config/devin/mcp_config.json
walk devin.sessions_db ~/.local/share/devin
check devin.sessions_db ~/.local/share/devin/cli/sessions.db
check devin.sessions_db ~/.local/share/devin/cli/sessions.db-shm
check devin.sessions_db ~/.local/share/devin/cli/sessions.db-wal
check devin.sessions_db ~/.local/share/devin/cli/transcripts/<session-id>.json
walk devin.acp_events ~/Library/Application Support/Devin/User/acp-events
walk devin.sessions_db ~/Library/Application Support/devin
check devin.sessions_db ~/Library/Application Support/devin/cli/sessions.db
check devin.sessions_db ~/Library/Application Support/devin/cli/sessions.db-shm
check devin.sessions_db ~/Library/Application Support/devin/cli/sessions.db-wal
check devin.sessions_db ~/Library/Application Support/devin/cli/transcripts/<session-id>.json
PROBES
        ;;
    factory_droid)
        cat <<'PROBES'
walk factory_droid.managed_settings /Library/Application Support/Factory/settings.json
walk factory_droid.managed_settings /etc/factory/settings.json
walk factory_droid.skills_and_droids ~/.agent/skills
walk factory_droid.skills_and_droids ~/.agents/skills
walk factory_droid.skills_and_droids ~/.claude/agents/*.md
walk factory_droid.auth,factory_droid.config,factory_droid.logs,factory_droid.mcp_and_hooks,factory_droid.sessions,factory_droid.skills_and_droids ~/.factory
check factory_droid.logs ~/.factory/bug-reports
check factory_droid.skills_and_droids ~/.factory/commands
check factory_droid.config ~/.factory/config.json
check factory_droid.skills_and_droids ~/.factory/droids
check factory_droid.mcp_and_hooks ~/.factory/hooks.json
check factory_droid.logs ~/.factory/logs
check factory_droid.mcp_and_hooks ~/.factory/mcp.json
check factory_droid.output_styles ~/.factory/output-styles/*.md
check factory_droid.sessions ~/.factory/sessions
check factory_droid.sessions ~/.factory/sessions/<uuid>.json
check factory_droid.config ~/.factory/settings.json
check factory_droid.config ~/.factory/settings.local.json
check factory_droid.skills_and_droids ~/.factory/skills
check factory_droid.specs ~/.factory/specs/**
check factory_droid.worktrees ~/.factory/worktrees/**
PROBES
        ;;
    gemini_cli)
        cat <<'PROBES'
walk gemini_cli.system_settings /Library/Application Support/GeminiCli
check gemini_cli.policies /Library/Application Support/GeminiCli/policies/**
check gemini_cli.system_settings /Library/Application Support/GeminiCli/settings.json
check gemini_cli.system_settings /Library/Application Support/GeminiCli/system-defaults.json
walk gemini_cli.system_settings /etc/gemini-cli
check gemini_cli.policies /etc/gemini-cli/policies/**
check gemini_cli.system_settings /etc/gemini-cli/settings.json
check gemini_cli.system_settings /etc/gemini-cli/system-defaults.json
walk gemini_cli.agent_definitions ~/.agents/skills/**
walk gemini_cli.chats,gemini_cli.home_tree,gemini_cli.install_evidence,gemini_cli.policy_integrity,gemini_cli.project_registry,gemini_cli.prompt_history_log ~/.cache/.gemini
check gemini_cli.project_runtime_trees ~/.cache/.gemini/history/<project-hash>
check gemini_cli.install_evidence ~/.cache/.gemini/installation_id
check gemini_cli.policy_integrity ~/.cache/.gemini/policy_integrity.json
check gemini_cli.project_registry ~/.cache/.gemini/projects.json
check gemini_cli.chats,gemini_cli.prompt_history_log ~/.cache/.gemini/tmp
check gemini_cli.project_runtime_trees ~/.cache/.gemini/tmp/<project-hash>
walk gemini_cli.agent_acknowledgments,gemini_cli.chats,gemini_cli.commands,gemini_cli.credentials,gemini_cli.google_accounts,gemini_cli.home_tree,gemini_cli.install_evidence,gemini_cli.mcp_oauth_tokens,gemini_cli.policy_integrity,gemini_cli.project_registry,gemini_cli.prompt_history_log,gemini_cli.shell_history,gemini_cli.trusted_folders,gemini_cli.user_settings ~/.gemini
check gemini_cli.mcp_oauth_tokens ~/.gemini/a2a-oauth-tokens.json
check gemini_cli.agent_acknowledgments ~/.gemini/acknowledgments/agents.json
check gemini_cli.agent_definitions ~/.gemini/agents/**
check gemini_cli.commands ~/.gemini/commands
check gemini_cli.google_accounts ~/.gemini/google_accounts.json
check gemini_cli.project_runtime_trees ~/.gemini/history/<project-hash>
check gemini_cli.install_evidence ~/.gemini/installation_id
check gemini_cli.mcp_oauth_tokens ~/.gemini/mcp-oauth-tokens.json
check gemini_cli.credentials ~/.gemini/oauth_creds.json
check gemini_cli.policies ~/.gemini/policies/**
check gemini_cli.policy_integrity ~/.gemini/policy_integrity.json
check gemini_cli.project_registry ~/.gemini/projects.json
check gemini_cli.chats ~/.gemini/sessions
check gemini_cli.user_settings ~/.gemini/settings.json
check gemini_cli.agent_definitions ~/.gemini/skills/**
check gemini_cli.chats,gemini_cli.prompt_history_log,gemini_cli.shell_history ~/.gemini/tmp
check gemini_cli.project_runtime_trees ~/.gemini/tmp/<project-hash>
check gemini_cli.trusted_folders ~/.gemini/trustedFolders.json
PROBES
        ;;
    goose)
        cat <<'PROBES'
walk goose.agents,goose.hooks,goose.plugins,goose.skills ~/.agents
check goose.agents ~/.agents/agents
check goose.hooks,goose.plugins ~/.agents/plugins
check goose.skills ~/.agents/skills
walk goose.agents,goose.skills ~/.claude
check goose.agents ~/.claude/agents
check goose.skills ~/.claude/skills
walk goose.agents,goose.command_history,goose.config,goose.hints,goose.memory,goose.permissions,goose.prompts,goose.secrets,goose.settings,goose.skills ~/.config/goose
check goose.hints ~/.config/goose/.goosehints
check goose.agents ~/.config/goose/agents
check goose.config ~/.config/goose/config.yaml
check goose.command_history ~/.config/goose/history.txt
check goose.memory ~/.config/goose/memory
check goose.permissions ~/.config/goose/permission.yaml
check goose.permissions ~/.config/goose/permissions/tool_permissions.json
check goose.prompts ~/.config/goose/prompts
check goose.secrets ~/.config/goose/secrets.yaml
check goose.settings ~/.config/goose/settings.json
check goose.skills ~/.config/goose/skills
walk goose.agents ~/.goose/agents
walk goose.sessions_db ~/.local/share/goose
check goose.sessions_jsonl_legacy ~/.local/share/goose/sessions/*.jsonl
check goose.sessions_db ~/.local/share/goose/sessions/sessions.db
check goose.sessions_db ~/.local/share/goose/sessions/sessions.db-shm
check goose.sessions_db ~/.local/share/goose/sessions/sessions.db-wal
walk goose.cli_logs,goose.command_history,goose.server_logs ~/.local/state
check goose.command_history ~/.local/state/goose/history.txt
check goose.cli_logs ~/.local/state/goose/logs/cli
check goose.cli_logs ~/.local/state/goose/logs/cli/YYYY-MM-DD
check goose.llm_request_logs ~/.local/state/goose/logs/llm_request.*.jsonl
check goose.server_logs ~/.local/state/goose/logs/server
walk goose.agents,goose.cli_logs,goose.command_history,goose.config,goose.hints,goose.memory,goose.permissions,goose.prompts,goose.secrets,goose.server_logs,goose.sessions_db,goose.settings,goose.skills ~/Library/Application Support/Block
check goose.hints ~/Library/Application Support/Block/goose/config/.goosehints
check goose.agents ~/Library/Application Support/Block/goose/config/agents
check goose.config ~/Library/Application Support/Block/goose/config/config.yaml
check goose.command_history ~/Library/Application Support/Block/goose/config/history.txt
check goose.memory ~/Library/Application Support/Block/goose/config/memory
check goose.permissions ~/Library/Application Support/Block/goose/config/permission.yaml
check goose.permissions ~/Library/Application Support/Block/goose/config/permissions/tool_permissions.json
check goose.prompts ~/Library/Application Support/Block/goose/config/prompts
check goose.secrets ~/Library/Application Support/Block/goose/config/secrets.yaml
check goose.settings ~/Library/Application Support/Block/goose/config/settings.json
check goose.skills ~/Library/Application Support/Block/goose/config/skills
check goose.command_history ~/Library/Application Support/Block/goose/data/history.txt
check goose.cli_logs ~/Library/Application Support/Block/goose/data/logs/cli
check goose.llm_request_logs ~/Library/Application Support/Block/goose/data/logs/llm_request.*.jsonl
check goose.server_logs ~/Library/Application Support/Block/goose/data/logs/server
check goose.sessions_jsonl_legacy ~/Library/Application Support/Block/goose/data/sessions/*.jsonl
check goose.sessions_db ~/Library/Application Support/Block/goose/data/sessions/sessions.db
check goose.sessions_db ~/Library/Application Support/Block/goose/data/sessions/sessions.db-shm
check goose.sessions_db ~/Library/Application Support/Block/goose/data/sessions/sessions.db-wal
check goose.command_history ~/Library/Application Support/Block/goose/state/history.txt
check goose.cli_logs ~/Library/Application Support/Block/goose/state/logs/cli
check goose.llm_request_logs ~/Library/Application Support/Block/goose/state/logs/llm_request.*.jsonl
check goose.server_logs ~/Library/Application Support/Block/goose/state/logs/server
walk goose.desktop_log ~/Library/Application Support/Goose/logs/main.log
PROBES
        ;;
    hermes)
        cat <<'PROBES'
walk hermes.a2a_audit,hermes.a2a_conversations,hermes.auth,hermes.background_processes,hermes.backups,hermes.blocked_scripts,hermes.browser_agent_profiles,hermes.browser_media,hermes.browser_profile,hermes.checkpoint_projects,hermes.checkpoints,hermes.config,hermes.cron,hermes.cron_executions,hermes.cron_external_workers,hermes.cron_jobs,hermes.cron_usage_audit,hermes.debug_share_pastes,hermes.env,hermes.gateway_state,hermes.hooks,hermes.logs,hermes.mcp_installs,hermes.mcp_tokens,hermes.memories,hermes.memory_store,hermes.model_traces,hermes.oauth_tokens,hermes.pairing,hermes.pastes,hermes.pending_skills,hermes.platform_sessions,hermes.process_results,hermes.profile_home,hermes.profile_tombstones,hermes.profiles,hermes.projects_db,hermes.remote_sandbox_snapshots,hermes.response_store,hermes.retired_wal_generations,hermes.retired_wal_manifests,hermes.retired_wal_transcripts,hermes.sandboxes,hermes.saved_sessions,hermes.session_exports,hermes.sessions_dir,hermes.skills,hermes.skills_prompt_snapshot,hermes.soul,hermes.spillover,hermes.state_db,hermes.state_snapshot_transcripts,hermes.state_snapshots,hermes.terminal_sessions,hermes.vault,hermes.verification_evidence ~/.hermes
check hermes.oauth_tokens ~/.hermes/.anthropic_oauth.json
check hermes.env ~/.hermes/.env
check hermes.skills_prompt_snapshot ~/.hermes/.skills_prompt_snapshot.json
check hermes.soul ~/.hermes/SOUL.md
check hermes.a2a_audit ~/.hermes/a2a_audit.jsonl
check hermes.a2a_conversations ~/.hermes/a2a_conversations/*.jsonl
check hermes.auth ~/.hermes/auth.json
check hermes.backups ~/.hermes/backups/*.zip
check hermes.browser_profile ~/.hermes/browser-profile/**
check hermes.browser_agent_profiles ~/.hermes/browser_auth/**
check hermes.browser_media ~/.hermes/browser_recordings/session_*.webm
check hermes.browser_media ~/.hermes/browser_screenshots/browser_screenshot_*.png
check hermes.blocked_scripts ~/.hermes/cache/blocked-scripts/blocked-*.sh
check hermes.oauth_tokens ~/.hermes/cache/bws_cache.enc.json
check hermes.oauth_tokens ~/.hermes/cache/bws_cache.json
check hermes.browser_media ~/.hermes/cache/screenshots/browser_screenshot_*.png
check hermes.spillover ~/.hermes/cache/spillover/*.txt
check hermes.gateway_state ~/.hermes/channel_aliases.json
check hermes.gateway_state ~/.hermes/channel_directory.json
check hermes.checkpoints ~/.hermes/checkpoints
check hermes.checkpoints ~/.hermes/checkpoints/store/**
check hermes.checkpoint_projects ~/.hermes/checkpoints/store/ledgers/*.json
check hermes.checkpoint_projects ~/.hermes/checkpoints/store/projects/*.json
check hermes.browser_agent_profiles ~/.hermes/chrome-debug/**
check hermes.config ~/.hermes/config.yaml
check hermes.cron ~/.hermes/cron
check hermes.cron_executions ~/.hermes/cron/executions.db
check hermes.cron_executions ~/.hermes/cron/executions.db-shm
check hermes.cron_executions ~/.hermes/cron/executions.db-wal
check hermes.cron_external_workers ~/.hermes/cron/external-workers/**
check hermes.cron_jobs ~/.hermes/cron/jobs.json
check hermes.cron_usage_audit ~/.hermes/cron/usage_audit.jsonl
check hermes.gateway_state ~/.hermes/gateway.pid
check hermes.gateway_state ~/.hermes/gateway_state.json
check hermes.oauth_tokens ~/.hermes/google_chat_user_client_secret.json
check hermes.oauth_tokens ~/.hermes/google_chat_user_oauth_pending.json
check hermes.oauth_tokens ~/.hermes/google_chat_user_oauth_pending/*.json
check hermes.oauth_tokens ~/.hermes/google_chat_user_token.json
check hermes.oauth_tokens ~/.hermes/google_chat_user_tokens/*.json
check hermes.oauth_tokens ~/.hermes/google_token.json
check hermes.profile_home ~/.hermes/home/**
check hermes.hooks ~/.hermes/hooks/**
check hermes.logs ~/.hermes/logs/**
check hermes.process_results ~/.hermes/logs/process-results/proc_*.json
check hermes.platform_sessions ~/.hermes/matrix/store/crypto.db
check hermes.mcp_installs ~/.hermes/mcp-installs/**
check hermes.mcp_tokens ~/.hermes/mcp-tokens/*.cimd-off
check hermes.mcp_tokens ~/.hermes/mcp-tokens/*.json
check hermes.memories ~/.hermes/memories/MEMORY.md
check hermes.memories ~/.hermes/memories/USER.md
check hermes.memory_store ~/.hermes/memory_store.db
check hermes.memory_store ~/.hermes/memory_store.db-shm
check hermes.memory_store ~/.hermes/memory_store.db-wal
check hermes.model_traces ~/.hermes/moa-traces/*.jsonl
check hermes.remote_sandbox_snapshots ~/.hermes/modal_snapshots.json
check hermes.pairing ~/.hermes/pairing/**
check hermes.pastes ~/.hermes/pastes/paste_*.txt
check hermes.debug_share_pastes ~/.hermes/pastes/pending.json
check hermes.pending_skills ~/.hermes/pending/skills/*.json
check hermes.platform_sessions ~/.hermes/platforms/matrix/store/crypto.db
check hermes.pairing ~/.hermes/platforms/pairing/**
check hermes.platform_sessions ~/.hermes/platforms/whatsapp/session/**
check hermes.background_processes ~/.hermes/processes.json
check hermes.a2a_audit,hermes.a2a_conversations,hermes.auth,hermes.background_processes,hermes.backups,hermes.blocked_scripts,hermes.browser_agent_profiles,hermes.browser_media,hermes.browser_profile,hermes.checkpoint_projects,hermes.checkpoints,hermes.config,hermes.cron,hermes.cron_executions,hermes.cron_external_workers,hermes.cron_jobs,hermes.cron_usage_audit,hermes.debug_share_pastes,hermes.env,hermes.gateway_state,hermes.hooks,hermes.logs,hermes.mcp_installs,hermes.mcp_tokens,hermes.memories,hermes.memory_store,hermes.model_traces,hermes.oauth_tokens,hermes.pairing,hermes.pastes,hermes.pending_skills,hermes.platform_sessions,hermes.process_results,hermes.profile_home,hermes.profiles,hermes.projects_db,hermes.remote_sandbox_snapshots,hermes.response_store,hermes.retired_wal_generations,hermes.retired_wal_manifests,hermes.retired_wal_transcripts,hermes.sandboxes,hermes.saved_sessions,hermes.session_exports,hermes.sessions_dir,hermes.skills,hermes.skills_prompt_snapshot,hermes.soul,hermes.spillover,hermes.state_db,hermes.state_snapshot_transcripts,hermes.state_snapshots,hermes.terminal_sessions,hermes.vault,hermes.verification_evidence ~/.hermes/profiles
check hermes.profile_tombstones ~/.hermes/profiles/.deleted
check hermes.projects_db ~/.hermes/projects.db
check hermes.projects_db ~/.hermes/projects.db-shm
check hermes.projects_db ~/.hermes/projects.db-wal
check hermes.response_store ~/.hermes/response_store.db
check hermes.response_store ~/.hermes/response_store.db-shm
check hermes.response_store ~/.hermes/response_store.db-wal
check hermes.sandboxes ~/.hermes/sandboxes
check hermes.session_exports ~/.hermes/session-exports/**
check hermes.sessions_dir ~/.hermes/sessions
check hermes.saved_sessions ~/.hermes/sessions/saved/*.json
check hermes.saved_sessions ~/.hermes/sessions/sessions.json
check hermes.remote_sandbox_snapshots ~/.hermes/singularity_snapshots.json
check hermes.skills ~/.hermes/skills
check hermes.oauth_tokens ~/.hermes/slack_tokens.json
check hermes.state_snapshot_transcripts ~/.hermes/state-snapshots
check hermes.state_snapshots ~/.hermes/state-snapshots/**
check hermes.state_db ~/.hermes/state.db
check hermes.state_db ~/.hermes/state.db-shm
check hermes.state_db ~/.hermes/state.db-wal
check hermes.terminal_sessions ~/.hermes/terminal-sessions/*.json
check hermes.vault ~/.hermes/vault/vault.json.enc
check hermes.vault ~/.hermes/vault/vault.key
check hermes.remote_sandbox_snapshots ~/.hermes/vercel_sandbox_snapshots.json
check hermes.verification_evidence ~/.hermes/verification_evidence.db
check hermes.verification_evidence ~/.hermes/verification_evidence.db-shm
check hermes.verification_evidence ~/.hermes/verification_evidence.db-wal
check hermes.gateway_state ~/.hermes/webhook_subscriptions.json
check hermes.platform_sessions ~/.hermes/whatsapp/session/**
PROBES
        ;;
    jetbrains_ai)
        cat <<'PROBES'
walk jetbrains_ai.base_directories,jetbrains_ai.ide_logs,jetbrains_ai.log_data ~/.cache/JetBrains
check jetbrains_ai.base_directories ~/.cache/JetBrains/<Product><Version>
walk jetbrains_ai.aia_task_history,jetbrains_ai.disabled_plugins,jetbrains_ai.password_safe,jetbrains_ai.path_properties ~/.config/JetBrains
check jetbrains_ai.base_directories ~/.config/JetBrains/<Product><Version>
check jetbrains_ai.mcp_config ~/.config/JetBrains/Air/mcp.json
walk jetbrains_ai.base_directories ~/.local/share/JetBrains/<Product><Version>
walk jetbrains_ai.aia_task_history,jetbrains_ai.base_directories,jetbrains_ai.disabled_plugins,jetbrains_ai.password_safe,jetbrains_ai.path_properties ~/Library/Application Support/JetBrains
check jetbrains_ai.base_directories ~/Library/Application Support/JetBrains/<Product><Version>
check jetbrains_ai.mcp_config ~/Library/Application Support/JetBrains/Air/mcp.json
walk jetbrains_ai.log_data ~/Library/Caches/JetBrains
check jetbrains_ai.base_directories ~/Library/Caches/JetBrains/<Product><Version>
walk jetbrains_ai.ide_logs ~/Library/Logs/JetBrains
check jetbrains_ai.base_directories ~/Library/Logs/JetBrains/<Product><Version>
walk jetbrains_ai.path_properties ~/idea.properties
PROBES
        ;;
    junie)
        cat <<'PROBES'
walk junie.jcp_outbox,junie.matterhorn_project_logs ~/.cache/JetBrains
walk junie.plugin_install_evidence ~/.config/JetBrains
walk junie.allowlist,junie.cli_sessions,junie.home_config,junie.mcp_config,junie.trust_and_auth_key ~/.junie
check junie.home_config ~/.junie/AGENTS.md
check junie.allowlist ~/.junie/allowlist.json
check junie.home_config ~/.junie/config.json
check junie.mcp_config ~/.junie/mcp/mcp.json
check junie.cli_sessions ~/.junie/sessions
check junie.home_config ~/.junie/settings.json
check junie.trust_and_auth_key ~/.junie/trust
check junie.trust_and_auth_key ~/.junie/trust/authentication-key
walk junie.plugin_install_evidence ~/.local/share/JetBrains
walk junie.plugin_install_evidence ~/Library/Application Support/JetBrains
walk junie.jcp_outbox,junie.matterhorn_project_logs ~/Library/Caches/JetBrains
PROBES
        ;;
    kilo_code)
        cat <<'PROBES'
walk kilo_code.extension_id_legacy_tree,kilo_code.settings ~/.config/Code
check kilo_code.settings ~/.config/Code/User/globalStorage/kilocode.kilo-code/settings/custom_modes.yaml
check kilo_code.extension_id_legacy_tree ~/.config/Code/User/globalStorage/kilocode.kilo-code/tasks
walk kilo_code.agents,kilo_code.config ~/.config/kilo
check kilo_code.agents ~/.config/kilo/agent
check kilo_code.config ~/.config/kilo/kilo.jsonc
walk kilo_code.home_dir ~/.kilocode/cli/global/settings/custom_modes.yaml
walk kilo_code.cli_db ~/.local/share/kilo
check kilo_code.cli_db ~/.local/share/kilo/kilo.db
check kilo_code.cli_db ~/.local/share/kilo/kilo.db-shm
check kilo_code.cli_db ~/.local/share/kilo/kilo.db-wal
walk kilo_code.extension_id_legacy_tree ~/.vscode-server/data/User/globalStorage/kilocode.kilo-code/tasks
walk kilo_code.extension_id_legacy_tree,kilo_code.settings ~/Library/Application Support/Code
check kilo_code.settings ~/Library/Application Support/Code/User/globalStorage/kilocode.kilo-code/settings/custom_modes.yaml
check kilo_code.extension_id_legacy_tree ~/Library/Application Support/Code/User/globalStorage/kilocode.kilo-code/tasks
PROBES
        ;;
    kiro)
        cat <<'PROBES'
walk kiro.managed_settings /Library/Application Support/Kiro/managed-settings.json
walk kiro.managed_settings /etc/kiro/managed-settings.json
walk kiro.cli_log /tmp/kiro-log/*.log
walk kiro.legacy_amazonq_config ~/.aws/amazonq/**
walk kiro.ide_legacy_global_storage ~/.config/Kiro/User/globalStorage/kiro.kiroagent/**
walk kiro.cli_settings,kiro.ide_session_files,kiro.mcp_config_user,kiro.permissions_user,kiro.permissions_workspace,kiro.skills_powers,kiro.steering_user ~/.kiro
check kiro.cli_session_database ~/.kiro/*.sqlite3
check kiro.cli_session_database ~/.kiro/*.sqlite3-shm
check kiro.cli_session_database ~/.kiro/*.sqlite3-wal
check kiro.agents ~/.kiro/agents/*
check kiro.hooks ~/.kiro/hooks/*.json
check kiro.skills_powers ~/.kiro/powers/**
check kiro.prompt_library ~/.kiro/prompts/*
check kiro.ide_session_files ~/.kiro/sessions
check kiro.cli_session_files ~/.kiro/sessions/cli/*.lock
check kiro.cli_session_files ~/.kiro/sessions/cli/<session-id>.json
check kiro.cli_session_files ~/.kiro/sessions/cli/<session-id>.jsonl
check kiro.cli_settings ~/.kiro/settings/cli.json
check kiro.mcp_config_user ~/.kiro/settings/mcp.json
check kiro.permissions_user ~/.kiro/settings/permissions.yaml
check kiro.skills_powers ~/.kiro/skills
check kiro.skills_powers ~/.kiro/skills/**
check kiro.steering_user ~/.kiro/steering/*.md
check kiro.steering_user ~/.kiro/steering/AGENTS.md
check kiro.permissions_workspace ~/.kiro/workspace-roots
walk kiro.cli_install ~/.local/bin/kiro-cli
walk kiro.cli_install ~/.local/bin/kirocli
walk kiro.cli_install ~/.local/bin/q
walk kiro.ide_legacy_global_storage ~/Library/Application Support/Kiro/User/globalStorage/kiro.kiroagent/**
walk kiro.ide_legacy_global_storage ~/Library/Application Support/kiro/User/globalStorage/kiro.kiroagent/**
PROBES
        ;;
    lmstudio)
        cat <<'PROBES'
walk lmstudio.cli_and_server,lmstudio.conversations,lmstudio.hub_downloads,lmstudio.mcp_config,lmstudio.models,lmstudio.presets ~/.lmstudio
check lmstudio.cli_and_server ~/.lmstudio/bin/lms
check lmstudio.presets ~/.lmstudio/config-presets
check lmstudio.conversations ~/.lmstudio/conversations
check lmstudio.hub_downloads ~/.lmstudio/hub
check lmstudio.mcp_config ~/.lmstudio/mcp.json
check lmstudio.models ~/.lmstudio/models
walk lmstudio.macos_app_support_and_logs ~/Library/Application Support/LM Studio
walk lmstudio.macos_app_support_and_logs ~/Library/Caches/ai.elementlabs.lmstudio
walk lmstudio.macos_app_support_and_logs ~/Library/HTTPStorages/ai.elementlabs.lmstudio
walk lmstudio.macos_app_support_and_logs ~/Library/Logs/LM Studio
walk lmstudio.macos_app_support_and_logs ~/Library/Preferences/ai.elementlabs.lmstudio.plist
walk lmstudio.macos_app_support_and_logs ~/Library/Saved Application State/ai.elementlabs.lmstudio.savedState
PROBES
        ;;
    ollama)
        cat <<'PROBES'
walk ollama.env_overrides /etc/systemd
check ollama.env_overrides /etc/systemd/system/ollama.service
check ollama.env_overrides /etc/systemd/system/ollama.service.d/override.conf
walk ollama.model_blobs /usr/share/ollama/.ollama/models/blobs/sha256-*
walk ollama.model_manifests /usr/share/ollama/.ollama/models/manifests
walk ollama.env_overrides ~/.bashrc
walk ollama.app_chat_database,ollama.app_config,ollama.backup_dir,ollama.cli_config,ollama.cli_prompt_history,ollama.logs,ollama.model_manifests,ollama.private_key ~/.ollama
check ollama.backup_dir ~/.ollama/backup
check ollama.app_config,ollama.cli_config ~/.ollama/config.json
check ollama.cli_config ~/.ollama/config/config.json
check ollama.app_chat_database ~/.ollama/db.sqlite
check ollama.app_chat_database ~/.ollama/db.sqlite-shm
check ollama.app_chat_database ~/.ollama/db.sqlite-wal
check ollama.cli_prompt_history ~/.ollama/history
check ollama.private_key ~/.ollama/id_ed25519
check ollama.private_key ~/.ollama/id_ed25519.pub
check ollama.logs ~/.ollama/logs/app.log
check ollama.logs ~/.ollama/logs/server.log
check ollama.model_blobs ~/.ollama/models/blobs/sha256-*
check ollama.model_manifests ~/.ollama/models/manifests
check ollama.cli_config ~/.ollama/server.json
walk ollama.env_overrides ~/.zshrc
walk ollama.app_chat_database,ollama.app_config,ollama.macos_app_container ~/Library/Application Support/Ollama
check ollama.app_config ~/Library/Application Support/Ollama/config.json
check ollama.app_chat_database ~/Library/Application Support/Ollama/db.sqlite
check ollama.app_chat_database ~/Library/Application Support/Ollama/db.sqlite-shm
check ollama.app_chat_database ~/Library/Application Support/Ollama/db.sqlite-wal
walk ollama.macos_app_container ~/Library/Caches/com.electron.ollama
walk ollama.macos_app_container ~/Library/Preferences/com.electron.ollama.plist
walk ollama.macos_app_container ~/Library/Saved Application State/com.electron.ollama.savedState
walk ollama.macos_app_container ~/Library/Webkit/com.electron.ollama
PROBES
        ;;
    opencode)
        cat <<'PROBES'
walk opencode.managed_config /Library/Application Support/opencode
walk opencode.managed_config /etc/opencode
walk opencode.install_and_runtime_trees ~/.cache/opencode/bin/**
walk opencode.agents_commands,opencode.config,opencode.tui_config ~/.config/opencode
check opencode.agents_commands ~/.config/opencode/agents
check opencode.agents_commands ~/.config/opencode/commands
check opencode.config ~/.config/opencode/opencode.json
check opencode.config ~/.config/opencode/opencode.jsonc
check opencode.tui_config ~/.config/opencode/tui.json
walk opencode.auth,opencode.db,opencode.legacy_json_storage,opencode.log,opencode.mcp_auth,opencode.repos_cache ~/.local/share/opencode
check opencode.auth ~/.local/share/opencode/auth.json
check opencode.log ~/.local/share/opencode/log
check opencode.mcp_auth ~/.local/share/opencode/mcp-auth.json
check opencode.db ~/.local/share/opencode/opencode-*.db
check opencode.db ~/.local/share/opencode/opencode-*.db-shm
check opencode.db ~/.local/share/opencode/opencode-*.db-wal
check opencode.db ~/.local/share/opencode/opencode.db
check opencode.db ~/.local/share/opencode/opencode.db-shm
check opencode.db ~/.local/share/opencode/opencode.db-wal
check opencode.repos_cache ~/.local/share/opencode/repos
check opencode.legacy_json_storage ~/.local/share/opencode/storage/message
check opencode.legacy_json_storage ~/.local/share/opencode/storage/part
check opencode.legacy_json_storage ~/.local/share/opencode/storage/session
walk opencode.state_and_temp ~/.local/state/opencode
PROBES
        ;;
    pi)
        cat <<'PROBES'
walk pi.agents_skills ~/.agents/skills/**
walk pi.auth,pi.bin,pi.debug_log,pi.models,pi.sessions,pi.settings ~/.pi
check pi.auth ~/.pi/agent/auth.json
check pi.bin ~/.pi/agent/bin
check pi.extensions ~/.pi/agent/extensions/**
check pi.models ~/.pi/agent/models.json
check pi.debug_log ~/.pi/agent/pi-debug.log
check pi.prompts ~/.pi/agent/prompts/**
check pi.sessions ~/.pi/agent/sessions
check pi.settings ~/.pi/agent/settings.json
check pi.skills ~/.pi/agent/skills/**
check pi.bin ~/.pi/agent/themes
check pi.extensions ~/.pi/agent/tools/**
check pi.bin ~/.pi/server
PROBES
        ;;
    qwen_code)
        cat <<'PROBES'
walk qwen_code.system_settings /Library/Application Support/QwenCode
check qwen_code.system_settings /Library/Application Support/QwenCode/settings.json
check qwen_code.system_settings /Library/Application Support/QwenCode/system-defaults.json
walk qwen_code.system_settings /etc/qwen-code
check qwen_code.system_settings /etc/qwen-code/settings.json
check qwen_code.system_settings /etc/qwen-code/system-defaults.json
walk qwen_code.ide_connection_locks /tmp/qwen-code-ide-server-*.json
walk qwen_code.user_extension_points ~/.agents/skills/**
walk qwen_code.env_files ~/.env
walk qwen_code.arena_worktrees,qwen_code.audit_landing,qwen_code.auto_memory,qwen_code.channels_scheduled_tasks,qwen_code.conversation_transcript,qwen_code.env_files,qwen_code.file_history_backups,qwen_code.install_evidence,qwen_code.mcp_approvals,qwen_code.mcp_oauth_tokens,qwen_code.project_temp_spill,qwen_code.prompt_history_log,qwen_code.prompt_terminal_ledger,qwen_code.qwen_oauth_credentials,qwen_code.session_sidecars,qwen_code.shell_history,qwen_code.subagent_transcripts,qwen_code.trusted_folders,qwen_code.usage_history,qwen_code.user_instructions,qwen_code.user_settings,qwen_code.workflow_generated_scripts,qwen_code.workflow_run_journals,qwen_code.workflow_run_snapshots ~/.qwen
check qwen_code.env_files ~/.qwen/.env
check qwen_code.user_instructions ~/.qwen/AGENTS.md
check qwen_code.user_instructions ~/.qwen/QWEN.md
check qwen_code.user_extension_points ~/.qwen/agents/<name>.md
check qwen_code.arena_worktrees ~/.qwen/arena
check qwen_code.audit_landing ~/.qwen/audits
check qwen_code.install_evidence ~/.qwen/bin/**
check qwen_code.channels_scheduled_tasks ~/.qwen/channels/cron.json
check qwen_code.channels_scheduled_tasks ~/.qwen/channels/daemon
check qwen_code.channels_scheduled_tasks ~/.qwen/channels/service.pid
check qwen_code.channels_scheduled_tasks ~/.qwen/channels/sessions.json
check qwen_code.user_extension_points ~/.qwen/commands/**
check qwen_code.debug_logs ~/.qwen/debug/<session-id>.txt
check qwen_code.user_extension_points ~/.qwen/extensions/**
check qwen_code.file_history_backups ~/.qwen/file-history
check qwen_code.ide_connection_locks ~/.qwen/ide/*.lock
check qwen_code.install_evidence ~/.qwen/installation_id
check qwen_code.user_extension_points ~/.qwen/locales/**
check qwen_code.mcp_oauth_tokens ~/.qwen/mcp-oauth-tokens-v2.json
check qwen_code.mcp_oauth_tokens ~/.qwen/mcp-oauth-tokens.json
check qwen_code.mcp_approvals ~/.qwen/mcpApprovals.json
check qwen_code.auto_memory ~/.qwen/memories/*
check qwen_code.auto_memory ~/.qwen/memories/MEMORY.md
check qwen_code.user_instructions ~/.qwen/memory.md
check qwen_code.qwen_oauth_credentials ~/.qwen/oauth_creds.json
check qwen_code.qwen_oauth_credentials ~/.qwen/oauth_creds.lock
check qwen_code.plan_files ~/.qwen/plans/<session-id>.md
check qwen_code.auto_memory,qwen_code.conversation_transcript,qwen_code.prompt_terminal_ledger,qwen_code.session_sidecars,qwen_code.subagent_transcripts,qwen_code.workflow_generated_scripts,qwen_code.workflow_run_journals,qwen_code.workflow_run_snapshots ~/.qwen/projects
check qwen_code.user_extension_points ~/.qwen/rules/**
check qwen_code.session_registry ~/.qwen/sessions/<pid>.json
check qwen_code.user_settings ~/.qwen/settings.json
check qwen_code.user_extension_points ~/.qwen/skills/**
check qwen_code.install_evidence ~/.qwen/source.json
check qwen_code.project_temp_spill,qwen_code.prompt_history_log,qwen_code.shell_history ~/.qwen/tmp
check qwen_code.trusted_folders ~/.qwen/trustedFolders.json
check qwen_code.install_evidence ~/.qwen/updates/npm
check qwen_code.usage_history ~/.qwen/usage_record.jsonl
check qwen_code.user_extension_points ~/.qwen/workflows/<name>.js
PROBES
        ;;
    roo_code)
        cat <<'PROBES'
walk roo_code.global_dirs ~/.agents
walk roo_code.global_dirs ~/.roo
check roo_code.global_dirs ~/.roo/rules
check roo_code.global_dirs ~/.roo/rules-<mode>
PROBES
        ;;
    vscode)
        cat <<'PROBES'
walk vscode.state_vscdb,vscode.user_data_roots ~/.config/Code
check vscode.user_data_roots ~/.config/Code/User/globalStorage
check vscode.state_vscdb ~/.config/Code/User/globalStorage/state.vscdb
check vscode.state_vscdb ~/.config/Code/User/globalStorage/state.vscdb-shm
check vscode.state_vscdb ~/.config/Code/User/globalStorage/state.vscdb-wal
walk vscode.user_data_roots ~/.config/VSCodium/User/globalStorage
walk vscode.extension_dirs ~/.cursor/extensions
walk vscode.extension_dirs,vscode.extension_install_evidence,vscode.file_policy,vscode.runtime_arguments ~/.vscode
walk vscode.extension_dirs,vscode.file_policy,vscode.runtime_arguments ~/.vscode-insiders
check vscode.runtime_arguments ~/.vscode-insiders/argv.json
check vscode.extension_dirs ~/.vscode-insiders/extensions
check vscode.file_policy ~/.vscode-insiders/policy.json
walk vscode.extension_dirs,vscode.extension_install_evidence,vscode.user_data_roots ~/.vscode-server
check vscode.user_data_roots ~/.vscode-server/data/User/globalStorage
check vscode.extension_dirs,vscode.extension_install_evidence ~/.vscode-server/extensions
check vscode.runtime_arguments ~/.vscode/argv.json
check vscode.extension_dirs ~/.vscode/extensions
check vscode.extension_install_evidence ~/.vscode/extensions/extensions.json
check vscode.extension_install_evidence ~/.vscode/extensions/kilocode.kilo-code-*
check vscode.extension_install_evidence ~/.vscode/extensions/rooveterinaryinc.roo-cline-*
check vscode.extension_install_evidence ~/.vscode/extensions/saoudrizwan.claude-dev-*
check vscode.file_policy ~/.vscode/policy.json
walk vscode.extension_dirs ~/.windsurf/extensions
walk vscode.state_vscdb,vscode.user_data_roots ~/Library/Application Support/Code
walk vscode.user_data_roots ~/Library/Application Support/Code - Insiders/User/globalStorage
check vscode.user_data_roots ~/Library/Application Support/Code/User/globalStorage
check vscode.state_vscdb ~/Library/Application Support/Code/User/globalStorage/state.vscdb
check vscode.state_vscdb ~/Library/Application Support/Code/User/globalStorage/state.vscdb-shm
check vscode.state_vscdb ~/Library/Application Support/Code/User/globalStorage/state.vscdb-wal
check vscode.state_vscdb ~/Library/Application Support/Code/User/globalStorage/state.vscdb.backup
PROBES
        ;;
    warp)
        cat <<'PROBES'
walk warp.global_rules,warp.mcp_config,warp.skills ~/.agents
check warp.mcp_config ~/.agents/.mcp.json
check warp.global_rules ~/.agents/AGENTS.md
check warp.skills ~/.agents/skills
walk warp.skills ~/.claude/skills
walk warp.skills ~/.codex/skills
walk warp.cli_settings ~/.config/warp-terminal/cli/settings.toml
walk warp.skills ~/.copilot/skills
walk warp.skills ~/.cursor/skills
walk warp.skills ~/.factory/skills
walk warp.skills ~/.gemini/skills
walk warp.skills ~/.github/skills
walk warp.mcp_auth ~/.mcp-auth
walk warp.skills ~/.opencode/skills
walk warp.mcp_config,warp.skills ~/.warp
check warp.mcp_config ~/.warp/.mcp.json
check warp.skills ~/.warp/skills
walk warp.cli_settings,warp.mcp_config ~/.warp_cli
check warp.mcp_config ~/.warp_cli/.mcp.json
check warp.cli_settings ~/.warp_cli/settings.toml
walk warp.mcp_logs,warp.sqlite ~/Library/Group Containers/2BBY89MBSN.dev.warp
check warp.mcp_logs ~/Library/Group Containers/2BBY89MBSN.dev.warp/Library/Application Support/dev.warp.Warp-Stable/mcp
check warp.sqlite ~/Library/Group Containers/2BBY89MBSN.dev.warp/Library/Application Support/dev.warp.Warp-Stable/warp.sqlite
check warp.sqlite ~/Library/Group Containers/2BBY89MBSN.dev.warp/Library/Application Support/dev.warp.Warp-Stable/warp.sqlite-shm
check warp.sqlite ~/Library/Group Containers/2BBY89MBSN.dev.warp/Library/Application Support/dev.warp.Warp-Stable/warp.sqlite-wal
walk warp.cli_logs ~/Library/Logs/warp-cli
PROBES
        ;;
    windsurf)
        cat <<'PROBES'
walk windsurf.language_server_binaries_and_logs /Applications/Devin.app
check windsurf.enterprise_policy_bundled /Applications/Devin.app/Contents/Resources/app/policies
walk windsurf.system_config /Library/Application Support/Devin/rules/*.md
walk windsurf.system_config /Library/Application Support/Windsurf
check windsurf.system_config /Library/Application Support/Windsurf/hooks.json
check windsurf.system_config /Library/Application Support/Windsurf/rules/*.md
check windsurf.system_config /Library/Application Support/Windsurf/skills
check windsurf.system_config /Library/Application Support/Windsurf/workflows
walk windsurf.system_config /etc/devin/rules/*.md
walk windsurf.enterprise_policy_json /etc/vscode/policy.json
walk windsurf.system_config /etc/windsurf
check windsurf.system_config /etc/windsurf/hooks.json
check windsurf.system_config /etc/windsurf/rules/*.md
check windsurf.system_config /etc/windsurf/skills
check windsurf.system_config /etc/windsurf/workflows
walk windsurf.language_server_binaries_and_logs /usr/share/devin-desktop
check windsurf.language_server_binaries_and_logs /usr/share/devin-desktop/resources/app/extensions/windsurf/bin/language_server_linux_x64
check windsurf.language_server_binaries_and_logs /usr/share/devin-desktop/resources/app/extensions/windsurf/devin/bin/devin
walk windsurf.language_server_binaries_and_logs /usr/share/windsurf/resources/app/extensions/windsurf/bin/language_server_linux_x64
walk windsurf.auth_credentials ~/.cache/nvim/codeium/config.json
walk windsurf.auth_credentials,windsurf.code_tracker_and_settings,windsurf.device_identity,windsurf.embedding_database,windsurf.global_rules,windsurf.hooks,windsurf.ignore_files,windsurf.language_server_binaries_and_logs,windsurf.mcp_config,windsurf.plugin_log,windsurf.workflows_and_skills ~/.codeium
check windsurf.ignore_files ~/.codeium/.codeiumignore
check windsurf.plugin_log ~/.codeium/codeium.log
check windsurf.auth_credentials ~/.codeium/config.json
check windsurf.hooks ~/.codeium/hooks.json
check windsurf.code_tracker_and_settings ~/.codeium/user_settings.pb
check windsurf.cascade_trajectories ~/.codeium/windsurf-insiders/cascade/*
check windsurf.memories ~/.codeium/windsurf-insiders/memories/*
check windsurf.global_rules ~/.codeium/windsurf-insiders/memories/global_rules.md
check windsurf.cascade_trajectories ~/.codeium/windsurf-next/cascade/*
check windsurf.memories ~/.codeium/windsurf-next/memories/*
check windsurf.global_rules ~/.codeium/windsurf-next/memories/global_rules.md
check windsurf.code_tracker_and_settings ~/.codeium/windsurf/bin/devin-desktop
check windsurf.code_tracker_and_settings ~/.codeium/windsurf/brain
check windsurf.cascade_trajectories ~/.codeium/windsurf/cascade/*
check windsurf.cascade_trajectories ~/.codeium/windsurf/cascade/*.pb
check windsurf.cascade_trajectories ~/.codeium/windsurf/cascade/*.pb.archived
check windsurf.code_tracker_and_settings ~/.codeium/windsurf/code_tracker
check windsurf.code_tracker_and_settings ~/.codeium/windsurf/code_tracker/active
check windsurf.code_tracker_and_settings ~/.codeium/windsurf/code_tracker/history
check windsurf.code_tracker_and_settings ~/.codeium/windsurf/codemaps/codemapindex.json
check windsurf.code_tracker_and_settings ~/.codeium/windsurf/context_state
check windsurf.embedding_database ~/.codeium/windsurf/database
check windsurf.embedding_database ~/.codeium/windsurf/database/<md5-of-workspace-id>
check windsurf.workflows_and_skills ~/.codeium/windsurf/global_workflows/*.md
check windsurf.hooks ~/.codeium/windsurf/hooks.json
check windsurf.implicit_trajectories ~/.codeium/windsurf/implicit/*.pb
check windsurf.code_tracker_and_settings ~/.codeium/windsurf/installation_id
check windsurf.mcp_config ~/.codeium/windsurf/mcp_config.json
check windsurf.memories ~/.codeium/windsurf/memories/*
check windsurf.memories ~/.codeium/windsurf/memories/*.pb
check windsurf.global_rules ~/.codeium/windsurf/memories/global_rules.md
check windsurf.device_identity ~/.codeium/windsurf/native_storage_migrations.lock
check windsurf.workflows_and_skills ~/.codeium/windsurf/skills
check windsurf.code_tracker_and_settings ~/.codeium/windsurf/user_settings.pb
walk windsurf.device_identity,windsurf.ide_global_state_vscdb,windsurf.ide_user_data,windsurf.ide_workspace_state_vscdb,windsurf.local_file_history,windsurf.mcp_oauth_state ~/.config/Devin
check windsurf.device_identity ~/.config/Devin/.devin-migration-complete
check windsurf.local_file_history ~/.config/Devin/User/History
check windsurf.acp_message_stores ~/.config/Devin/User/acp-messages/<session-uuid>.db
check windsurf.acp_message_stores ~/.config/Devin/User/acp-messages/<session-uuid>.db-shm
check windsurf.acp_message_stores ~/.config/Devin/User/acp-messages/<session-uuid>.db-wal
check windsurf.ide_user_data ~/.config/Devin/User/chatLanguageModels.json
check windsurf.ide_global_state_vscdb ~/.config/Devin/User/globalStorage/state.vscdb
check windsurf.ide_global_state_vscdb ~/.config/Devin/User/globalStorage/state.vscdb-shm
check windsurf.ide_global_state_vscdb ~/.config/Devin/User/globalStorage/state.vscdb-wal
check windsurf.ide_global_state_vscdb ~/.config/Devin/User/globalStorage/state.vscdb.backup
check windsurf.ide_user_data ~/.config/Devin/User/settings.json
check windsurf.ide_workspace_state_vscdb ~/.config/Devin/User/workspaceStorage
check windsurf.ide_user_data ~/.config/Devin/Workspaces
check windsurf.device_identity ~/.config/Devin/cli/installation_id
check windsurf.ide_user_data ~/.config/Devin/config.json
check windsurf.device_identity ~/.config/Devin/machineid
check windsurf.mcp_oauth_state ~/.config/Devin/mcp/oauth
walk windsurf.ide_global_state_vscdb,windsurf.ide_user_data,windsurf.ide_workspace_state_vscdb,windsurf.local_file_history ~/.config/Windsurf
check windsurf.local_file_history ~/.config/Windsurf/User/History
check windsurf.ide_global_state_vscdb ~/.config/Windsurf/User/globalStorage/state.vscdb
check windsurf.ide_global_state_vscdb ~/.config/Windsurf/User/globalStorage/state.vscdb-shm
check windsurf.ide_global_state_vscdb ~/.config/Windsurf/User/globalStorage/state.vscdb-wal
check windsurf.ide_user_data ~/.config/Windsurf/User/settings.json
check windsurf.ide_workspace_state_vscdb ~/.config/Windsurf/User/workspaceStorage
walk windsurf.cli_feature_state ~/.config/devin/cli/<name>.<hash>.bin
walk windsurf.cli_feature_state ~/.config/devin/telemetry_state.json
walk windsurf.ide_user_data,windsurf.plans ~/.devin
walk windsurf.server_data ~/.devin-server/**
check windsurf.language_server_binaries_and_logs ~/.devin-server/data/logs
walk windsurf.shared_storage ~/.devin-shared
check windsurf.shared_storage ~/.devin-shared/sharedStorage/state.vscdb
check windsurf.shared_storage ~/.devin-shared/sharedStorage/state.vscdb-shm
check windsurf.shared_storage ~/.devin-shared/sharedStorage/state.vscdb-wal
check windsurf.shared_storage ~/.devin-shared/sharedStorage/state.vscdb.backup
check windsurf.ide_user_data ~/.devin/.devin-argv-precopy
check windsurf.ide_user_data ~/.devin/argv.json
check windsurf.ide_user_data ~/.devin/extensions/extensions.json
check windsurf.plans ~/.devin/plans
check windsurf.plans ~/.devin/plans/plan-*.md
check windsurf.cascade_transcripts ~/.devin/transcripts/*.jsonl
check windsurf.worktrees ~/.devin/worktrees/*
walk windsurf.auth_credentials ~/.local/share/devin/credentials.toml
walk windsurf.acp_registry,windsurf.plans ~/.windsurf
walk windsurf.acp_registry ~/.windsurf-next/acp/registry.json
walk windsurf.server_data ~/.windsurf-server/**
check windsurf.language_server_binaries_and_logs ~/.windsurf-server/data/logs
check windsurf.acp_registry ~/.windsurf/acp/registry.json
check windsurf.plans ~/.windsurf/plans
check windsurf.cascade_transcripts ~/.windsurf/transcripts/*.jsonl
check windsurf.worktrees ~/.windsurf/worktrees/*
walk windsurf.auth_credentials ~/AppData/Local/devin/credentials.toml
walk windsurf.device_identity,windsurf.ide_global_state_vscdb,windsurf.ide_user_data,windsurf.ide_workspace_state_vscdb,windsurf.local_file_history,windsurf.macos_update_state,windsurf.mcp_oauth_state ~/Library/Application Support/Devin
check windsurf.device_identity ~/Library/Application Support/Devin/.devin-migration-complete
check windsurf.macos_update_state ~/Library/Application Support/Devin/1.12-main.sock
check windsurf.macos_update_state ~/Library/Application Support/Devin/Backups
check windsurf.macos_update_state ~/Library/Application Support/Devin/Crashpad
check windsurf.local_file_history ~/Library/Application Support/Devin/User/History
check windsurf.acp_message_stores ~/Library/Application Support/Devin/User/acp-messages/<session-uuid>.db
check windsurf.acp_message_stores ~/Library/Application Support/Devin/User/acp-messages/<session-uuid>.db-shm
check windsurf.acp_message_stores ~/Library/Application Support/Devin/User/acp-messages/<session-uuid>.db-wal
check windsurf.ide_user_data ~/Library/Application Support/Devin/User/chatLanguageModels.json
check windsurf.ide_global_state_vscdb ~/Library/Application Support/Devin/User/globalStorage/state.vscdb
check windsurf.ide_global_state_vscdb ~/Library/Application Support/Devin/User/globalStorage/state.vscdb-shm
check windsurf.ide_global_state_vscdb ~/Library/Application Support/Devin/User/globalStorage/state.vscdb-wal
check windsurf.ide_global_state_vscdb ~/Library/Application Support/Devin/User/globalStorage/state.vscdb.backup
check windsurf.ide_global_state_vscdb ~/Library/Application Support/Devin/User/globalStorage/storage.json
check windsurf.ide_user_data ~/Library/Application Support/Devin/User/settings.json
check windsurf.ide_workspace_state_vscdb ~/Library/Application Support/Devin/User/workspaceStorage
check windsurf.ide_user_data ~/Library/Application Support/Devin/Workspaces
check windsurf.device_identity ~/Library/Application Support/Devin/cli/installation_id
check windsurf.ide_user_data ~/Library/Application Support/Devin/config.json
check windsurf.device_identity ~/Library/Application Support/Devin/machineid
check windsurf.mcp_oauth_state ~/Library/Application Support/Devin/mcp/oauth
walk windsurf.ide_global_state_vscdb,windsurf.ide_user_data,windsurf.ide_workspace_state_vscdb,windsurf.local_file_history ~/Library/Application Support/Windsurf
walk windsurf.ide_global_state_vscdb ~/Library/Application Support/Windsurf - Next
check windsurf.ide_global_state_vscdb ~/Library/Application Support/Windsurf - Next/User/globalStorage/state.vscdb
check windsurf.ide_global_state_vscdb ~/Library/Application Support/Windsurf - Next/User/globalStorage/state.vscdb-shm
check windsurf.ide_global_state_vscdb ~/Library/Application Support/Windsurf - Next/User/globalStorage/state.vscdb-wal
check windsurf.local_file_history ~/Library/Application Support/Windsurf/User/History
check windsurf.ide_global_state_vscdb ~/Library/Application Support/Windsurf/User/globalStorage/state.vscdb
check windsurf.ide_global_state_vscdb ~/Library/Application Support/Windsurf/User/globalStorage/state.vscdb-shm
check windsurf.ide_global_state_vscdb ~/Library/Application Support/Windsurf/User/globalStorage/state.vscdb-wal
check windsurf.ide_global_state_vscdb ~/Library/Application Support/Windsurf/User/globalStorage/storage.json
check windsurf.ide_user_data ~/Library/Application Support/Windsurf/User/keybindings.json
check windsurf.ide_user_data ~/Library/Application Support/Windsurf/User/settings.json
check windsurf.ide_user_data ~/Library/Application Support/Windsurf/User/snippets
check windsurf.ide_workspace_state_vscdb ~/Library/Application Support/Windsurf/User/workspaceStorage
check windsurf.ide_user_data ~/Library/Application Support/Windsurf/Workspaces
check windsurf.ide_user_data ~/Library/Application Support/Windsurf/argv.json
check windsurf.ide_global_state_vscdb ~/Library/Application Support/Windsurf/machineId
walk windsurf.cli_feature_state ~/Library/Application Support/devin/cli/<name>.<hash>.bin
walk windsurf.cli_feature_state ~/Library/Application Support/devin/telemetry_state.json
walk windsurf.macos_bundle_storage ~/Library/Caches/com.exafunction.windsurf
walk windsurf.macos_update_state ~/Library/Caches/com.exafunction.windsurf.ShipIt
check windsurf.macos_bundle_storage ~/Library/Caches/com.exafunction.windsurf/Cache.db
check windsurf.macos_bundle_storage ~/Library/Caches/com.exafunction.windsurf/Cache.db-shm
check windsurf.macos_bundle_storage ~/Library/Caches/com.exafunction.windsurf/Cache.db-wal
walk windsurf.macos_bundle_storage ~/Library/HTTPStorages/com.exafunction.windsurf
check windsurf.macos_bundle_storage ~/Library/HTTPStorages/com.exafunction.windsurf/httpstorages.sqlite
check windsurf.macos_bundle_storage ~/Library/HTTPStorages/com.exafunction.windsurf/httpstorages.sqlite-shm
check windsurf.macos_bundle_storage ~/Library/HTTPStorages/com.exafunction.windsurf/httpstorages.sqlite-wal
walk windsurf.macos_preferences ~/Library/Preferences/com.exafunction.windsurf.plist
PROBES
        ;;
    zed)
        cat <<'PROBES'
walk zed.extensions,zed.prompt_library,zed.settings,zed.user_agent_instructions,zed.user_configuration ~/.config/zed
check zed.user_agent_instructions ~/.config/zed/AGENTS.md
check zed.user_configuration ~/.config/zed/debug.json
check zed.user_configuration ~/.config/zed/global_settings.json
check zed.user_configuration ~/.config/zed/keymap.json
check zed.user_configuration ~/.config/zed/keymap_backup.json
check zed.extensions ~/.config/zed/prompt_overrides
check zed.prompt_library ~/.config/zed/prompts
check zed.settings ~/.config/zed/settings.json
check zed.user_configuration ~/.config/zed/settings_backup.json
check zed.user_configuration ~/.config/zed/tasks.json
walk zed.prompt_library,zed.threads_db ~/.local/share/zed
check zed.prompt_library ~/.local/share/zed/prompts
check zed.threads_db ~/.local/share/zed/threads/threads.db
check zed.threads_db ~/.local/share/zed/threads/threads.db-shm
check zed.threads_db ~/.local/share/zed/threads/threads.db-wal
walk zed.state_tree ~/.local/state
check zed.state_tree ~/.local/state/Zed
check zed.state_tree ~/.local/state/zed
walk zed.flatpak_legacy_threads ~/.var/app/dev.zed.Zed/data/zed/threads/threads-db.1.mdb
walk zed.extensions,zed.semantic_index,zed.sidebar_threads,zed.threads_db ~/Library/Application Support/Zed
check zed.extensions ~/Library/Application Support/Zed/copilot
check zed.sidebar_threads ~/Library/Application Support/Zed/db/0-stable/db.sqlite
check zed.sidebar_threads ~/Library/Application Support/Zed/db/0-stable/db.sqlite-shm
check zed.sidebar_threads ~/Library/Application Support/Zed/db/0-stable/db.sqlite-wal
check zed.extensions ~/Library/Application Support/Zed/debug_adapters
check zed.extensions ~/Library/Application Support/Zed/devcontainer
check zed.semantic_index ~/Library/Application Support/Zed/embeddings
check zed.extensions ~/Library/Application Support/Zed/extensions
check zed.extensions ~/Library/Application Support/Zed/external_agents
check zed.extensions ~/Library/Application Support/Zed/remote_extensions
check zed.extensions ~/Library/Application Support/Zed/remote_servers
check zed.extensions ~/Library/Application Support/Zed/server_state
check zed.threads_db ~/Library/Application Support/Zed/threads/threads.db
check zed.threads_db ~/Library/Application Support/Zed/threads/threads.db-shm
check zed.threads_db ~/Library/Application Support/Zed/threads/threads.db-wal
walk zed.logs ~/Library/Logs/Zed
PROBES
        ;;
    *)
        return 1
        ;;
    esac
}

tokens_for() {
    case "$1" in
    aider) echo 'aider' ;;
    amazonq) echo 'amazonq amazon' ;;
    amp) echo 'amp sourcegraph' ;;
    chatgpt_desktop) echo 'chatgpt openai' ;;
    claude_code) echo 'claude anthropic' ;;
    claude_desktop) echo 'claude anthropic' ;;
    cline) echo 'cline' ;;
    codex) echo 'codex openai' ;;
    continue) echo 'continue' ;;
    copilot) echo 'copilot github' ;;
    cursor) echo 'cursor anysphere' ;;
    devin) echo 'devin cognition' ;;
    factory_droid) echo 'factory droid' ;;
    gemini_cli) echo 'gemini google' ;;
    goose) echo 'goose block' ;;
    hermes) echo 'hermes' ;;
    jetbrains_ai) echo 'jetbrains' ;;
    junie) echo 'junie jetbrains' ;;
    kilo_code) echo 'kilo' ;;
    kiro) echo 'kiro amazon' ;;
    lmstudio) echo 'lmstudio element' ;;
    ollama) echo 'ollama' ;;
    opencode) echo 'opencode' ;;
    qwen_code) echo 'qwen alibaba' ;;
    roo_code) echo 'roo' ;;
    vscode) echo 'vscode microsoft' ;;
    warp) echo 'warp' ;;
    windsurf) echo 'windsurf cognition' ;;
    zed) echo 'zed industries' ;;
    *) return 1 ;;
    esac
}

ALL_FAMILIES='aider amazonq amp chatgpt_desktop claude_code claude_desktop cline codex continue copilot crosscutting cursor devin factory_droid gemini_cli goose hermes jetbrains_ai junie kilo_code kiro lmstudio ollama opencode pi qwen_code roo_code vscode warp windsurf zed'
# END generated probes

if [ "$WANT" = --list ]; then
    printf '%s\n' $ALL_FAMILIES
    exit 0
fi

printf 'host: %s\n' "$(uname -srm)"
if [ "$(uname -s)" = Darwin ]; then
    printf 'macos: %s\n' "$(sw_vers -productVersion 2>/dev/null || echo unknown)"
fi
printf 'depth: %s\n' "$DEPTH"
printf 'taken: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [ "$WANT" = all ]; then
    for family in $ALL_FAMILIES; do
        measure "$family"
    done
else
    measure "$WANT" || exit 1
fi

section 'done'
printf 'Read this file before sending it. Delete any line you would rather not share.\n'
