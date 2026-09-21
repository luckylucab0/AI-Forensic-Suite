#!/bin/sh
# Measure which of an agent's documented paths actually exist on this machine, on macOS or
# Linux. Read only, and names only.
#
# Why this exists. A hundred and twenty-six catalogue entries rest on somebody else's
# reading of a closed-source product rather than on a vendor page, and two families rest on
# no vendor source at all. A path that was invented is the worst defect this catalogue can
# carry: a collection searches it, finds nothing, and an analyst concludes the agent was
# never used. Only a real installation settles that, and no amount of further reading will.
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
#   sh scripts/measure_layout.sh > layout.txt
#   sh scripts/measure_layout.sh cursor > layout.txt     # one family only
#
# Then read layout.txt, remove anything you would rather not share, and send it.

set -u

DEPTH=${DEPTH:-4}
WANT=${1:-all}

# The tilde substitution is done with a literal string replacement rather than with a shell
# parameter expansion, because a home directory can contain a character that expansion
# treats as a pattern.
shorten() {
    sed -e "s|^$HOME|~|" -e "s| $HOME| ~|g"
}

section() {
    printf '\n===== %s\n' "$1"
}

# One tree, to a bounded depth, names and metadata only. A missing directory is reported as
# missing rather than skipped: an absence is a finding here, and the whole point is to tell
# a path that is wrong apart from a product that was never installed.
tree_of() {
    if [ ! -e "$1" ]; then
        printf 'ABSENT   %s\n' "$1" | shorten
        return
    fi
    printf 'PRESENT  %s\n' "$1" | shorten
    # -printf is not portable to BSD find, so the metadata comes from a second call per
    # entry. Slower and portable, which is the right trade for a one-off measurement.
    find "$1" -maxdepth "$DEPTH" 2>/dev/null | sort | while IFS= read -r path; do
        if [ -d "$path" ]; then
            kind=d
            size=-
        else
            kind=f
            size=$(wc -c <"$path" 2>/dev/null | tr -d ' ')
        fi
        printf '  %s %10s  %s\n' "$kind" "$size" "$path" | shorten
    done
}

version_of() {
    if [ -f "$1/Contents/Info.plist" ]; then
        printf 'VERSION  %s = %s\n' "$1" \
            "$(defaults read "$1/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null ||
                echo unknown)" | shorten
    fi
}

printf 'host: %s\n' "$(uname -srm)"
if [ "$(uname -s)" = Darwin ]; then
    printf 'macos: %s\n' "$(sw_vers -productVersion 2>/dev/null || echo unknown)"
fi
printf 'depth: %s\n' "$DEPTH"
printf 'taken: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [ "$WANT" = all ] || [ "$WANT" = cursor ]; then
    section 'cursor'
    version_of /Applications/Cursor.app
    for path in \
        "$HOME/Library/Application Support/Cursor" \
        "$HOME/Library/Caches/Cursor" \
        "$HOME/Library/Preferences/com.todesktop.230313mzl4w4u92.plist" \
        "$HOME/.cursor" \
        "$HOME/.cursor-server" \
        "$HOME/.config/Cursor" \
        "$HOME/.local/share/cursor-agent"; do
        tree_of "$path"
    done
fi

if [ "$WANT" = all ] || [ "$WANT" = chatgpt_desktop ]; then
    section 'chatgpt_desktop'
    version_of /Applications/ChatGPT.app
    for path in \
        "$HOME/Library/Application Support/com.openai.chat" \
        "$HOME/Library/Containers/com.openai.chat" \
        "$HOME/Library/Caches/com.openai.chat" \
        "$HOME/Library/HTTPStorages/com.openai.chat" \
        "$HOME/Library/Saved Application State/com.openai.chat.savedState" \
        "$HOME/Library/Logs/ChatGPT" \
        "$HOME/Library/Preferences/com.openai.chat.plist" \
        "$HOME/.codex"; do
        tree_of "$path"
    done
    # The group containers and any other bundle identifier this vendor ships under, found
    # by name rather than assumed: the catalogue's entries for this family are the ones
    # that rest on no vendor source at all, so what the identifiers actually are is part
    # of what this measurement is for.
    section 'chatgpt_desktop: identifiers found by name'
    for parent in "$HOME/Library/Group Containers" "$HOME/Library/Containers" \
        "$HOME/Library/Application Support"; do
        [ -d "$parent" ] || continue
        find "$parent" -maxdepth 1 -iname '*openai*' -o -maxdepth 1 -iname '*chatgpt*' \
            2>/dev/null | sort | shorten
    done
fi

if [ "$WANT" = all ] || [ "$WANT" = windsurf ]; then
    section 'windsurf'
    for path in \
        "$HOME/Library/Application Support/Windsurf" \
        "$HOME/Library/Application Support/Devin" \
        "$HOME/.codeium" \
        "$HOME/.windsurf" \
        "$HOME/.devin" \
        "$HOME/.config/devin"; do
        tree_of "$path"
    done
fi

section 'done'
printf 'Read this file before sending it. Delete any line you would rather not share.\n'
