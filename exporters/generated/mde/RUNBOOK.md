# Collecting AI coding agent artifacts through live response

<!-- Generated from the artifact catalogue. Do not edit by hand:
<!-- run `afx export-collection` and commit the result.
<!-- Catalogue digest: 483bd9a3bd62
<!--
<!-- An empty result from this rule means the paths it searched held nothing. It does
<!-- not mean the host is clean. Unverified catalogue entries, relocated data trees and
<!-- the paths listed as not covered below are all reasons a used agent leaves no hit
<!-- here. Where this matters, run the suite's own collector instead: it reads the
<!-- relocation variables and the agents' own state files, which no static rule can.
-->

Live response has a small command set, no usable wildcards and no way to fetch a
file it cannot name exactly. Collecting a few hundred catalogued paths through it
one `getfile` at a time is not practical, so the sequence below pushes this
suite's own collector instead, runs it, and fetches the bundle it produced. The
collector reads the relocation variables and the agents' own state files, which
no fixed list of paths can.

## Before the session

Upload `collect.ps1` to the live response library once, under **Settings >
Endpoints > Live response**. It is a single file with no modules and it runs on
PowerShell 5.1, which is what a live response session provides.

Upload `Check-AIAgentPresence.ps1` beside it if you are working through a fleet:
it reports which agents left a trace and copies nothing, so it is the cheap first
step on a host you have not yet decided to collect from.

## In the session

```text
# 1. Decide whether this host is worth a collection. Reads only, copies nothing.
run Check-AIAgentPresence.ps1

# 2. Collect. Writes a bundle under the path the script reports.
#    Drop -AllUsers if you are only interested in the signed-in user; the manifest
#    records which was done either way, so a partial collection is an honest one.
run collect.ps1 -parameters "-AllUsers -Zip"

# 3. Fetch it. Use the exact path the previous step printed.
getfile "C:\\Windows\\Temp\\agentforensics\\<bundle-id>.zip"
```

Then verify the bundle before you read it, on your own workstation:

```bash
afx verify <bundle-id>.zip
```

## Why not a list of getfile commands

Because it would be a worse answer that looks like a better one. Live response
fetches a named file, so a generated list could only name the paths with no
wildcard in them. Every session store in this catalogue is keyed by a session
identifier or a workspace hash, which means the transcripts, the part of the
evidence an investigation is actually about, would be exactly what such a list
left out.

## What is on the endpoint, per agent

Windows-relevant catalogue entries, as a sense of what a collection will cover:

| Agent | Key | Windows artifacts |
| --- | --- | --- |
| Aider | `aider` | 13 |
| Amazon Q Developer (CLI and IDE extension) | `amazonq` | 20 |
| Amp | `amp` | 7 |
| ChatGPT Desktop | `chatgpt_desktop` | 1 |
| Claude Code | `claude_code` | 75 |
| Claude Desktop | `claude_desktop` | 25 |
| Cline | `cline` | 24 |
| Continue | `continue` | 17 |
| Cross-cutting evidence | `crosscutting` | 21 |
| Cursor | `cursor` | 44 |
| Devin | `devin` | 2 |
| Factory Droid | `factory_droid` | 9 |
| Gemini CLI | `gemini_cli` | 13 |
| GitHub Copilot CLI | `copilot` | 20 |
| Goose | `goose` | 14 |
| Hermes | `hermes` | 56 |
| JetBrains AI Assistant | `jetbrains_ai` | 6 |
| Junie | `junie` | 9 |
| Kilo Code | `kilo_code` | 7 |
| Kiro | `kiro` | 21 |
| LM Studio | `lmstudio` | 6 |
| Ollama | `ollama` | 11 |
| OpenAI Codex CLI | `codex` | 13 |
| OpenCode | `opencode` | 11 |
| Qwen Code | `qwen_code` | 33 |
| Roo Code | `roo_code` | 7 |
| Visual Studio Code host storage | `vscode` | 5 |
| Warp | `warp` | 1 |
| Windsurf | `windsurf` | 33 |
| Zed | `zed` | 6 |
| pi | `pi` | 10 |

The count is entries, not files: one entry can be a directory holding a thousand
transcripts, or a file that is not there on this host.
