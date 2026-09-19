"""Read aider's chat log, which is a markdown file it appends to as it runs.

The file lives inside the working copy rather than in a profile, which is what makes it
worth reading twice over: it is the one transcript in this catalogue that is routinely
committed to a repository by accident, and it is recoverable from git objects and from
backups of a project directory long after a home directory has been wiped.

Every shape in it comes from one writer, `IO.append_chat_history`, and the four callers
that reach it. Source, fetched and read:
https://raw.githubusercontent.com/Aider-AI/aider/main/aider/io.py

- A run writes `# aider chat started at <local time>` when its IO is constructed, so each
  of those lines is the start of one run of the tool.
- A prompt is written by `user_input`, which prefixes every line of it with `#### `. A
  prompt typed over three lines is three consecutive `#### ` lines, and an empty one is
  written as `<blank>`.
- An answer is written by `ai_output` as plain markdown with no prefix at all, which is why
  the code the model emitted is in this file verbatim, fenced as the model fenced it.
- Everything else aider prints goes through one blockquote.

That last one is a limit worth stating plainly, because it is the difference between a
reading and a guess. `confirm_ask` writes its question and the letter the person answered,
`prompt_ask` writes its question and the free text, and `tool_output`, `tool_error` and
`tool_warning` write their notices. All five produce `> ` and one line of text, with
nothing in the file to tell them apart. So a line like `> Add src/app/index.js to the
chat? y` is an approval and a line like `> Applied edit to src/app/index.js` is a notice,
and this parser does not claim to know which is which: those lines are carried whole, in
the order they were written, and said to be uninterpreted. Reading them as permission
decisions on the shape of the text would put approvals in a case that nobody gave.

**Times.** One per run, from the banner, and it is `datetime.now()` with no zone, so it is
read as UTC with the note this suite puts on every naive timestamp. The turns inside a run
have no time of their own anywhere in the file, and none is invented for them: dating a
whole conversation to the moment its run started would put a day's work at one instant.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from agentforensics.model import Event, unparsed
from agentforensics.parsers.base import ParseContext, normalise_ts

# The banner a run writes when its IO is constructed. The time is local and has no zone,
# which the event says rather than this module deciding for it.
_BANNER = re.compile(r"^#\s+aider chat started at\s+(?P<when>.+?)\s*$")

# What a prompt line looks like. The writer emits "#### " and then one line of the prompt,
# so a prompt of several lines is several of these in a row.
_PROMPT = "#### "

# Everything aider prints about itself, questions and answers included, in one shape.
_NOTICE = "> "

# Said on every one of those lines, because a reader who sees the text of an approval
# question in a case will otherwise take the case to have decided it was an approval.
_AMBIGUOUS = (
    "aider writes its notices, its questions and the answers people gave to them through "
    "one blockquote with nothing to tell them apart, so this line is carried as written "
    "rather than read as one of them"
)


class AiderParser:
    """The chat log aider keeps inside the working copy."""

    name = "aider"

    _LOGS = frozenset({"aider.chat_history"})

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in self._LOGS

    def parse(self, context: ParseContext) -> Iterator[Event]:
        # Read as text rather than through the line-delimited JSON reader: this is markdown,
        # a blank line separates a prompt from what follows it, and that reader drops blank
        # lines and marks every line that is not an object.
        with context.local_path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            lines = [(number, raw.rstrip("\r\n")) for number, raw in enumerate(f, start=1)]

        project = context.original_path.rsplit("/", 1)[0] if "/" in context.original_path else None
        pending: list[str] = []
        start = 0
        answer: list[str] = []
        answer_start = 0

        def common(number: int) -> dict[str, Any]:
            return {
                "user": context.user,
                "host": context.host,
                # The vendor joins this file name to the repository root, so the directory
                # holding it is the working copy the conversation was about.
                "project_path": project,
                "provenance": context.provenance(f"line:{number}"),
                "agent": context.agent,
            }

        def flush_prompt() -> Iterator[Event]:
            if not pending:
                return
            text = "\n".join(pending)
            yield Event(
                kind="user.prompt",
                raw={"text": text},
                ts_utc=None,
                ts_precision="absent",
                ts_source=None,
                actor="user",
                # `<blank>` is what the writer puts in the file for an empty input, so the
                # event says the person pressed enter on nothing rather than showing a
                # prompt that reads as literal text somebody typed.
                payload={"text": None if text == "<blank>" else text, "empty": text == "<blank>"},
                **common(start),
            )

        def flush_answer() -> Iterator[Event]:
            if not answer:
                return
            text = "\n".join(answer).strip()
            if not text:
                return
            yield Event(
                kind="assistant.text",
                raw={"text": text},
                ts_utc=None,
                ts_precision="absent",
                ts_source=None,
                actor="assistant",
                payload={"text": text},
                **common(answer_start),
            )

        for number, line in lines:
            banner = _BANNER.match(line)
            if banner or line.startswith(_PROMPT) or line.startswith(_NOTICE):
                yield from flush_answer()
                answer = []
            if banner:
                yield from flush_prompt()
                pending = []
                when, precision, note = normalise_ts(banner.group("when"))
                yield Event(
                    kind="session.start",
                    raw={"text": line},
                    ts_utc=when,
                    ts_precision=precision,
                    ts_source="the banner this run wrote" if when else None,
                    actor="system",
                    payload={"text": line.lstrip("# ").strip()},
                    parse_problem=note,
                    **common(number),
                )
                continue
            if line.startswith(_PROMPT):
                if not pending:
                    start = number
                # rstrip because the writer ends every line but the last of a prompt with
                # two spaces, which is markdown for a line break and not part of what was
                # typed.
                pending.append(line[len(_PROMPT) :].rstrip())
                continue
            yield from flush_prompt()
            pending = []
            if line.startswith(_NOTICE):
                yield unparsed(
                    context.provenance(f"line:{number}"),
                    context.agent,
                    {"text": line},
                    _AMBIGUOUS,
                    user=context.user,
                    host=context.host,
                    project_path=project,
                    payload={"text": line[len(_NOTICE) :].rstrip()},
                )
                continue
            if not answer:
                answer_start = number
            answer.append(line)
        yield from flush_prompt()
        yield from flush_answer()
