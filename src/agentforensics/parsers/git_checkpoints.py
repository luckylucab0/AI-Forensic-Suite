"""Read the checkpoint references two agents write into a git repository.

An agent that can undo its own edits keeps a snapshot of the files it is about to change.
Two of the agents here do it with git, and the modern shape is the one worth reading: the
extension runs `git stash create` in the user's own repository and then writes the commit
it got under a private reference namespace, `refs/cline/checkpoints/<session>/<run>`. So a
checkpoint is a commit in the developer's own object store, pointed at by a file of
forty-one bytes that nothing else on the endpoint explains.

What this reader takes from a collection is the part a collection actually has. The
reference files and the reference log are small text files and are collected; the objects
they point at are in the repository's object store, which this catalogue does not collect
and a full disk image would. So the events here answer when a checkpoint was taken, for
which session and which run of it, and which commit it is, and they say plainly that the
content behind it is not in the case. That is a timeline no other artifact carries: the
reference log is the only record on the endpoint that dates an agent's edits to a
repository, and it survives the deletion of the conversation that made them.

Three files, three shapes, all of them text:

- a reference file, which holds one object id, or a symbolic reference to another name
- the reference log beside it, one line per write, each carrying the previous and the new
  object id, who wrote it, when, and a message the tool chose
- the packed references file, where git moves a reference once it packs them, which is why
  a checkpoint can be absent from `refs/` and still exist

The identity in a reference log is the repository's own git identity, which is a person's
name and address. It is carried because it is evidence of who the commit was attributed to
and because the case is evidence, and an examiner handling it is handling a device's data
either way.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from agentforensics.model import Event, unparsed
from agentforensics.parsers.base import ParseContext, normalise_ts, text_lines

# The artifacts this reader claims. The two shadow repositories are the older mechanism,
# where the whole repository including its objects sits under the extension's storage; the
# third is the modern one, where only the references are in the user's own repository.
STORES = frozenset(
    {
        "cline.checkpoint_refs_in_workspace",
        "cline.checkpoints_shadow_git_legacy",
        "roo_code.checkpoints",
    }
)

# Said on every event, because the difference decides what an analyst can do next. A
# reference names a commit; the commit's content is in the repository's object store, which
# this collection does not take.
NO_CONTENT = (
    "this is the reference to a checkpoint and not its content: the commit it names lives "
    "in the repository's object store, which a collection of these paths does not carry. "
    "Recover it from the endpoint or from a disk image with the object id on this event"
)

# One line of a git reference log. The format is the one git writes: the previous object,
# the new object, the identity, the time as seconds since the epoch and a zone, then a tab
# and whatever the tool that wrote it had to say.
_REFLOG = re.compile(
    r"^(?P<old>[0-9a-f]{40}|[0-9a-f]{64})\s+"
    r"(?P<new>[0-9a-f]{40}|[0-9a-f]{64})\s+"
    r"(?P<who>.*?)\s+"
    r"(?P<when>\d+)\s+(?P<zone>[+-]\d{4})"
    r"(?:\t(?P<message>.*))?$"
)

# An object id on its own, which is what a loose reference file holds.
_OBJECT_ID = re.compile(r"^(?P<id>[0-9a-f]{40}|[0-9a-f]{64})$")

# A line of the packed references file. The peeled lines beginning with a caret belong to
# the reference above them and are not references of their own.
_PACKED = re.compile(r"^(?P<id>[0-9a-f]{40}|[0-9a-f]{64})\s+(?P<ref>\S+)$")

# The private namespaces these agents write. A packed references file holds every reference
# in the repository, and the branches a developer works on are not this artifact's evidence.
_NAMESPACES = ("refs/cline/", "refs/roo/", "refs/checkpoints/")


class GitCheckpointsParser:
    """The checkpoint references, read as the timeline they are."""

    name = "git_checkpoints"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in STORES

    def parse(self, context: ParseContext) -> Iterator[Event]:
        name = context.original_path.replace("\\", "/")
        if name.endswith("/packed-refs"):
            yield from self._packed(context)
            return
        if "/logs/refs/" in name:
            yield from self._reflog(context)
            return
        yield from self._ref(context)

    def _ref(self, context: ParseContext) -> Iterator[Event]:
        """A loose reference file: one object id, or a pointer to another name."""
        lines = [line for line in text_lines(context.local_path) if line.text.strip()]
        if not lines:
            yield unparsed(
                context.provenance("file"),
                context.agent,
                {"file": context.local_path.name},
                "this reference file is empty, which is what a partially written or a "
                "deleted reference leaves behind",
                user=context.user,
                host=context.host,
            )
            return
        text = lines[0].text.strip()
        found = _OBJECT_ID.match(text)
        if not found:
            if text.startswith("ref: "):
                yield self._event(
                    context,
                    "file",
                    {"symbolic_ref": text[len("ref: ") :].strip()},
                    note="this reference points at another reference rather than at a "
                    "commit, so the checkpoint is whatever that one names",
                )
                return
            yield unparsed(
                context.provenance("file"),
                context.agent,
                {"text": text},
                "this file is under a reference path and does not hold an object id",
                user=context.user,
                host=context.host,
            )
            return
        yield self._event(
            context,
            "file",
            {"object_id": found.group("id"), **_ref_parts(context.original_path)},
        )

    def _reflog(self, context: ParseContext) -> Iterator[Event]:
        """The log beside a reference: one line per write, and the only clock here."""
        for line in text_lines(context.local_path):
            if not line.text.strip():
                continue
            found = _REFLOG.match(line.text)
            if not found:
                yield unparsed(
                    context.provenance(line.locator),
                    context.agent,
                    line.text,
                    line.problem or "this line is not in the shape a reference log is written in",
                    user=context.user,
                    host=context.host,
                )
                continue
            when, precision, timing = normalise_ts(int(found.group("when")))
            yield self._event(
                context,
                line.locator,
                {
                    "object_id": found.group("new"),
                    "previous_object_id": found.group("old"),
                    # The identity git recorded for the write. It is a person, and it is
                    # evidence of attribution rather than decoration.
                    "written_by": found.group("who"),
                    "message": found.group("message") or None,
                    "zone": found.group("zone"),
                    **_ref_parts(context.original_path),
                },
                when=when,
                precision=precision,
                source="the reference log's own timestamp",
                note=timing,
            )

    def _packed(self, context: ParseContext) -> Iterator[Event]:
        """The packed references file, narrowed to the namespaces these agents write."""
        for line in text_lines(context.local_path):
            text = line.text.strip()
            if not text or text.startswith("#") or text.startswith("^"):
                continue
            found = _PACKED.match(text)
            if not found:
                continue
            ref = found.group("ref")
            if not ref.startswith(_NAMESPACES):
                # Every branch and tag in the repository is in this file. Only the private
                # namespaces are this artifact's evidence, and carrying the rest would put
                # a developer's whole branch list into a case that did not ask for it.
                continue
            yield self._event(
                context,
                line.locator,
                {"object_id": found.group("id"), **_ref_parts(ref)},
            )

    def _event(
        self,
        context: ParseContext,
        locator: str,
        record: dict[str, Any],
        *,
        when: str | None = None,
        precision: str = "absent",
        source: str | None = None,
        note: str | None = None,
    ) -> Event:
        return Event(
            kind="file.snapshot",
            provenance=context.provenance(locator),
            agent=context.agent,
            raw=record,
            ts_utc=when,
            ts_precision=precision,  # type: ignore[arg-type]
            ts_source=source if when else None,
            # The agent wrote the reference, not the person: the extension creates the
            # stash and updates the reference by itself around an edit it is making.
            actor="assistant",
            user=context.user,
            host=context.host,
            session_id=record.get("session_id"),
            payload={"checkpoint": record, "text": record.get("message")},
            parse_problem=" ".join(part for part in (note, NO_CONTENT) if part),
        )


def _ref_parts(path: str) -> dict[str, Any]:
    """The session and the run a checkpoint reference names, where it names them.

    The namespace one of these agents documents is `refs/cline/checkpoints/<session>/<run>`,
    so the last two segments carry the conversation the snapshot belongs to and which turn
    of it. Read positionally and only from that shape: a reference under another layout
    keeps its name and claims nothing.
    """
    text = path.replace("\\", "/")
    at = text.find("refs/")
    ref = text[at:] if at >= 0 else text
    # The reference log lives under .git/logs/refs/..., and the reference it logs is the
    # same name with the logs segment removed.
    ref = ref.replace("logs/refs/", "refs/", 1)
    out: dict[str, Any] = {"ref": ref}
    parts = ref.split("/")
    if len(parts) >= 5 and parts[2] == "checkpoints":
        out["session_id"] = parts[3]
        out["run"] = parts[4]
    return out


__all__ = ["NO_CONTENT", "STORES", "GitCheckpointsParser"]
